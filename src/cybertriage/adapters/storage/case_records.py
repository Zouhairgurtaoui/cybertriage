"""Shared case schema and report linking, using the caller's transaction."""

import json
import sqlite3
from collections.abc import Sequence
from datetime import datetime, timezone
from uuid import uuid4

from cybertriage.domain.case import CaseError
from cybertriage.domain.triage import AnalysisRecord


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def has_group_storage(connection: sqlite3.Connection) -> bool:
    return connection.execute("""SELECT COUNT(*) FROM sqlite_master
        WHERE type='table' AND name IN ('alert_groups','alert_group_members')""").fetchone()[0] == 2


def initialize_case_schema(connection: sqlite3.Connection) -> None:
    statements = (
        """CREATE TABLE IF NOT EXISTS incident_cases (
            case_id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL,
            priority TEXT NOT NULL CHECK(priority IN ('low','medium','high','critical')),
            status TEXT NOT NULL CHECK(status IN ('open','investigating','resolved','closed')),
            disposition TEXT NOT NULL CHECK(disposition IN ('unconfirmed','benign','confirmed_compromise')),
            version INTEGER NOT NULL CHECK(version > 0), created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS case_alerts (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL REFERENCES incident_cases(case_id),
            alert_record_id TEXT NOT NULL REFERENCES alerts(record_id),
            active INTEGER NOT NULL CHECK(active IN (0,1)), first_attached_at TEXT NOT NULL,
            changed_at TEXT NOT NULL, UNIQUE(case_id, alert_record_id))""",
        "CREATE INDEX IF NOT EXISTS case_alert_memberships ON case_alerts(alert_record_id, active)",
        """CREATE TABLE IF NOT EXISTS case_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
            case_id TEXT NOT NULL REFERENCES incident_cases(case_id), kind TEXT NOT NULL,
            actor TEXT NOT NULL, reason TEXT NOT NULL, details_json TEXT NOT NULL,
            occurred_at TEXT NOT NULL, recorded_at TEXT NOT NULL)""",
        "CREATE INDEX IF NOT EXISTS case_events_history ON case_events(case_id, seq)",
        """CREATE TABLE IF NOT EXISTS case_relationships (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, relationship_id TEXT NOT NULL UNIQUE,
            case_id TEXT NOT NULL REFERENCES incident_cases(case_id),
            source_alert_id TEXT NOT NULL REFERENCES alerts(record_id),
            target_alert_id TEXT NOT NULL REFERENCES alerts(record_id),
            kind TEXT NOT NULL CHECK(kind IN ('observed','hypothesis')), predicate TEXT NOT NULL,
            rationale TEXT NOT NULL, supporting_ids_json TEXT NOT NULL, proof_json TEXT NOT NULL,
            analysis_id TEXT REFERENCES analyses(analysis_id), actor TEXT NOT NULL, recorded_at TEXT NOT NULL,
            CHECK(source_alert_id <> target_alert_id))""",
        "CREATE INDEX IF NOT EXISTS case_relationship_history ON case_relationships(case_id, seq)",
        """CREATE TABLE IF NOT EXISTS case_relationship_reviews (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, relationship_id TEXT NOT NULL REFERENCES case_relationships(relationship_id),
            decision TEXT NOT NULL CHECK(decision IN ('accepted','rejected','retracted','superseded')),
            actor TEXT NOT NULL, reason TEXT NOT NULL, recorded_at TEXT NOT NULL)""",
        "CREATE INDEX IF NOT EXISTS case_relationship_review_history ON case_relationship_reviews(relationship_id, seq)",
        """CREATE TABLE IF NOT EXISTS analysis_alert_coverage (
            analysis_id TEXT NOT NULL REFERENCES analyses(analysis_id),
            alert_record_id TEXT NOT NULL REFERENCES alerts(record_id),
            PRIMARY KEY(analysis_id, alert_record_id))""",
        "CREATE INDEX IF NOT EXISTS analysis_alert_coverage_alert ON analysis_alert_coverage(alert_record_id, analysis_id)",
        """CREATE TABLE IF NOT EXISTS case_analyses (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL REFERENCES incident_cases(case_id),
            analysis_id TEXT NOT NULL REFERENCES analyses(analysis_id), linked_at TEXT NOT NULL,
            UNIQUE(case_id, analysis_id))""",
        "CREATE INDEX IF NOT EXISTS case_analysis_history ON case_analyses(case_id, seq)",
        """CREATE TABLE IF NOT EXISTS case_stage_assertions (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, assertion_id TEXT NOT NULL UNIQUE,
            case_id TEXT NOT NULL REFERENCES incident_cases(case_id), stage TEXT NOT NULL CHECK(stage IN
                ('reconnaissance','weaponization','delivery','exploitation','installation','command_and_control','actions_on_objectives')),
            kind TEXT NOT NULL CHECK(kind IN ('hypothesis','analyst_assessed')), supporting_ids_json TEXT NOT NULL,
            actor TEXT NOT NULL, reason TEXT NOT NULL, recorded_at TEXT NOT NULL)""",
        "CREATE INDEX IF NOT EXISTS case_stage_history ON case_stage_assertions(case_id, seq)",
        """CREATE TABLE IF NOT EXISTS case_stage_reviews (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, assertion_id TEXT NOT NULL REFERENCES case_stage_assertions(assertion_id),
            decision TEXT NOT NULL CHECK(decision IN ('accepted','rejected','retracted','superseded')),
            actor TEXT NOT NULL, reason TEXT NOT NULL, recorded_at TEXT NOT NULL)""",
        "CREATE INDEX IF NOT EXISTS case_stage_review_history ON case_stage_reviews(assertion_id, seq)",
    )
    for statement in statements:
        connection.execute(statement)
    for table in ("case_events", "case_relationships", "case_relationship_reviews", "analysis_alert_coverage", "case_analyses",
                  "case_stage_assertions", "case_stage_reviews"):
        for operation in ("UPDATE", "DELETE"):
            connection.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()}
                BEFORE {operation} ON {table} BEGIN
                SELECT RAISE(ABORT, 'Case history is append-only'); END""")


def append_case_event(connection: sqlite3.Connection, case_id: str, kind: str, actor: str,
                      reason: str, details: object, occurred_at: str | None = None,
                      *, advance_version: bool = True) -> None:
    now = utc_now()
    connection.execute("""INSERT INTO case_events
        (event_id,case_id,kind,actor,reason,details_json,occurred_at,recorded_at)
        VALUES(?,?,?,?,?,?,?,?)""", (uuid4().hex, case_id, kind, actor, reason,
        json.dumps(details, ensure_ascii=False, allow_nan=False), occurred_at or now, now))
    if advance_version:
        connection.execute("UPDATE incident_cases SET version=version+1, updated_at=? WHERE case_id=?", (now, case_id))


def record_report_coverage(connection: sqlite3.Connection, analysis_id: str, anchor_id: str, evidence: str) -> None:
    """Coverage derives from application evidence, never from model report text."""
    covered = {anchor_id}
    try:
        snapshot = json.loads(evidence)
    except (ValueError, RecursionError):
        snapshot = None
    if isinstance(snapshot, dict) and isinstance(snapshot.get("group_id"), str) and has_group_storage(connection):
        group_id = snapshot["group_id"]
        group = connection.execute("SELECT representative_record_id FROM alert_groups WHERE group_id=?", (group_id,)).fetchone()
        members = snapshot.get("alerts")
        if group and group[0] == anchor_id and isinstance(members, list) and 1 <= len(members) <= 5:
            for member in members:
                if not isinstance(member, dict):
                    continue
                manager, source_id = member.get("source_instance"), member.get("source_alert_id")
                if not isinstance(manager, str) or not isinstance(source_id, str):
                    continue
                row = connection.execute("""SELECT a.record_id FROM alerts a JOIN alert_group_members m
                    ON m.alert_record_id=a.record_id WHERE m.group_id=? AND a.source_instance=? AND a.source_alert_id=?""",
                    (group_id, manager, source_id)).fetchone()
                if row:
                    covered.add(row[0])
    for alert_id in sorted(covered):
        connection.execute("INSERT OR IGNORE INTO analysis_alert_coverage VALUES(?,?)", (analysis_id, alert_id))


def link_report_to_cases(connection: sqlite3.Connection, analysis_id: str) -> None:
    rows = connection.execute("""SELECT DISTINCT m.case_id FROM case_alerts m
        JOIN analysis_alert_coverage c ON c.alert_record_id=m.alert_record_id
        WHERE c.analysis_id=? AND m.active=1 ORDER BY m.case_id""", (analysis_id,)).fetchall()
    for row in rows:
        case_id = row[0]
        inserted = connection.execute("INSERT OR IGNORE INTO case_analyses(case_id,analysis_id,linked_at) VALUES(?,?,?)",
                                      (case_id, analysis_id, utc_now())).rowcount
        if inserted:
            append_case_event(connection, case_id, "analysis_linked", "system:report-storage",
                              "Stored report covers attached evidence; no case finding is inferred.",
                              {"analysis_id": analysis_id})


def record_analysis_case_links(connection: sqlite3.Connection, record: AnalysisRecord) -> None:
    record_report_coverage(connection, record.analysis_id, record.alert_record_id, record.evidence)
    link_report_to_cases(connection, record.analysis_id)


def backfill_attached_reports(connection: sqlite3.Connection, alert_ids: Sequence[str]) -> None:
    """Inspect a bounded batch, including legacy group reports' actual snapshots."""
    anchors = set(alert_ids)
    if has_group_storage(connection):
        for alert_id in alert_ids:
            row = connection.execute("""SELECT g.representative_record_id FROM alert_groups g JOIN alert_group_members m
                ON m.group_id=g.group_id WHERE m.alert_record_id=?""", (alert_id,)).fetchone()
            if row:
                anchors.add(row[0])
    if not anchors:
        return
    placeholders = ",".join("?" for _ in anchors)
    rows = connection.execute(f"""SELECT analysis_id,alert_record_id,length(CAST(evidence AS BLOB))
        FROM analyses WHERE alert_record_id IN ({placeholders}) ORDER BY analysis_id LIMIT 1001""",
        tuple(sorted(anchors))).fetchall()
    if len(rows) > 1000 or sum(row[2] for row in rows) > 8 * 1024 * 1024:
        raise CaseError("Historical report coverage exceeds the attachment budget; a bounded migration is required.")
    for row in rows:
        evidence_row = connection.execute("SELECT evidence FROM analyses WHERE analysis_id=?", (row[0],)).fetchone()
        if evidence_row is None:
            raise CaseError("Historical report disappeared during attachment.")
        record_report_coverage(connection, row[0], row[1], evidence_row[0])
        link_report_to_cases(connection, row[0])
