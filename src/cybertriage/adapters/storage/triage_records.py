"""Triage SQL operations; callers own the surrounding transaction."""

import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cybertriage.domain.alert import IngestionReceipt
from cybertriage.domain.triage_policy import TriagePlan


def initialize_triage_schema(connection: sqlite3.Connection) -> None:
    statements = (
        """CREATE TABLE IF NOT EXISTS triage_policies (
            revision TEXT PRIMARY KEY, settings_json TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS alert_groups (
            group_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
            representative_record_id TEXT NOT NULL UNIQUE REFERENCES alerts(record_id),
            window_start TEXT NOT NULL, window_end TEXT NOT NULL,
            max_members INTEGER NOT NULL CHECK(max_members BETWEEN 2 AND 5),
            created_at TEXT NOT NULL)""",
        """CREATE INDEX IF NOT EXISTS idx_alert_groups_fingerprint
            ON alert_groups(fingerprint)""",
        """CREATE TABLE IF NOT EXISTS alert_group_members (
            group_id TEXT NOT NULL REFERENCES alert_groups(group_id),
            alert_record_id TEXT NOT NULL UNIQUE REFERENCES alerts(record_id),
            joined_at TEXT NOT NULL, PRIMARY KEY(group_id, alert_record_id))""",
        """CREATE TABLE IF NOT EXISTS triage_decisions (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, decision_id TEXT NOT NULL UNIQUE,
            alert_record_id TEXT NOT NULL REFERENCES alerts(record_id),
            kind TEXT NOT NULL CHECK(kind IN ('ingestion', 'legacy', 'analyst_override')),
            action TEXT NOT NULL CHECK(action IN ('investigate', 'group', 'suppress')),
            reason TEXT NOT NULL, rule_id TEXT,
            policy_revision TEXT NOT NULL REFERENCES triage_policies(revision),
            group_id TEXT REFERENCES alert_groups(group_id),
            actor TEXT, created_at TEXT NOT NULL)""",
        """CREATE INDEX IF NOT EXISTS idx_triage_decisions_alert
            ON triage_decisions(alert_record_id, seq)""",
        """CREATE TABLE IF NOT EXISTS analyst_feedback (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, feedback_id TEXT NOT NULL UNIQUE,
            alert_record_id TEXT NOT NULL REFERENCES alerts(record_id),
            analyst TEXT NOT NULL, label TEXT NOT NULL
                CHECK(label IN ('benign', 'malicious', 'uncertain')),
            reason TEXT NOT NULL, created_at TEXT NOT NULL)""",
        """CREATE INDEX IF NOT EXISTS idx_analyst_feedback_alert
            ON analyst_feedback(alert_record_id, seq)""",
    )
    for statement in statements:
        connection.execute(statement)
    # Operator database access is trusted; these protect application-level audit history.
    for table in ("triage_policies", "triage_decisions", "analyst_feedback", "alert_group_members"):
        for operation in ("UPDATE", "DELETE"):
            connection.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()}
                BEFORE {operation} ON {table}
                BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END""")


def enqueue_analysis(connection: sqlite3.Connection, record_id: str, *, delay_seconds: int = 0) -> str:
    now = datetime.now(timezone.utc)
    connection.execute(
        """INSERT INTO analysis_jobs
            (job_id, alert_record_id, status, attempt_count, created_at, available_at)
            VALUES (?, ?, 'pending', 0, ?, ?)
            ON CONFLICT(alert_record_id) DO NOTHING""",
        (uuid4().hex, record_id, now.isoformat(),
         (now + timedelta(seconds=delay_seconds)).isoformat()),
    )
    return connection.execute("SELECT job_id FROM analysis_jobs WHERE alert_record_id = ?",
                              (record_id,)).fetchone()["job_id"]


def record_decision(connection: sqlite3.Connection, record_id: str, plan: TriagePlan,
                    *, action: str | None = None, group_id: str | None = None,
                    kind: str = "ingestion", actor: str | None = None) -> str:
    connection.execute("INSERT INTO triage_policies(revision, settings_json) VALUES (?, ?) "
                       "ON CONFLICT(revision) DO NOTHING",
                       (plan.policy_revision, plan.policy_snapshot_json))
    decision_id = uuid4().hex
    connection.execute(
        """INSERT INTO triage_decisions
            (decision_id, alert_record_id, kind, action, reason, rule_id,
             policy_revision, group_id, actor, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (decision_id, record_id, kind, action or plan.action, plan.reason, plan.rule_id,
         plan.policy_revision, group_id, actor, datetime.now(timezone.utc).isoformat()),
    )
    return decision_id


def apply_plan(connection: sqlite3.Connection, record_id: str, plan: TriagePlan) -> IngestionReceipt:
    group_id: str | None = None
    job_id: str | None = None
    action: str = plan.action
    candidate = plan.grouping
    if action == "investigate" and candidate is not None:
        existing = connection.execute(
            """SELECT g.group_id, j.job_id FROM alert_groups g
                JOIN analysis_jobs j ON j.alert_record_id = g.representative_record_id
                WHERE g.fingerprint = ? AND j.status = 'pending'
                AND (SELECT COUNT(*) FROM alert_group_members m
                     WHERE m.group_id = g.group_id) < g.max_members
                ORDER BY g.created_at DESC, g.group_id LIMIT 1""",
            (candidate.fingerprint,),
        ).fetchone()
        now = datetime.now(timezone.utc).isoformat()
        if existing is not None:
            group_id, job_id, action = existing["group_id"], existing["job_id"], "group"
        else:
            group_id = uuid4().hex
            connection.execute(
                """INSERT INTO alert_groups VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (group_id, candidate.fingerprint, record_id, candidate.window_start,
                 candidate.window_end, candidate.max_members, now),
            )
            job_id = enqueue_analysis(connection, record_id, delay_seconds=candidate.settle_seconds)
        connection.execute("INSERT INTO alert_group_members VALUES (?, ?, ?)",
                           (group_id, record_id, now))
    elif action == "investigate":
        job_id = enqueue_analysis(connection, record_id)

    decision_id = record_decision(connection, record_id, plan, action=action, group_id=group_id)
    return IngestionReceipt(record_id, True, action, decision_id, group_id, job_id)


def existing_receipt(connection: sqlite3.Connection, record_id: str) -> IngestionReceipt | None:
    row = connection.execute(
        "SELECT * FROM triage_decisions WHERE alert_record_id = ? ORDER BY seq DESC LIMIT 1",
        (record_id,),
    ).fetchone()
    if row is None:
        return None
    job = connection.execute("SELECT job_id FROM analysis_jobs WHERE alert_record_id = ?",
                             (record_id,)).fetchone()
    if job is None and row["group_id"] is not None:
        job = connection.execute(
            """SELECT j.job_id FROM alert_groups g JOIN analysis_jobs j
                ON j.alert_record_id = g.representative_record_id WHERE g.group_id = ?""",
            (row["group_id"],),
        ).fetchone()
    return IngestionReceipt(record_id, False, row["action"], row["decision_id"],
                            row["group_id"], job["job_id"] if job else None)
