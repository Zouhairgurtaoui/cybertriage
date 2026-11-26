"""Transactional case storage sharing the alert/report SQLite database."""

import base64
import json
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from typing import cast
from uuid import uuid4

from cybertriage.adapters.storage.alerts_sqlite import SqliteAlertRepository
from cybertriage.adapters.storage.analyses_sqlite import SqliteAnalysisWriter
from cybertriage.adapters.storage.case_records import (
    append_case_event, backfill_attached_reports, has_group_storage, utc_now,
)
from cybertriage.domain.case import (
    CaseAlertEvidence, CaseConflictError, CaseDisposition, CaseError, CasePriority,
    CaseStatus, CaseStorageError, IncidentCase, RelationshipAssertion,
)


class SqliteCaseRepository:
    def __init__(self, database_path: Path):
        if not database_path.is_file():
            raise CaseError("The alert database must already exist.")
        self._database_path = database_path
        with self._session() as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(alerts)")}
            if not {"record_id", "source_instance", "source_alert_id", "payload_json", "payload_hash", "received_at"} <= columns:
                raise CaseError("This file is not a CyberTriage alert database.")
        SqliteAnalysisWriter(database_path)

    @contextmanager
    def _session(self, write: bool = False) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._database_path.resolve().as_uri() + "?mode=rw", uri=True, timeout=5)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection
            connection.commit()
        except sqlite3.Error as error:
            connection.rollback()
            raise CaseStorageError("Case storage operation failed; no partial changes were committed.") from error
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _case(connection: sqlite3.Connection, case_id: str, expected: int | None = None,
              editable: bool = False) -> IncidentCase:
        row = connection.execute("SELECT * FROM incident_cases WHERE case_id=?", (case_id,)).fetchone()
        if row is None:
            raise CaseError("Case not found.")
        if expected is not None and row["version"] != expected:
            raise CaseConflictError("Case version changed; reload the case before retrying.")
        if editable and row["status"] in {"resolved", "closed"}:
            raise CaseError("Reopen the case before changing its evidence or relationships.")
        return IncidentCase(row["case_id"], row["title"], row["description"],
                            cast(CasePriority, row["priority"]), cast(CaseStatus, row["status"]),
                            cast(CaseDisposition, row["disposition"]), row["version"], row["created_at"], row["updated_at"])

    @staticmethod
    def _attached(connection: sqlite3.Connection, case_id: str, ids: Sequence[str]) -> None:
        for alert_id in set(ids):
            if not connection.execute("SELECT 1 FROM case_alerts WHERE case_id=? AND alert_record_id=? AND active=1",
                                      (case_id, alert_id)).fetchone():
                raise CaseError(f"Alert {alert_id} is not actively attached to this case.")

    @staticmethod
    def _alert(connection: sqlite3.Connection, record_id: str) -> CaseAlertEvidence:
        row = connection.execute("SELECT payload_json,payload_hash FROM alerts WHERE record_id=?", (record_id,)).fetchone()
        if row is None:
            raise CaseError("Alert not found.")
        if sha256(row[0].encode("utf-8")).hexdigest() != row[1]:
            raise CaseError("Stored alert failed its integrity check.")
        return CaseAlertEvidence(record_id, SqliteAlertRepository._deserialize(row[0]), row[1])

    def create(self, title: str, description: str, priority: str, actor: str) -> IncidentCase:
        case_id, now = uuid4().hex, utc_now()
        with self._session(True) as connection:
            connection.execute("""INSERT INTO incident_cases
                (case_id,title,description,priority,status,disposition,version,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                               (case_id, title, description, priority, "open", "unconfirmed", 1, now, now))
            append_case_event(connection, case_id, "case_created", actor, "Case opened.",
                              {"title": title, "description": description, "priority": priority}, advance_version=False)
            return self._case(connection, case_id)

    def get(self, case_id: str) -> IncidentCase:
        with self._session() as connection:
            return self._case(connection, case_id)

    def require_active_alert(self, case_id: str, alert_id: str) -> None:
        with self._session() as connection:
            self._case(connection, case_id)
            self._attached(connection, case_id, [alert_id])

    def list_cases(self, status: str | None, limit: int, after: str | None) -> Mapping[str, object]:
        with self._session() as connection:
            rows = connection.execute("""SELECT * FROM incident_cases WHERE (? IS NULL OR status=?)
                AND (? IS NULL OR case_id>?) ORDER BY case_id LIMIT ?""", (status, status, after, after, limit + 1)).fetchall()
            return self._bounded({"cases": [dict(row) for row in rows[:limit]],
                    "next_after": rows[limit - 1]["case_id"] if len(rows) > limit else None,
                    "ordering": "case_id; new cases can appear on either side of a listing cursor"})

    def update(self, case_id: str, changes: Mapping[str, str], expected_version: int,
               actor: str, reason: str, supporting_ids: Sequence[str]) -> IncidentCase:
        if not changes or set(changes) - {"title", "description", "priority", "status", "disposition"}:
            raise CaseError("Invalid case update fields.")
        with self._session(True) as connection:
            previous = self._case(connection, case_id, expected_version)
            self._attached(connection, case_id, supporting_ids)
            if changes.get("disposition") == "confirmed_compromise" and not supporting_ids:
                raise CaseError("Supporting attached alerts are required to confirm compromise.")
            changed = {key: value for key, value in changes.items() if getattr(previous, key) != value}
            if changed:
                assignments = ",".join(f"{key}=?" for key in changed)  # keys restricted above
                connection.execute(f"UPDATE incident_cases SET {assignments} WHERE case_id=?", (*changed.values(), case_id))
                append_case_event(connection, case_id, "case_updated", actor, reason,
                                  {"before": {key: getattr(previous, key) for key in changed}, "after": changed,
                                   "supporting_alert_ids": list(supporting_ids), "finding_origin": "explicit_operator_command"})
            return self._case(connection, case_id)

    def attach(self, case_id: str, alert_ids: Sequence[str], group_id: str | None,
               actor: str, reason: str) -> Mapping[str, object]:
        with self._session(True) as connection:
            self._case(connection, case_id, editable=True)
            if group_id:
                if not has_group_storage(connection):
                    raise CaseError("This database has no triage group storage.")
                rows = connection.execute("SELECT alert_record_id FROM alert_group_members WHERE group_id=? ORDER BY alert_record_id", (group_id,)).fetchall()
                if not rows or len(rows) > 5:
                    raise CaseError("Group not found or group membership is invalid.")
                alert_ids = tuple(row[0] for row in rows)
            added = []
            for alert_id in dict.fromkeys(alert_ids):
                self._alert(connection, alert_id)
                current = connection.execute("SELECT active FROM case_alerts WHERE case_id=? AND alert_record_id=?", (case_id, alert_id)).fetchone()
                if current and current[0]:
                    continue
                total = connection.execute("SELECT COUNT(*) FROM case_alerts WHERE case_id=?", (case_id,)).fetchone()[0]
                memberships = connection.execute("SELECT COUNT(*) FROM case_alerts WHERE alert_record_id=? AND active=1", (alert_id,)).fetchone()[0]
                if (not current and total >= 1000) or memberships >= 20:
                    raise CaseError("Case capacity (1000 historic alerts) or alert membership capacity (20 active cases) reached.")
                now = utc_now()
                connection.execute("""INSERT INTO case_alerts(case_id,alert_record_id,active,first_attached_at,changed_at)
                    VALUES(?,?,1,?,?) ON CONFLICT(case_id,alert_record_id) DO UPDATE SET active=1,changed_at=excluded.changed_at""",
                    (case_id, alert_id, now, now))
                append_case_event(connection, case_id, "alert_attached", actor, reason,
                                  {"alert_record_id": alert_id, "group_snapshot_id": group_id,
                                   "interpretation": "Case membership does not establish a common attacker."})
                added.append(alert_id)
            backfill_attached_reports(connection, added)
            return {"case": asdict(self._case(connection, case_id)), "attached_alert_ids": added,
                    "unchanged_alert_ids": [value for value in alert_ids if value not in added]}

    def detach(self, case_id: str, alert_id: str, expected_version: int, actor: str, reason: str) -> IncidentCase:
        with self._session(True) as connection:
            self._case(connection, case_id, expected_version, editable=True)
            self._attached(connection, case_id, (alert_id,))
            connection.execute("UPDATE case_alerts SET active=0,changed_at=? WHERE case_id=? AND alert_record_id=?", (utc_now(), case_id, alert_id))
            append_case_event(connection, case_id, "alert_detached", actor, reason,
                              {"alert_record_id": alert_id, "retained": "Original alert, reports and relationship history remain stored."})
            return self._case(connection, case_id)

    def note(self, case_id: str, text: str, actor: str) -> IncidentCase:
        with self._session(True) as connection:
            self._case(connection, case_id)
            append_case_event(connection, case_id, "investigation_note", actor, text, {})
            return self._case(connection, case_id)

    def alert_evidence(self, record_id: str) -> CaseAlertEvidence:
        with self._session() as connection:
            return self._alert(connection, record_id)

    def relate(self, case_id: str, assertion: RelationshipAssertion, actor: str) -> Mapping[str, object]:
        with self._session(True) as connection:
            self._case(connection, case_id, editable=True)
            self._attached(connection, case_id, (assertion.source_alert_id, assertion.target_alert_id, *assertion.supporting_alert_ids))
            if assertion.analysis_id and not connection.execute("SELECT 1 FROM case_analyses WHERE case_id=? AND analysis_id=?", (case_id, assertion.analysis_id)).fetchone():
                raise CaseError("Supporting analysis is not linked to this case.")
            if assertion.kind == "observed":
                proof = json.loads(assertion.proof_json)
                for field, alert_id in (("source_payload_sha256", assertion.source_alert_id), ("target_payload_sha256", assertion.target_alert_id)):
                    if proof.get(field) != self._alert(connection, alert_id).payload_hash:
                        raise CaseConflictError("Relationship evidence changed; rebuild the assertion.")
            relationship_id = uuid4().hex
            connection.execute("""INSERT INTO case_relationships
                (relationship_id,case_id,source_alert_id,target_alert_id,kind,predicate,rationale,supporting_ids_json,
                 proof_json,analysis_id,actor,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (relationship_id, case_id, assertion.source_alert_id, assertion.target_alert_id, assertion.kind,
                 assertion.predicate, assertion.rationale, json.dumps(assertion.supporting_alert_ids), assertion.proof_json,
                 assertion.analysis_id, actor, utc_now()))
            append_case_event(connection, case_id, "relationship_asserted", actor, assertion.rationale,
                              {"relationship_id": relationship_id, "kind": assertion.kind, "predicate": assertion.predicate,
                               "source_alert_id": assertion.source_alert_id, "target_alert_id": assertion.target_alert_id})
            return {"case": asdict(self._case(connection, case_id)), "relationship_id": relationship_id,
                    "kind": assertion.kind, "review_status": "recorded" if assertion.kind == "observed" else "proposed"}

    def review_relationship(self, case_id: str, relationship_id: str, decision: str,
                            expected_version: int, actor: str, reason: str) -> IncidentCase:
        with self._session(True) as connection:
            self._case(connection, case_id, expected_version, editable=True)
            row = connection.execute("SELECT kind FROM case_relationships WHERE case_id=? AND relationship_id=?", (case_id, relationship_id)).fetchone()
            if not row:
                raise CaseError("Relationship not found in this case.")
            allowed = {"accepted", "rejected", "superseded"} if row[0] == "hypothesis" else {"retracted", "superseded"}
            if decision not in allowed:
                raise CaseError("This review decision is not valid for the relationship kind.")
            connection.execute("""INSERT INTO case_relationship_reviews(relationship_id,decision,actor,reason,recorded_at)
                VALUES(?,?,?,?,?)""", (relationship_id, decision, actor, reason, utc_now()))
            append_case_event(connection, case_id, "relationship_reviewed", actor, reason,
                              {"relationship_id": relationship_id, "decision": decision, "kind": row[0],
                               "interpretation": "Review does not convert a hypothesis into an observation."})
            return self._case(connection, case_id)

    def read(self, case_id: str, section: str, limit: int, after: int) -> Mapping[str, object]:
        queries = {
            "alerts": """SELECT m.*,a.source_instance,a.source_alert_id,a.payload_hash,
                json_extract(a.payload_json,'$.timestamp') AS event_time,
                json_extract(a.payload_json,'$.agent_name') AS agent_name,
                json_extract(a.payload_json,'$.event') AS event_json
                FROM case_alerts m JOIN alerts a ON a.record_id=m.alert_record_id WHERE m.case_id=? AND m.seq>? ORDER BY m.seq LIMIT ?""",
            "history": "SELECT * FROM case_events WHERE case_id=? AND seq>? ORDER BY seq LIMIT ?",
            "relationships": """SELECT r.*, COALESCE((SELECT decision FROM case_relationship_reviews v WHERE v.relationship_id=r.relationship_id ORDER BY v.seq DESC LIMIT 1),
                CASE r.kind WHEN 'observed' THEN 'recorded' ELSE 'proposed' END) AS review_status,
                s.active AS source_attached,t.active AS target_attached
                FROM case_relationships r JOIN case_alerts s ON s.case_id=r.case_id AND s.alert_record_id=r.source_alert_id
                JOIN case_alerts t ON t.case_id=r.case_id AND t.alert_record_id=r.target_alert_id
                WHERE r.case_id=? AND r.seq>? ORDER BY r.seq LIMIT ?""",
            "investigations": """SELECT c.*,a.alert_record_id AS anchor_alert_id,a.completed_at,a.retrieval_query,
                (SELECT COUNT(*) FROM analysis_alert_coverage x WHERE x.analysis_id=a.analysis_id) AS covered_alert_count
                FROM case_analyses c JOIN analyses a ON a.analysis_id=c.analysis_id WHERE c.case_id=? AND c.seq>? ORDER BY c.seq LIMIT ?""",
        }
        with self._session() as connection:
            case = self._case(connection, case_id)
            rows = connection.execute(queries[section], (case_id, after, limit + 1)).fetchall()
            items = []
            for row in rows[:limit]:
                item = dict(row)
                for key in tuple(item):
                    if key.endswith("_json"):
                        raw = item.pop(key)
                        item[key[:-5]] = json.loads(raw) if raw is not None else None
                items.append(item)
            return self._bounded({"case_id": case_id, "case_version": case.version, section: items,
                                  "next_after": rows[limit - 1]["seq"] if len(rows) > limit else None})

    def report(self, case_id: str, analysis_id: str) -> Mapping[str, object]:
        with self._session() as connection:
            self._case(connection, case_id)
            row = connection.execute("""SELECT a.* FROM analyses a JOIN case_analyses c ON c.analysis_id=a.analysis_id
                WHERE c.case_id=? AND c.analysis_id=?""", (case_id, analysis_id)).fetchone()
            if row is None:
                raise CaseError("Report not linked to this case.")
            covered = connection.execute("""SELECT x.alert_record_id,COALESCE(m.active,0) AS actively_attached
                FROM analysis_alert_coverage x LEFT JOIN case_alerts m ON m.alert_record_id=x.alert_record_id AND m.case_id=?
                WHERE x.analysis_id=? ORDER BY x.alert_record_id""", (case_id, analysis_id)).fetchall()
            report = dict(row)
            report["result"] = json.loads(report.pop("result_json"))
            return self._bounded({"case_id": case_id, "report": report, "coverage": [dict(item) for item in covered],
                                  "interpretation": "Model report remains provisional. Coverage can include alerts outside this case; no extra members were attached."}, 2 * 1024 * 1024)

    def timeline(self, case_id: str, limit: int, cursor: str | None) -> Mapping[str, object]:
        with self._session() as connection:
            case = self._case(connection, case_id)
            last: tuple[str, str, str] = ("", "", "")
            if cursor:
                try:
                    value = json.loads(base64.b64decode(cursor, altchars=b"-_", validate=True))
                    if not isinstance(value, dict) or set(value) != {"case_id", "version", "last"} or value["case_id"] != case_id:
                        raise ValueError()
                    if type(value["version"]) is not int or value["version"] != case.version:
                        raise CaseConflictError("Case changed while paging; restart the timeline.")
                    parts = value["last"]
                    if not isinstance(parts, list) or len(parts) != 3 or not all(isinstance(part, str) and len(part) <= 128 for part in parts):
                        raise ValueError()
                    last = (parts[0], parts[1], parts[2])
                except (ValueError, TypeError, KeyError, RecursionError) as error:
                    if isinstance(error, CaseConflictError):
                        raise
                    raise CaseError("Invalid timeline cursor.") from error
            rows = connection.execute("""WITH timeline AS (
                SELECT json_extract(a.payload_json,'$.timestamp') AS occurred_at,'alert' AS kind,a.record_id AS item_id,
                    a.received_at AS recorded_at,json_object('alert_record_id',a.record_id,'source_alert_id',a.source_alert_id,
                    'source_instance',a.source_instance,'agent_name',json_extract(a.payload_json,'$.agent_name'),
                    'event',json_extract(a.payload_json,'$.event'),'currently_attached',m.active) AS details
                    FROM case_alerts m JOIN alerts a ON a.record_id=m.alert_record_id WHERE m.case_id=?
                UNION ALL SELECT e.occurred_at,'history',e.event_id,e.recorded_at,
                    json_object('event_kind',e.kind,'actor',e.actor,'reason',e.reason,'details',json(e.details_json))
                    FROM case_events e WHERE e.case_id=?
                UNION ALL SELECT a.completed_at,'analysis',a.analysis_id,c.linked_at,
                    json_object('analysis_id',a.analysis_id,'anchor_alert_id',a.alert_record_id,'provisional',json('true'))
                    FROM case_analyses c JOIN analyses a ON a.analysis_id=c.analysis_id WHERE c.case_id=?)
                SELECT * FROM timeline WHERE (occurred_at,kind,item_id)>(?,?,?) ORDER BY occurred_at,kind,item_id LIMIT ?""",
                (case_id, case_id, case_id, *last, limit + 1)).fetchall()
            items = []
            for row in rows[:limit]:
                item = dict(row)
                item["details"] = json.loads(item["details"])
                items.append(item)
            next_cursor = None
            if len(rows) > limit:
                end = rows[limit - 1]
                token = {"case_id": case_id, "version": case.version, "last": [end["occurred_at"], end["kind"], end["item_id"]]}
                next_cursor = base64.urlsafe_b64encode(json.dumps(token).encode()).decode()
            return self._bounded({"case_id": case_id, "case_version": case.version, "timeline": items,
                                  "next_cursor": next_cursor, "ordering": "reported/recorded UTC time, kind, ID; chronology is not causation"})

    @staticmethod
    def _bounded(value: dict[str, object], budget: int = 512 * 1024) -> Mapping[str, object]:
        if len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")) > budget:
            raise CaseError("Case output exceeds its byte budget; request a smaller page.")
        return value
