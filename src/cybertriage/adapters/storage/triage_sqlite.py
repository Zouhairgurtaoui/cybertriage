import json
import sqlite3
from contextlib import closing, contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from cybertriage.application.policies.alert_triage import decoded_field
from cybertriage.application.ports.triage_policy import AlertEvidenceGrounder
from cybertriage.adapters.storage.triage_records import (
    enqueue_analysis, initialize_triage_schema, record_decision,
)
from cybertriage.domain.alert import AlertNotFoundError
from cybertriage.domain.triage_policy import (
    AnalystFeedback, TriageEvaluationRow, TriagePlan, TriageReviewError,
)


class SqliteTriageReviewRepository:
    """Append-only decisions and labels; grouping remains candidate correlation."""

    def __init__(self, database_path: Path, grounder: AlertEvidenceGrounder | None = None):
        if not database_path.is_file():
            raise TriageReviewError("The alert database must already exist.")
        self._path = database_path.resolve()
        self._grounder = grounder
        with self._session(write=True) as connection:
            initialize_triage_schema(connection)

    @contextmanager
    def _session(self, *, write: bool = False):
        try:
            with closing(sqlite3.connect(f"{self._path.as_uri()}?mode=rw", uri=True, timeout=5)) as connection:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys = ON")
                with connection:
                    connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                    yield connection
        except (OSError, sqlite3.Error) as error:
            raise TriageReviewError("Triage storage operation failed.") from error

    @staticmethod
    def _require_alert(connection, record_id: str) -> None:
        if connection.execute("SELECT 1 FROM alerts WHERE record_id = ?", (record_id,)).fetchone() is None:
            raise AlertNotFoundError("No stored alert matches this record ID.")

    @staticmethod
    def _release(connection, record_id: str, analyst: str, reason: str) -> dict[str, object]:
        existing = connection.execute("SELECT job_id FROM analysis_jobs WHERE alert_record_id = ?",
                                      (record_id,)).fetchone()
        plan = TriagePlan("investigate", reason, None, "analyst-override-v1",
                          '{"source":"explicit_analyst_override","version":1}')
        decision_id = record_decision(connection, record_id, plan,
                                       kind="analyst_override", actor=analyst)
        job_id = enqueue_analysis(connection, record_id)
        job = connection.execute("SELECT status FROM analysis_jobs WHERE job_id = ?", (job_id,)).fetchone()
        return {"decision_id": decision_id, "job_id": job_id,
                "job_created": existing is None, "job_status": job["status"]}

    def feedback(self, feedback: AnalystFeedback) -> dict[str, object]:
        with self._session(write=True) as connection:
            self._require_alert(connection, feedback.alert_record_id)
            feedback_id = uuid4().hex
            connection.execute(
                """INSERT INTO analyst_feedback
                    (feedback_id, alert_record_id, analyst, label, reason, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                (feedback_id, feedback.alert_record_id, feedback.analyst,
                 feedback.label, feedback.reason, datetime.now(timezone.utc).isoformat()),
            )
            response: dict[str, object] = {"feedback_id": feedback_id, "label": feedback.label}
            if feedback.label in ("malicious", "uncertain"):
                response.update(self._release(connection, feedback.alert_record_id,
                                               feedback.analyst, feedback.reason))
            return response

    def release(self, alert_record_id: str, analyst: str, reason: str) -> dict[str, object]:
        with self._session(write=True) as connection:
            self._require_alert(connection, alert_record_id)
            return self._release(connection, alert_record_id, analyst, reason)

    def inspect(self, alert_record_id: str) -> dict[str, object]:
        with self._session() as connection:
            self._require_alert(connection, alert_record_id)
            decisions = connection.execute(
                "SELECT * FROM triage_decisions WHERE alert_record_id = ? ORDER BY seq DESC LIMIT 201",
                (alert_record_id,),
            ).fetchall()
            feedback = connection.execute(
                "SELECT * FROM analyst_feedback WHERE alert_record_id = ? ORDER BY seq DESC LIMIT 201",
                (alert_record_id,),
            ).fetchall()
            group = connection.execute(
                """SELECT g.* FROM alert_groups g JOIN alert_group_members m
                    ON m.group_id = g.group_id WHERE m.alert_record_id = ?""",
                (alert_record_id,),
            ).fetchone()
            members = [] if group is None else [dict(row) for row in connection.execute(
                """SELECT m.alert_record_id, a.source_instance, a.source_alert_id
                    FROM alert_group_members m JOIN alerts a ON a.record_id = m.alert_record_id
                    WHERE m.group_id = ? ORDER BY m.joined_at, m.alert_record_id""",
                (group["group_id"],),
            )]
            job = connection.execute("SELECT job_id, status, attempt_count FROM analysis_jobs WHERE alert_record_id = ?",
                                     (alert_record_id,)).fetchone()
            representative_job = None if group is None else connection.execute(
                "SELECT job_id, status, attempt_count FROM analysis_jobs WHERE alert_record_id = ?",
                (group["representative_record_id"],),
            ).fetchone()
            return {"alert_record_id": alert_record_id,
                    "decisions": [dict(row) for row in decisions[:200]],
                    "feedback": [dict(row) for row in feedback[:200]],
                    "history_truncated": len(decisions) > 200 or len(feedback) > 200,
                    "group": dict(group) if group else None, "group_members": members,
                    "representative_job": dict(representative_job) if representative_job else None,
                    "individual_job": dict(job) if job else None}

    def evaluation_rows(self) -> tuple[TriageEvaluationRow, ...]:
        with self._session() as connection:
            rows = connection.execute(
                """SELECT COALESCE(d.action, 'untriaged') AS action,
                          COALESCE(d.policy_revision, 'pre-policy') AS policy_revision, f.label
                    FROM alerts a
                    LEFT JOIN triage_decisions d ON d.seq = (
                        SELECT MIN(seq) FROM triage_decisions WHERE alert_record_id = a.record_id
                        AND kind IN ('ingestion', 'legacy'))
                    LEFT JOIN analyst_feedback f ON f.seq = (
                        SELECT MAX(seq) FROM analyst_feedback WHERE alert_record_id = a.record_id)
                    ORDER BY a.record_id LIMIT 100001"""
            ).fetchall()
            if len(rows) > 100000:
                raise TriageReviewError("Evaluation exceeds 100000 alerts; export a bounded dataset.")
            return tuple(TriageEvaluationRow(row["action"], row["policy_revision"], row["label"]) for row in rows)

    def group_context(self, representative_record_id: str) -> str | None:
        from cybertriage.adapters.storage.alerts_sqlite import SqliteAlertRepository

        with self._session() as connection:
            group = connection.execute(
                "SELECT * FROM alert_groups WHERE representative_record_id = ?",
                (representative_record_id,),
            ).fetchone()
            if group is None:
                return None
            rows = connection.execute(
                """SELECT a.payload_json, a.payload_hash FROM alert_group_members m
                    JOIN alerts a ON a.record_id = m.alert_record_id
                    WHERE m.group_id = ? ORDER BY m.joined_at, m.alert_record_id""",
                (group["group_id"],),
            ).fetchall()
            if not 1 <= len(rows) <= 5:
                raise TriageReviewError("Invalid group membership count.")
            summaries = []
            selected_fields = (
                "win.eventdata.targetUserName", "win.eventdata.targetDomainName",
                "win.eventdata.ipAddress", "win.eventdata.logonType",
                "win.eventdata.status", "win.eventdata.subStatus",
                "win.eventdata.failureReason", "win.eventdata.subjectUserName",
                "srcip", "dstuser",
            )
            for row in rows:
                if sha256(row["payload_json"].encode("utf-8")).hexdigest() != row["payload_hash"]:
                    raise TriageReviewError("Grouped alert failed its integrity check.")
                alert = SqliteAlertRepository._deserialize(row["payload_json"])
                data = json.loads(alert.decoded_data_json)
                summaries.append({
                    "source_instance": alert.source_instance, "source_alert_id": alert.source_alert_id,
                    "timestamp": alert.timestamp.isoformat(), "agent_id": alert.agent_id,
                    "agent_name": alert.agent_name, "rule_id": alert.rule_id,
                    "rule_level": alert.rule_level,
                    "event": asdict(alert.event) if alert.event else None,
                    "description_excerpt": alert.description[:120],
                    "fields": {key: value for key in selected_fields
                               if (value := decoded_field(data, key)) is not None},
                    "grounding": dict(self._grounder.ground_alert(alert)) if self._grounder else None,
                })
            summaries.sort(key=lambda item: (
                str(item["timestamp"]), str(item["source_instance"]), str(item["source_alert_id"]),
            ))
            payload = {"group_id": group["group_id"], "grouped_event_count": len(summaries),
                       "window_start": group["window_start"], "window_end": group["window_end"],
                       "alerts": summaries, "raw_context_omitted": True,
                       "interpretation": "Candidate grouping by shared fields and time; not proof of a common actor or attack. Full original alerts remain stored.",
                       "scope": "Only members delivered to this group; the grouping window is not an executed log search or a claim of complete activity coverage."}
            content = json.dumps(payload, ensure_ascii=True, allow_nan=False)
            if len(content.encode("utf-8")) > 11000:
                raise TriageReviewError("Grouped evidence exceeds its report input budget.")
            return content
