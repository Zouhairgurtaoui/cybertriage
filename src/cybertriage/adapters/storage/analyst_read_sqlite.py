"""Bounded analyst projections over retained alerts and saved reports."""

import json
from dataclasses import asdict

from cybertriage.adapters.storage.cases_sqlite import SqliteCaseRepository
from cybertriage.application.services.case_management import identifier, page
from cybertriage.domain.case import CaseError


class SqliteAnalystAlertReader(SqliteCaseRepository):
    @staticmethod
    def _cursor(limit, before):
        page(limit)
        if before is not None and (type(before) is not int or not 1 <= before <= 9223372036854775807):
            raise CaseError("Cursor must be a positive SQLite sequence.")

    def _job_anchor(self, connection):
        if self._has(connection, "alert_groups") and self._has(connection, "alert_group_members"):
            return """COALESCE((SELECT g.representative_record_id FROM alert_group_members m
                JOIN alert_groups g ON g.group_id=m.group_id
                WHERE m.alert_record_id=a.record_id),a.record_id)"""
        return "a.record_id"

    @staticmethod
    def _has(connection, table):
        return connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None

    def list_alerts(self, limit=50, before=None):
        self._cursor(limit, before)
        with self._session() as connection:
            jobs = self._has(connection, "analysis_jobs")
            triage = self._has(connection, "triage_decisions")
            job_fields = "j.job_id,j.status AS job_status" if jobs else "NULL AS job_id,NULL AS job_status"
            triage_fields = """(SELECT d.action FROM triage_decisions d WHERE d.alert_record_id=a.record_id
                ORDER BY d.seq DESC LIMIT 1) AS triage_action""" if triage else "NULL AS triage_action"
            rows = connection.execute(f"""SELECT a.rowid AS sequence,a.record_id,a.source_instance,a.source_alert_id,a.received_at,
                json_extract(a.payload_json,'$.timestamp') AS event_time,json_extract(a.payload_json,'$.agent_name') AS agent_name,
                json_extract(a.payload_json,'$.rule_level') AS rule_level,json_extract(a.payload_json,'$.description') AS description,
                json_extract(a.payload_json,'$.event') AS event_json,{job_fields},{triage_fields}
                FROM alerts a {'LEFT JOIN analysis_jobs j ON j.alert_record_id=' + self._job_anchor(connection) if jobs else ''}
                WHERE (? IS NULL OR a.rowid<?) ORDER BY a.rowid DESC LIMIT ?""", (before, before, limit + 1)).fetchall()
            items = []
            for row in rows[:limit]:
                item = dict(row)
                event_json = item.pop("event_json")
                item["event"] = json.loads(event_json) if event_json else None
                items.append(item)
            return self._bounded({"alerts": items, "next_before": rows[limit - 1]["sequence"] if len(rows) > limit else None,
                "ordering": "Newest local insertion first; incident timestamps are shown separately."})

    def alert_detail(self, record_id):
        record_id = identifier(record_id)
        with self._session() as connection:
            evidence = self._alert(connection, record_id)
            row = connection.execute("SELECT received_at FROM alerts WHERE record_id=?", (record_id,)).fetchone()
            alert = asdict(evidence.alert)
            alert["timestamp"] = evidence.alert.timestamp.isoformat()
            alert["decoded_data"] = json.loads(alert.pop("decoded_data_json"))
            decision = None
            if self._has(connection, "triage_decisions"):
                decision = connection.execute("SELECT * FROM triage_decisions WHERE alert_record_id=? ORDER BY seq DESC LIMIT 1", (record_id,)).fetchone()
            job = None
            if self._has(connection, "analysis_jobs"):
                job = connection.execute(f"""SELECT j.job_id,j.status,j.attempt_count,j.last_error_code
                    FROM alerts a JOIN analysis_jobs j ON j.alert_record_id={self._job_anchor(connection)}
                    WHERE a.record_id=?""", (record_id,)).fetchone()
            return self._bounded({"record_id": record_id, "payload_sha256": evidence.payload_hash,
                "received_at": row["received_at"], "alert": alert, "latest_triage": dict(decision) if decision else None,
                "analysis_job": dict(job) if job else None}, 2 * 1024 * 1024)

    def list_analyses(self, limit=50, before=None, alert_id=None):
        self._cursor(limit, before)
        if alert_id is not None:
            alert_id = identifier(alert_id)
        with self._session() as connection:
            if alert_id is not None:
                self._alert(connection, alert_id)
            if not self._has(connection, "analyses"):
                return {"analyses": [], "next_before": None}
            rows = connection.execute("""SELECT r.rowid AS sequence,r.analysis_id,r.alert_record_id AS anchor_alert_id,
                r.completed_at,r.retrieval_query,a.source_instance,a.source_alert_id,
                json_extract(a.payload_json,'$.agent_name') AS agent_name,
                json_extract(a.payload_json,'$.description') AS description,
                (SELECT COUNT(*) FROM analysis_alert_coverage c WHERE c.analysis_id=r.analysis_id) AS covered_alert_count
                FROM analyses r JOIN alerts a ON a.record_id=r.alert_record_id
                WHERE (? IS NULL OR r.rowid<?) AND (? IS NULL OR r.alert_record_id=? OR EXISTS
                    (SELECT 1 FROM analysis_alert_coverage c WHERE c.analysis_id=r.analysis_id AND c.alert_record_id=?))
                ORDER BY r.rowid DESC LIMIT ?""", (before, before, alert_id, alert_id, alert_id, limit + 1)).fetchall()
            return self._bounded({"analyses": [dict(row) for row in rows[:limit]],
                "next_before": rows[limit - 1]["sequence"] if len(rows) > limit else None,
                "ordering": "Newest saved report first; automatic and requested reports share this list."})

    def analysis_detail(self, analysis_id):
        analysis_id = identifier(analysis_id)
        with self._session() as connection:
            if not self._has(connection, "analyses"):
                raise CaseError("Agent report not found.")
            row = connection.execute("SELECT * FROM analyses WHERE analysis_id=?", (analysis_id,)).fetchone()
            if row is None:
                raise CaseError("Agent report not found.")
            report = dict(row)
            report["result"] = json.loads(report.pop("result_json"))
            coverage = [dict(item) for item in connection.execute("""SELECT alert_record_id FROM analysis_alert_coverage
                WHERE analysis_id=? ORDER BY alert_record_id""", (analysis_id,))]
            return self._bounded({"report": report, "coverage": coverage,
                "interpretation": "Saved model analysis; analyst review is required. An empty coverage list indicates legacy coverage metadata."}, 2 * 1024 * 1024)
