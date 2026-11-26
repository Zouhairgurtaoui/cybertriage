"""Bounded inbox projections over retained alerts; no inference or scheduling."""

import json
from dataclasses import asdict

from cybertriage.adapters.storage.cases_sqlite import SqliteCaseRepository
from cybertriage.application.services.case_management import identifier, page
from cybertriage.domain.case import CaseError


class SqliteAnalystAlertReader(SqliteCaseRepository):
    @staticmethod
    def _has(connection, table):
        return connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None

    def list_alerts(self, limit=50, before=None):
        page(limit)
        if before is not None and (type(before) is not int or not 1 <= before <= 9223372036854775807):
            raise CaseError("Inbox cursor must be a positive SQLite sequence.")
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
                FROM alerts a {'LEFT JOIN analysis_jobs j ON j.alert_record_id=a.record_id' if jobs else ''}
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
            return self._bounded({"record_id": record_id, "payload_sha256": evidence.payload_hash,
                "received_at": row["received_at"], "alert": alert, "latest_triage": dict(decision) if decision else None}, 2 * 1024 * 1024)
