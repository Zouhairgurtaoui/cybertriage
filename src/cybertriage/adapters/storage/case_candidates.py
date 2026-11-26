"""Bounded retained-alert correlation candidates; no automatic case mutation."""

import json
from datetime import timedelta, timezone

from cybertriage.adapters.storage.cases_sqlite import SqliteCaseRepository
from cybertriage.application.policies.alert_triage import decoded_field
from cybertriage.application.services.case_management import identifier
from cybertriage.domain.case import CaseError


class SqliteCaseCandidates(SqliteCaseRepository):
    def __init__(self, database_path):
        super().__init__(database_path)
        with self._session(True) as connection:
            connection.execute("""CREATE INDEX IF NOT EXISTS alerts_manager_reported_time
                ON alerts(source_instance,julianday(json_extract(payload_json,'$.timestamp')))""")

    def suggest(self, case_id: str, anchor_id: str, window_seconds: int = 300, limit: int = 20):
        case_id, anchor_id = identifier(case_id), identifier(anchor_id)
        if type(window_seconds) is not int or not 1 <= window_seconds <= 3600 or type(limit) is not int or not 1 <= limit <= 100:
            raise CaseError("Candidate window must be 1..3600 seconds and limit 1..100.")
        with self._session() as connection:
            case = self._case(connection, case_id)
            self._attached(connection, case_id, [anchor_id])
            anchor = self._alert(connection, anchor_id)
            alert = anchor.alert
            data = json.loads(alert.decoded_data_json)
            accounts = []
            for role in ("target", "subject"):
                name = decoded_field(data, f"win.eventdata.{role}UserName")
                domain = decoded_field(data, f"win.eventdata.{role}DomainName")
                if name and domain and name != "-" and domain != "-":
                    accounts.append((name, domain, role))
            timestamp = alert.timestamp.astimezone(timezone.utc)
            try:
                start, end = timestamp - timedelta(seconds=window_seconds), timestamp + timedelta(seconds=window_seconds)
            except OverflowError as error:
                raise CaseError("Anchor timestamp cannot support the requested candidate window.") from error
            conditions = ["json_extract(a.payload_json,'$.agent_id')=?"]
            values = [alert.agent_id]
            for name, domain, _ in accounts:
                for role in ("target", "subject"):
                    conditions.append(f"""(json_extract(json_extract(a.payload_json,'$.decoded_data_json'),'$.win.eventdata.{role}UserName')=?
                        AND json_extract(json_extract(a.payload_json,'$.decoded_data_json'),'$.win.eventdata.{role}DomainName')=?)""")
                    values.extend((name, domain))
            # JSON paths are fixed field-role constants; all identities and times are SQL parameters.
            rows = connection.execute(f"""SELECT a.record_id FROM alerts a WHERE a.source_instance=? AND a.record_id<>?
                AND NOT EXISTS(SELECT 1 FROM case_alerts m WHERE m.case_id=? AND m.alert_record_id=a.record_id AND m.active=1)
                AND julianday(json_extract(a.payload_json,'$.timestamp')) BETWEEN julianday(?) AND julianday(?)
                AND ({' OR '.join(conditions)}) ORDER BY a.record_id LIMIT 2001""",
                (alert.source_instance, anchor_id, case_id, start.isoformat(), end.isoformat(), *values)).fetchall()
            if len(rows) > 2000:
                raise CaseError("Candidate scope exceeds 2000 alerts; use a smaller window.")
            candidates = []
            for row in rows:
                evidence = self._alert(connection, row["record_id"])
                item = evidence.alert
                if not start <= item.timestamp <= end:
                    continue
                other = json.loads(item.decoded_data_json)
                reasons = []
                if item.agent_id == alert.agent_id:
                    reasons.append({"kind": "same_reported_host", "manager": alert.source_instance, "agent_id": alert.agent_id})
                for name, domain, source_role in accounts:
                    for target_role in ("target", "subject"):
                        if decoded_field(other, f"win.eventdata.{target_role}UserName") == name and decoded_field(other, f"win.eventdata.{target_role}DomainName") == domain:
                            reasons.append({"kind": "same_reported_account_fields", "name": name, "domain": domain,
                                "anchor_role": source_role, "candidate_role": target_role})
                if reasons:
                    candidates.append({"alert_record_id": evidence.record_id, "source_alert_id": item.source_alert_id,
                        "agent_name": item.agent_name, "timestamp": item.timestamp.isoformat(),
                        "event": {"provider": item.event.provider, "channel": item.event.channel, "event_id": item.event.event_id} if item.event else None,
                        "rule_level": item.rule_level, "reasons": reasons, "payload_sha256": evidence.payload_hash,
                        "distance_seconds": abs((item.timestamp - timestamp).total_seconds())})
            candidates.sort(key=lambda row: (row["distance_seconds"], row["alert_record_id"]))
            return self._bounded({"case_id": case_id, "case_version": case.version, "anchor_alert_id": anchor_id,
                "anchor_payload_sha256": anchor.payload_hash, "candidate_count": len(candidates),
                "has_more": len(candidates) > limit, "candidates": candidates[:limit],
                "scope": {"source_instance": alert.source_instance, "start": start.isoformat(), "end": end.isoformat()},
                "interpretation": "Shared reported host/account fields within a time window are review candidates, not an attacker identity or causal attack chain. No alerts were attached."})
