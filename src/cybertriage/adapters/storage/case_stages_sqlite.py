import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from uuid import uuid4

from cybertriage.adapters.storage.cases_sqlite import SqliteCaseRepository
from cybertriage.adapters.storage.case_records import append_case_event, utc_now
from cybertriage.domain.case import CaseError, IncidentCase
from cybertriage.domain.graph import KILL_CHAIN_STAGES


class SqliteCaseStageRepository(SqliteCaseRepository):
    """Append stage assessments and reviews using the existing case transaction boundary."""

    def add_stage(self, case_id: str, stage: str, kind: str, supporting_ids: Sequence[str], expected_version: int,
                  actor: str, reason: str) -> Mapping[str, object]:
        if stage not in dict(KILL_CHAIN_STAGES) or kind not in {"hypothesis", "analyst_assessed"} or not supporting_ids:
            raise CaseError("A supported stage, assessment kind and attached evidence are required.")
        with self._session(True) as connection:
            self._case(connection, case_id, expected_version, editable=True)
            self._attached(connection, case_id, supporting_ids)
            if connection.execute("SELECT COUNT(*) FROM case_stage_assertions WHERE case_id=?", (case_id,)).fetchone()[0] >= 2000:
                raise CaseError("Case stage-assessment capacity exceeded.")
            assertion_id = uuid4().hex
            connection.execute("""INSERT INTO case_stage_assertions
                (assertion_id,case_id,stage,kind,supporting_ids_json,actor,reason,recorded_at) VALUES(?,?,?,?,?,?,?,?)""",
                (assertion_id, case_id, stage, kind, json.dumps(list(supporting_ids)), actor, reason, utc_now()))
            append_case_event(connection, case_id, "kill_chain_stage_asserted", actor, reason,
                {"assertion_id": assertion_id, "stage": stage, "kind": kind, "supporting_alert_ids": list(supporting_ids),
                 "interpretation": "Explicit operator assessment; not an automatic finding of attack success or compromise."})
            return {"case": asdict(self._case(connection, case_id)), "assertion_id": assertion_id,
                    "kind": kind, "stage": stage, "review_status": "proposed" if kind == "hypothesis" else "recorded"}

    def review_stage(self, case_id: str, assertion_id: str, decision: str, expected_version: int,
                     actor: str, reason: str) -> IncidentCase:
        with self._session(True) as connection:
            self._case(connection, case_id, expected_version, editable=True)
            row = connection.execute("SELECT kind FROM case_stage_assertions WHERE case_id=? AND assertion_id=?", (case_id, assertion_id)).fetchone()
            if row is None:
                raise CaseError("Stage assessment does not belong to this case.")
            allowed = {"accepted", "rejected", "superseded"} if row[0] == "hypothesis" else {"accepted", "retracted", "superseded"}
            if decision not in allowed:
                raise CaseError("Invalid review decision for this stage-assessment kind.")
            connection.execute("INSERT INTO case_stage_reviews(assertion_id,decision,actor,reason,recorded_at) VALUES(?,?,?,?,?)",
                (assertion_id, decision, actor, reason, utc_now()))
            append_case_event(connection, case_id, "kill_chain_stage_reviewed", actor, reason,
                {"assertion_id": assertion_id, "kind": row[0], "decision": decision,
                 "interpretation": "Review preserves the assessment kind and does not update case disposition."})
            return self._case(connection, case_id)

    def stages(self, case_id: str, limit: int, after: int) -> Mapping[str, object]:
        with self._session() as connection:
            case = self._case(connection, case_id)
            rows = connection.execute("""SELECT s.*,COALESCE((SELECT decision FROM case_stage_reviews r
                WHERE r.assertion_id=s.assertion_id ORDER BY r.seq DESC LIMIT 1),
                CASE s.kind WHEN 'hypothesis' THEN 'proposed' ELSE 'recorded' END) AS review_status
                FROM case_stage_assertions s WHERE s.case_id=? AND s.seq>? ORDER BY s.seq LIMIT ?""",
                (case_id, after, limit + 1)).fetchall()
            items = []
            for row in rows[:limit]:
                item = dict(row)
                item["supporting_alert_ids"] = json.loads(item.pop("supporting_ids_json"))
                items.append(item)
            return self._bounded({"case_id": case_id, "case_version": case.version, "stages": items,
                "next_after": rows[limit - 1]["seq"] if len(rows) > limit else None})
