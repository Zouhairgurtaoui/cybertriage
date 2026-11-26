"""Consistent, bounded read-only snapshots of authoritative case records."""

import json
import sqlite3
from contextlib import closing
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path

from cybertriage.adapters.storage.case_records import utc_now
from cybertriage.adapters.storage.cases_sqlite import SqliteCaseRepository
from cybertriage.domain.graph import CaseGraphSnapshot, GraphAlert, GraphError, GraphStorageError, canonical_json

MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024


class SqliteCaseGraphReader:
    def __init__(self, database_path: Path):
        self._path = database_path.resolve()

    def _connect(self):
        connection = sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        return connection

    def current_version(self, case_id: str) -> int:
        try:
            with closing(self._connect()) as connection:
                return SqliteCaseRepository._case(connection, case_id).version
        except sqlite3.Error as error:
            raise GraphStorageError("Cannot read the authoritative case version.") from error

    def snapshot(self, case_id: str) -> CaseGraphSnapshot:
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN")
                case = SqliteCaseRepository._case(connection, case_id)
                budget = 0

                def rows(query, parameters, maximum):
                    nonlocal budget
                    output = []
                    for row in connection.execute(query, parameters):
                        # Count before adding; SQLite may return one large row, never an unbounded result list.
                        item = dict(row)
                        budget += len(canonical_json(item).encode("utf-8"))
                        if len(output) >= maximum or budget > MAX_SNAPSHOT_BYTES:
                            raise GraphError("Case exceeds the graph snapshot budget; narrow or archive the case first.")
                        output.append(item)
                    return output

                memberships = rows("""SELECT m.*,a.payload_hash,a.received_at,
                    length(CAST(a.payload_json AS BLOB)) AS payload_bytes FROM case_alerts m
                    JOIN alerts a ON a.record_id=m.alert_record_id WHERE m.case_id=? ORDER BY m.seq""", (case_id,), 1000)
                if budget + sum(row["payload_bytes"] for row in memberships) > MAX_SNAPSHOT_BYTES:
                    raise GraphError("Alert payloads exceed the graph snapshot budget.")
                budget += sum(row["payload_bytes"] for row in memberships)
                alerts = []
                for row in memberships:
                    evidence = SqliteCaseRepository._alert(connection, row["alert_record_id"])
                    alerts.append(GraphAlert(evidence.record_id, evidence.alert, evidence.payload_hash, row["received_at"],
                        bool(row["active"]), row["first_attached_at"], row["changed_at"]))
                relationships = rows("SELECT * FROM case_relationships WHERE case_id=? ORDER BY seq", (case_id,), 2000)
                relation_reviews = rows("""SELECT r.* FROM case_relationship_reviews r JOIN case_relationships s
                    ON s.relationship_id=r.relationship_id WHERE s.case_id=? ORDER BY r.seq""", (case_id,), 5000)
                stages = rows("SELECT * FROM case_stage_assertions WHERE case_id=? ORDER BY seq", (case_id,), 2000)
                stage_reviews = rows("""SELECT r.* FROM case_stage_reviews r JOIN case_stage_assertions s
                    ON s.assertion_id=r.assertion_id WHERE s.case_id=? ORDER BY r.seq""", (case_id,), 5000)
                history = rows("SELECT * FROM case_events WHERE case_id=? ORDER BY seq", (case_id,), 5000)
                reports = rows("""SELECT c.analysis_id,c.linked_at,a.completed_at FROM case_analyses c
                    JOIN analyses a ON a.analysis_id=c.analysis_id WHERE c.case_id=? ORDER BY c.seq""", (case_id,), 1000)
                for report in reports:
                    coverage = rows("SELECT alert_record_id FROM analysis_alert_coverage WHERE analysis_id=? ORDER BY alert_record_id",
                                    (report["analysis_id"],), 1000)
                    report["covered_alert_ids"] = [row["alert_record_id"] for row in coverage]
                content = {"case": asdict(case), "alerts": [asdict(alert) for alert in alerts],
                    "relationships": relationships, "relationship_reviews": relation_reviews, "stages": stages,
                    "stage_reviews": stage_reviews, "history": history, "reports": reports}
                digest = sha256(canonical_json(content).encode("utf-8")).hexdigest()
                return CaseGraphSnapshot(case, tuple(alerts), canonical_json(relationships), canonical_json(relation_reviews),
                    canonical_json(stages), canonical_json(stage_reviews), canonical_json(history), canonical_json(reports), digest, utc_now())
        except sqlite3.Error as error:
            raise GraphStorageError("Cannot snapshot case storage; initialize case storage before graph export.") from error
