"""Rebuildable graph delivery cursors; case versions act as durable change markers."""

from datetime import datetime, timedelta, timezone

from cybertriage.adapters.storage.cases_sqlite import SqliteCaseRepository
from cybertriage.application.services.case_graph import namespace_name


class SqliteGraphSyncState(SqliteCaseRepository):
    def __init__(self, database_path, namespace):
        super().__init__(database_path)
        self._namespace = namespace_name(namespace)
        with self._session(True) as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS graph_delivery_state(
                namespace TEXT NOT NULL,case_id TEXT NOT NULL REFERENCES incident_cases(case_id),
                delivered_version INTEGER NOT NULL DEFAULT 0,next_attempt_at TEXT NOT NULL,
                last_error_code TEXT,updated_at TEXT NOT NULL,PRIMARY KEY(namespace,case_id))""")

    def next_case(self):
        with self._session() as connection:
            row = connection.execute("""SELECT c.case_id FROM incident_cases c LEFT JOIN graph_delivery_state s
                ON s.case_id=c.case_id AND s.namespace=? WHERE (s.case_id IS NULL OR
                (s.delivered_version<c.version AND s.next_attempt_at<=?)) ORDER BY c.updated_at,c.case_id LIMIT 1""",
                (self._namespace, datetime.now(timezone.utc).isoformat())).fetchone()
            return row[0] if row else None

    def record(self, case_id, delivered_version, error_code=None):
        now = datetime.now(timezone.utc)
        next_time = now + timedelta(seconds=30 if error_code else 0)
        with self._session(True) as connection:
            connection.execute("""INSERT INTO graph_delivery_state(namespace,case_id,delivered_version,next_attempt_at,last_error_code,updated_at)
                VALUES(?,?,?,?,?,?) ON CONFLICT(namespace,case_id) DO UPDATE SET
                delivered_version=MAX(graph_delivery_state.delivered_version,excluded.delivered_version),
                next_attempt_at=excluded.next_attempt_at,last_error_code=excluded.last_error_code,updated_at=excluded.updated_at""",
                (self._namespace, case_id, delivered_version, next_time.isoformat(), error_code, now.isoformat()))
