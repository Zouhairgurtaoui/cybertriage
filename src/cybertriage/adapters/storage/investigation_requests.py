"""A separate leased queue for explicit re-investigations; automatic jobs stay intact."""

from contextlib import closing
from hashlib import sha256
from uuid import uuid4

from cybertriage.adapters.storage.case_records import append_case_event, utc_now
from cybertriage.adapters.storage.cases_sqlite import SqliteCaseRepository
from cybertriage.adapters.storage.jobs_sqlite import SqliteAnalysisQueue
from cybertriage.domain.case import CaseConflictError, CaseError
from cybertriage.domain.response_workflow import canonical


class SqliteInvestigationRequests(SqliteAnalysisQueue):
    _jobs_table = "requested_investigations"
    _results_table = "requested_investigation_results"

    def __init__(self, database_path):
        self._cases = SqliteCaseRepository(database_path)
        with self._cases._session(True) as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS requested_investigations(
                job_id TEXT PRIMARY KEY,alert_record_id TEXT NOT NULL REFERENCES alerts(record_id),
                case_id TEXT NOT NULL REFERENCES incident_cases(case_id),task TEXT NOT NULL,actor TEXT NOT NULL,
                case_version INTEGER NOT NULL,idempotency_key TEXT NOT NULL,request_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed')),
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count>=0),created_at TEXT NOT NULL,
                available_at TEXT NOT NULL,claim_token TEXT,lease_expires_at TEXT,last_error_code TEXT,finished_at TEXT,
                UNIQUE(case_id,idempotency_key),CHECK((status='running' AND claim_token IS NOT NULL AND lease_expires_at IS NOT NULL)
                    OR (status<>'running' AND claim_token IS NULL AND lease_expires_at IS NULL)))""")
            connection.execute("CREATE INDEX IF NOT EXISTS requested_investigation_pending ON requested_investigations(status,available_at)")
            connection.execute("""CREATE TRIGGER IF NOT EXISTS requested_investigation_identity
                BEFORE UPDATE ON requested_investigations WHEN NEW.job_id<>OLD.job_id OR NEW.case_id<>OLD.case_id
                OR NEW.alert_record_id<>OLD.alert_record_id OR NEW.task<>OLD.task OR NEW.actor<>OLD.actor
                OR NEW.case_version<>OLD.case_version OR NEW.idempotency_key<>OLD.idempotency_key OR NEW.request_hash<>OLD.request_hash
                BEGIN SELECT RAISE(ABORT,'Investigation request identity is immutable'); END""")
        super().__init__(database_path)

    def request(self, case_id, alert_id, task, actor, expected_version, idempotency_key):
        from cybertriage.application.services.case_management import identifier, text, version
        case_id, alert_id = identifier(case_id), identifier(alert_id)
        task, actor = text(task, "Investigation task", 1500), text(actor, "Actor", 128)
        expected_version, idempotency_key = version(expected_version), identifier(idempotency_key)
        digest = sha256(canonical([case_id, alert_id, task, actor, expected_version]).encode()).hexdigest()
        with self._cases._session(True) as connection:
            existing = connection.execute("SELECT * FROM requested_investigations WHERE case_id=? AND idempotency_key=?", (case_id, idempotency_key)).fetchone()
            if existing:
                if existing["request_hash"] != digest:
                    raise CaseConflictError("Investigation idempotency key has different request content.")
                return self._view(connection, case_id, existing["job_id"])
            case = self._cases._case(connection, case_id, expected_version, editable=True)
            self._cases._attached(connection, case_id, [alert_id])
            count = connection.execute("SELECT COUNT(*) FROM requested_investigations WHERE case_id=?", (case_id,)).fetchone()[0]
            pending = connection.execute("SELECT COUNT(*) FROM requested_investigations WHERE case_id=? AND status IN ('pending','running')", (case_id,)).fetchone()[0]
            if count >= 1000 or pending >= 20:
                raise CaseError("Investigation history or pending-request capacity reached.")
            job_id, now = uuid4().hex, utc_now()
            connection.execute("""INSERT INTO requested_investigations(job_id,alert_record_id,case_id,task,actor,case_version,
                idempotency_key,request_hash,created_at,available_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (job_id, alert_id, case_id, task, actor, case.version + 1, idempotency_key, digest, now, now))
            append_case_event(connection, case_id, "investigation_requested", actor, task,
                              {"job_id": job_id, "alert_record_id": alert_id, "scope": "Application-derived read-only query authority."})
            return self._view(connection, case_id, job_id)

    @staticmethod
    def _view(connection, case_id, job_id):
        row = connection.execute("""SELECT j.job_id,j.case_id,j.alert_record_id,j.task,j.actor,j.case_version,
            j.status,j.attempt_count,j.created_at,j.finished_at,j.last_error_code,r.analysis_id
            FROM requested_investigations j LEFT JOIN requested_investigation_results r ON r.job_id=j.job_id
            WHERE j.case_id=? AND j.job_id=?""", (case_id, job_id)).fetchone()
        if row is None:
            raise CaseError("Investigation request not found in this case.")
        return dict(row)

    def get_request(self, case_id, job_id):
        from cybertriage.application.services.case_management import identifier
        case_id, job_id = identifier(case_id), identifier(job_id)
        with self._cases._session() as connection:
            return self._view(connection, case_id, job_id)

    def list_requests(self, case_id, limit=50, before=None):
        from cybertriage.application.services.case_management import identifier, page
        case_id = identifier(case_id)
        page(limit)
        if before is not None and (type(before) is not int or not 1 <= before <= 9223372036854775807):
            raise CaseError("Request cursor must be a positive SQLite sequence.")
        with self._cases._session() as connection:
            self._cases._case(connection, case_id)
            rows = connection.execute("""SELECT rowid AS sequence,job_id FROM requested_investigations
                WHERE case_id=? AND (? IS NULL OR rowid<?) ORDER BY rowid DESC LIMIT ?""", (case_id, before, before, limit + 1)).fetchall()
            return self._cases._bounded({"case_id": case_id,
                "requests": [self._view(connection, case_id, row["job_id"]) for row in rows[:limit]],
                "next_before": rows[limit - 1]["sequence"] if len(rows) > limit else None})

    def processing_context(self, job):
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            self._require_claim(connection, job, utc_now())
            row = connection.execute("SELECT * FROM requested_investigations WHERE job_id=?", (job.job_id,)).fetchone()
            self._cases._case(connection, row["case_id"], editable=True)
            self._cases._attached(connection, row["case_id"], [job.alert_record_id])
            return dict(row)
