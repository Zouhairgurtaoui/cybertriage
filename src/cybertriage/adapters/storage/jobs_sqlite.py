import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cybertriage.domain.jobs import (
    ClaimedAnalysisJob,
    JobLeaseLostError,
    JobStorageError,
)
from cybertriage.adapters.storage.analysis_records import insert_analysis
from cybertriage.domain.triage import AnalysisRecord


class SqliteAnalysisQueue:
    def __init__(self, database_path: Path):
        if not database_path.is_file():
            raise JobStorageError(
                "The alert database must exist before opening the queue."
            )

        self._database_path = database_path.resolve()
        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute("""
                        CREATE TABLE IF NOT EXISTS analysis_job_results (
                            job_id TEXT PRIMARY KEY,
                            analysis_id TEXT NOT NULL UNIQUE,

                            FOREIGN KEY (job_id)
                                REFERENCES analysis_jobs(job_id)
                                ON DELETE RESTRICT,

                            FOREIGN KEY (analysis_id)
                                REFERENCES analyses(analysis_id)
                                ON DELETE RESTRICT
                        )
                    """)

        except sqlite3.Error as error:
            raise JobStorageError(
                "Could not initialize job-result storage."
            ) from error

    def _connect(self) -> sqlite3.Connection:
        # mode=rw prevents accidentally creating an empty database.
        connection = sqlite3.connect(
            f"{self._database_path.as_uri()}?mode=rw",
            uri=True,
            timeout=5.0,
        )
        connection.row_factory = sqlite3.Row

        try:
            connection.execute("PRAGMA foreign_keys = ON")
        except sqlite3.Error:
            connection.close()
            raise

        return connection

    @staticmethod
    def _require_claim(
        connection: sqlite3.Connection,
        job: ClaimedAnalysisJob,
        now_text: str,
    ) -> sqlite3.Row:
        # Caller must already hold a BEGIN IMMEDIATE transaction.
        row = connection.execute(
            """
            SELECT attempt_count
            FROM analysis_jobs
            WHERE job_id = ?
              AND alert_record_id = ?
              AND status = 'running'
              AND claim_token = ?
              AND lease_expires_at > ?
            """,
            (
                job.job_id,
                job.alert_record_id,
                job.claim_token,
                now_text,
            ),
        ).fetchone()

        if row is None:
            raise JobLeaseLostError(
                "The job claim has expired or belongs to another worker."
            )

        return row

    def complete(
        self,
        job: ClaimedAnalysisJob,
        record: AnalysisRecord,
    ) -> None:
        if record.alert_record_id != job.alert_record_id:
            raise ValueError(
                "The investigation does not belong to this job's alert."
            )

        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")

                    now_text = datetime.now(timezone.utc).isoformat()
                    self._require_claim(connection, job, now_text)

                    insert_analysis(connection, record)

                    connection.execute(
                        """
                        INSERT INTO analysis_job_results (
                            job_id,
                            analysis_id
                        )
                        VALUES (?, ?)
                        """,
                        (job.job_id, record.analysis_id),
                    )

                    connection.execute(
                        """
                        UPDATE analysis_jobs
                        SET status = 'completed',
                            claim_token = NULL,
                            lease_expires_at = NULL,
                            last_error_code = NULL,
                            finished_at = ?
                        WHERE job_id = ?
                        """,
                        (now_text, job.job_id),
                    )

        except (
            sqlite3.Error,
            TypeError,
            ValueError,
            RecursionError,
        ) as error:
            raise JobStorageError(
                "Could not save the report and complete its job."
            ) from error

    def fail(
        self,
        job: ClaimedAnalysisJob,
        *,
        error_code: str,
        retryable: bool = True,
        max_attempts: int = 3,
        retry_delay_seconds: int = 30,
    ) -> None:
        if (
            not isinstance(error_code, str)
            or not 1 <= len(error_code) <= 64
            or not error_code.isascii()
            or not error_code.replace("_", "").isalnum()
        ):
            raise ValueError(
                "error_code must be a short ASCII identifier."
            )

        if type(retryable) is not bool:
            raise ValueError("retryable must be a boolean.")

        if type(max_attempts) is not int or max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer.")

        if (
            type(retry_delay_seconds) is not int
            or not 0 <= retry_delay_seconds <= 86400
        ):
            raise ValueError(
                "retry_delay_seconds must be an integer from 0 to 86400."
            )

        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")

                    now = datetime.now(timezone.utc)
                    now_text = now.isoformat()

                    row = self._require_claim(
                        connection,
                        job,
                        now_text,
                    )

                    can_retry = (
                        retryable
                        and row["attempt_count"] < max_attempts
                    )

                    available_at = (
                        now + timedelta(seconds=retry_delay_seconds)
                        if can_retry
                        else now
                    )

                    connection.execute(
                        """
                        UPDATE analysis_jobs
                        SET status = ?,
                            available_at = ?,
                            last_error_code = ?,
                            claim_token = NULL,
                            lease_expires_at = NULL,
                            finished_at = ?
                        WHERE job_id = ?
                        """,
                        (
                            "pending" if can_retry else "failed",
                            available_at.isoformat(),
                            error_code,
                            None if can_retry else now_text,
                            job.job_id,
                        ),
                    )

        except sqlite3.Error as error:
            raise JobStorageError(
                "Could not record the job failure."
            ) from error

    def claim_next(
        self,
        *,
        lease_seconds: int = 600,
        max_attempts: int = 3,
        job_id: str | None = None,
    ) -> ClaimedAnalysisJob | None:
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 86400:
            raise ValueError(
                "lease_seconds must be an integer from 1 to 86400."
            )

        if type(max_attempts) is not int or max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer.")

        if job_id is not None and (
            not isinstance(job_id, str) or not job_id.strip()
        ):
            raise ValueError("job_id must be a non-empty string.")

        try:
            with closing(self._connect()) as connection:
                with connection:
                    # Reserve SQLite's write transaction before selecting.
                    connection.execute("BEGIN IMMEDIATE")

                    now = datetime.now(timezone.utc)
                    now_text = now.isoformat()

                    # Finish exhausted jobs, including workers that crashed
                    # during their final permitted attempt.
                    connection.execute(
                        """
                        UPDATE analysis_jobs
                        SET status = 'failed',
                            last_error_code = CASE
                                WHEN status = 'running'
                                    THEN 'lease_expired'
                                ELSE COALESCE(
                                    last_error_code,
                                    'attempt_limit_reached'
                                )
                            END,
                            claim_token = NULL,
                            lease_expires_at = NULL,
                            finished_at = ?
                        WHERE attempt_count >= ?
                          AND (
                              (
                                  status = 'pending'
                                  AND available_at <= ?
                              )
                              OR
                              (
                                  status = 'running'
                                  AND lease_expires_at <= ?
                              )
                          )
                          AND (? IS NULL OR job_id = ?)
                        """,
                        (
                            now_text,
                            max_attempts,
                            now_text,
                            now_text,
                            job_id,
                            job_id,
                        ),
                    )

                    row = connection.execute(
                        """
                        SELECT job_id, alert_record_id, attempt_count
                        FROM analysis_jobs
                        WHERE attempt_count < ?
                          AND (
                              (
                                  status = 'pending'
                                  AND available_at <= ?
                              )
                              OR
                              (
                                  status = 'running'
                                  AND lease_expires_at <= ?
                              )
                          )
                          AND (? IS NULL OR job_id = ?)
                        ORDER BY created_at, job_id
                        LIMIT 1
                        """,
                        (
                            max_attempts,
                            now_text,
                            now_text,
                            job_id,
                            job_id,
                        ),
                    ).fetchone()

                    if row is None:
                        return None

                    claim_token = uuid4().hex
                    lease_expires_at = now + timedelta(
                        seconds=lease_seconds
                    )

                    connection.execute(
                        """
                        UPDATE analysis_jobs
                        SET status = 'running',
                            attempt_count = attempt_count + 1,
                            claim_token = ?,
                            lease_expires_at = ?,
                            finished_at = NULL,
                            last_error_code = CASE
                                WHEN status = 'running'
                                    THEN 'lease_expired'
                                ELSE last_error_code
                            END
                        WHERE job_id = ?
                        """,
                        (
                            claim_token,
                            lease_expires_at.isoformat(),
                            row["job_id"],
                        ),
                    )

                    return ClaimedAnalysisJob(
                        job_id=row["job_id"],
                        alert_record_id=row["alert_record_id"],
                        claim_token=claim_token,
                        attempt_count=row["attempt_count"] + 1,
                        lease_expires_at=lease_expires_at,
                    )

        except sqlite3.Error as error:
            raise JobStorageError(
                "Could not claim an analysis job."
            ) from error

    def renew(
        self,
        job: ClaimedAnalysisJob,
        *,
        lease_seconds: int = 600,
    ) -> None:
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 86400:
            raise ValueError(
                "lease_seconds must be an integer from 1 to 86400."
            )

        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")

                    now = datetime.now(timezone.utc)
                    self._require_claim(
                        connection,
                        job,
                        now.isoformat(),
                    )

                    connection.execute(
                        """
                        UPDATE analysis_jobs
                        SET lease_expires_at = ?
                        WHERE job_id = ?
                        """,
                        (
                            (
                                now + timedelta(seconds=lease_seconds)
                            ).isoformat(),
                            job.job_id,
                        ),
                    )

        except sqlite3.Error as error:
            raise JobStorageError(
                "Could not renew the job lease."
            ) from error
