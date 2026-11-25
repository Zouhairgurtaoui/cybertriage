import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cybertriage.domain.jobs import (
    ClaimedAnalysisJob,
    JobStorageError,
)


class SqliteAnalysisQueue:
    def __init__(self, database_path: Path):
        if not database_path.is_file():
            raise JobStorageError(
                "The alert database must exist before opening the queue."
            )

        self._database_path = database_path.resolve()

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

    def claim_next(
        self,
        *,
        lease_seconds: int = 600,
        max_attempts: int = 3,
    ) -> ClaimedAnalysisJob | None:
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 86400:
            raise ValueError(
                "lease_seconds must be an integer from 1 to 86400."
            )

        if type(max_attempts) is not int or max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer.")

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
                        """,
                        (
                            now_text,
                            max_attempts,
                            now_text,
                            now_text,
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
                        ORDER BY created_at, job_id
                        LIMIT 1
                        """,
                        (
                            max_attempts,
                            now_text,
                            now_text,
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