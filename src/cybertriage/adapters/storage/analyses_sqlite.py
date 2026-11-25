import json
import sqlite3
from contextlib import closing
from dataclasses import asdict
from datetime import timezone
from pathlib import Path

from cybertriage.domain.triage import (
    AnalysisRecord,
    AnalysisStorageError,
)


class SqliteAnalysisWriter:
    def __init__(self, database_path: Path):
        self._database_path = database_path

        if not database_path.is_file():
            raise AnalysisStorageError(
                "The alert database must exist before initializing "
                "investigation storage."
            )

        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute("""
                        CREATE TABLE IF NOT EXISTS analyses (
                            analysis_id TEXT PRIMARY KEY,
                            alert_record_id TEXT NOT NULL,
                            completed_at TEXT NOT NULL,
                            retrieval_query TEXT NOT NULL,
                            evidence TEXT NOT NULL,
                            result_json TEXT NOT NULL,

                            FOREIGN KEY (alert_record_id)
                                REFERENCES alerts(record_id)
                                ON DELETE RESTRICT
                        )
                    """)

        except sqlite3.Error as error:
            raise AnalysisStorageError(
                "Could not initialize investigation storage."
            ) from error

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database_path,
            timeout=5.0,
        )

        try:
            connection.execute("PRAGMA foreign_keys = ON")
        except sqlite3.Error:
            connection.close()
            raise

        return connection

    def save(self, record: AnalysisRecord) -> None:
        try:
            if record.completed_at.utcoffset() is None:
                raise ValueError(
                    "The completion timestamp must include a timezone."
                )

            result_json = json.dumps(
                asdict(record.result),
                ensure_ascii=False,
                allow_nan=False,
            )

            completed_at = record.completed_at.astimezone(
                timezone.utc
            ).isoformat()

            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT INTO analyses (
                            analysis_id,
                            alert_record_id,
                            completed_at,
                            retrieval_query,
                            evidence,
                            result_json
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record.analysis_id,
                            record.alert_record_id,
                            completed_at,
                            record.retrieval_query,
                            record.evidence,
                            result_json,
                        ),
                    )

        except (
            sqlite3.Error,
            TypeError,
            ValueError,
            RecursionError,
        ) as error:
            raise AnalysisStorageError(
                "Could not save the investigation report."
            ) from error