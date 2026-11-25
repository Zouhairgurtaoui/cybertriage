import json
import sqlite3
from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from cybertriage.domain.alert import (
    AlertConflictError,
    AlertStorageError,
    IngestionReceipt,
    InvalidAlertError,
    SecurityAlert,
)

from cybertriage.domain.security_event import EventIdentity


class SqliteAlertRepository:
    def __init__(self, database_path: Path):
        if str(database_path) == ":memory:":
            raise ValueError("This repository requires a database file.")

        self._database_path = database_path

        try:
            database_path.parent.mkdir(parents=True, exist_ok=True)

            with closing(self._connect()) as connection:
                with connection:
                    connection.execute("""
                        CREATE TABLE IF NOT EXISTS alerts (
                            record_id TEXT PRIMARY KEY,
                            source_instance TEXT NOT NULL,
                            source_alert_id TEXT NOT NULL,
                            payload_json TEXT NOT NULL,
                            payload_hash TEXT NOT NULL,
                            received_at TEXT NOT NULL,

                            UNIQUE (source_instance, source_alert_id)
                        )
                    """)
                    connection.execute("""
                        CREATE TABLE IF NOT EXISTS analysis_jobs (
                            job_id TEXT PRIMARY KEY,
                            alert_record_id TEXT NOT NULL UNIQUE,

                            status TEXT NOT NULL DEFAULT 'pending'
                                CHECK (
                                    status IN (
                                        'pending',
                                        'running',
                                        'completed',
                                        'failed'
                                    )
                                ),

                            attempt_count INTEGER NOT NULL DEFAULT 0
                                CHECK (attempt_count >= 0),

                            created_at TEXT NOT NULL,
                            available_at TEXT NOT NULL,

                            claim_token TEXT,
                            lease_expires_at TEXT,
                            last_error_code TEXT,
                            finished_at TEXT,

                            FOREIGN KEY (alert_record_id)
                                REFERENCES alerts(record_id)
                                ON DELETE RESTRICT,

                            CHECK (
                                (
                                    status = 'running'
                                    AND claim_token IS NOT NULL
                                    AND lease_expires_at IS NOT NULL
                                )
                                OR
                                (
                                    status <> 'running'
                                    AND claim_token IS NULL
                                    AND lease_expires_at IS NULL
                                )
                            )
                        )
                    """)

                    connection.execute("""
                        CREATE INDEX IF NOT EXISTS
                            idx_analysis_jobs_ready
                        ON analysis_jobs (
                            status,
                            available_at,
                            created_at
                        )
                    """)
        except (OSError, sqlite3.Error) as error:
            raise AlertStorageError(
                "Could not initialize alert storage."
            ) from error

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database_path,
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
    def _enqueue_analysis(
        connection: sqlite3.Connection,
        record_id: str,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()

        connection.execute(
            """
            INSERT INTO analysis_jobs (
                job_id,
                alert_record_id,
                status,
                attempt_count,
                created_at,
                available_at
            )
            VALUES (?, ?, 'pending', 0, ?, ?)
            ON CONFLICT (alert_record_id) DO NOTHING
            """,
            (
                uuid4().hex,
                record_id,
                now,
                now,
            ),
        )

    def save_and_schedule(
        self,
        alert: SecurityAlert,
    ) -> IngestionReceipt:
        payload_json = self._serialize(alert)
        payload_hash = sha256(payload_json.encode("utf-8")).hexdigest()

        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute("BEGIN IMMEDIATE")

                    existing = connection.execute(
                        """
                        SELECT record_id, payload_hash
                        FROM alerts
                        WHERE source_instance = ?
                          AND source_alert_id = ?
                        """,
                        (
                            alert.source_instance,
                            alert.source_alert_id,
                        ),
                    ).fetchone()

                    if existing is not None:
                        if existing["payload_hash"] != payload_hash:
                            raise AlertConflictError(
                                "This source alert identity already exists "
                                "with different normalized content."
                            )

                        self._enqueue_analysis(
                            connection,
                            existing["record_id"],
                        )

                        return IngestionReceipt(
                            record_id=existing["record_id"],
                            created=False,
                        )

                    record_id = uuid4().hex
                    received_at = datetime.now(timezone.utc).isoformat()

                    connection.execute(
                        """
                        INSERT INTO alerts (
                            record_id,
                            source_instance,
                            source_alert_id,
                            payload_json,
                            payload_hash,
                            received_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            record_id,
                            alert.source_instance,
                            alert.source_alert_id,
                            payload_json,
                            payload_hash,
                            received_at,
                        ),
                    )
                    self._enqueue_analysis(connection, record_id)

                    return IngestionReceipt(
                        record_id=record_id,
                        created=True,
                    )

        except sqlite3.Error as error:
            raise AlertStorageError(
                "Could not save the alert and schedule its analysis."
            ) from error
        
    def get(self, record_id: str) -> SecurityAlert | None:
        if not isinstance(record_id, str) or not record_id.strip():
            raise ValueError("record_id must be a non-empty string.")

        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    """
                    SELECT payload_json, payload_hash
                    FROM alerts
                    WHERE record_id = ?
                    """,
                    (record_id,),
                ).fetchone()

        except sqlite3.Error as error:
            raise AlertStorageError(
                "Could not read the stored alert."
            ) from error

        if row is None:
            return None

        payload_json = row["payload_json"]

        actual_hash = sha256(
            payload_json.encode("utf-8")
        ).hexdigest()

        if actual_hash != row["payload_hash"]:
            raise AlertStorageError(
                "The stored alert failed its integrity check."
            )

        try:
            return self._deserialize(payload_json)

        except (TypeError, ValueError, KeyError, RecursionError) as error:
            raise AlertStorageError(
                "The stored alert could not be reconstructed."
            ) from error

    @classmethod
    def _deserialize(cls, payload_json: str) -> SecurityAlert:
        payload = json.loads(payload_json)

        if not isinstance(payload, dict):
            raise ValueError("Stored alert must be a JSON object.")

        payload["timestamp"] = datetime.fromisoformat(
            payload["timestamp"]
        )

        mitre_ids = payload["mitre_ids"]

        if not isinstance(mitre_ids, list) or not all(
            isinstance(value, str) for value in mitre_ids
        ):
            raise ValueError("Stored MITRE IDs must be a list of strings.")

        payload["mitre_ids"] = tuple(mitre_ids)

        event_data = payload["event"]

        if event_data is not None:
            if (
                not isinstance(event_data, dict)
                or not isinstance(event_data.get("provider"), str)
                or not isinstance(event_data.get("channel"), str)
            ):
                raise ValueError("Stored event identity is invalid.")

            payload["event"] = EventIdentity(**event_data)

        alert = SecurityAlert(**payload)

        # Reuse the existing serialization checks, including timezone
        # and decoded-data validation.
        cls._serialize(alert)

        return alert

    @staticmethod
    def _serialize(alert: SecurityAlert) -> str:
        if (
            alert.timestamp.tzinfo is None
            or alert.timestamp.utcoffset() is None
        ):
            raise InvalidAlertError(
                "The alert timestamp must include a timezone."
            )

        payload = asdict(alert)
        payload["timestamp"] = (
            alert.timestamp.astimezone(timezone.utc).isoformat()
        )

        try:
            decoded_data = json.loads(alert.decoded_data_json)

            if not isinstance(decoded_data, dict):
                raise InvalidAlertError(
                    "Decoded alert data must represent a JSON object."
                )

            payload["decoded_data_json"] = json.dumps(
                decoded_data,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )

            return json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )

        except (TypeError, ValueError, RecursionError) as error:
            raise InvalidAlertError(
                "The normalized alert contains invalid data."
            ) from error