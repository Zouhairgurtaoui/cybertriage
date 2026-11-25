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
        return connection

    def save_if_new(
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

                    return IngestionReceipt(
                        record_id=record_id,
                        created=True,
                    )

        except sqlite3.Error as error:
            raise AlertStorageError(
                "Could not save the alert."
            ) from error

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