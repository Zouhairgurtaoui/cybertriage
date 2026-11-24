import json
import os
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import re
from urllib.parse import urlsplit

from cybertriage.domain.security_event import SecurityEventDefinition


class JsonEventCatalogStore:
    def __init__(self, path: Path):
        self._path = path


    def load(self) -> list[SecurityEventDefinition]:
        with self._path.open("rb") as file:
            content = file.read(2 * 1024 * 1024 + 1)

        if len(content) > 2 * 1024 * 1024:
            raise ValueError("Catalogue snapshot exceeds the size limit.")

        payload = json.loads(content.decode("utf-8"))

        if not isinstance(payload, dict):
            raise ValueError("Catalogue snapshot must be a JSON object.")

        if (
            type(payload.get("schema_version")) is not int
            or payload["schema_version"] != 1
        ):
            raise ValueError("Unsupported catalogue schema version.")

        entries = payload.get("definitions")

        if not isinstance(entries, list) or not entries:
            raise ValueError("Catalogue must contain event definitions.")

        expected_fields = {
            "provider",
            "channel",
            "event_id",
            "description",
            "source_url",
            "source_revision",
        }

        definitions = []
        seen = set()

        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != expected_fields:
                raise ValueError("Invalid event definition structure.")

            for field in expected_fields - {"event_id"}:
                value = entry[field]
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"Invalid definition field: {field}")

            if (
                type(entry["event_id"]) is not int
                or not 0 <= entry["event_id"] <= 65535
            ):
                raise ValueError("Invalid event ID.")

            source = urlsplit(entry["source_url"])

            if (
                source.scheme != "https"
                or source.netloc != "learn.microsoft.com"
            ):
                raise ValueError("Unexpected event definition source.")

            if not re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                entry["source_revision"],
            ):
                raise ValueError("Invalid source revision.")

            key = (
                entry["provider"],
                entry["channel"],
                entry["event_id"],
            )

            if key in seen:
                raise ValueError(f"Duplicate event definition: {key}")

            seen.add(key)
            definitions.append(SecurityEventDefinition(**entry))

        return definitions

    def save(
        self,
        definitions: list[SecurityEventDefinition],
    ) -> None:
        if not definitions:
            raise ValueError("Refusing to save an empty event catalogue.")

        keys = [
            (item.provider, item.channel, item.event_id)
            for item in definitions
        ]

        if len(keys) != len(set(keys)):
            raise ValueError("Duplicate definitions in catalogue snapshot.")

        payload = {
            "schema_version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "definitions": [asdict(item) for item in definitions],
        }

        self._path.parent.mkdir(parents=True, exist_ok=True)

        temporary_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self._path.parent,
                prefix=f".{self._path.name}.",
                suffix=".tmp",
                delete=False,
            ) as file:
                temporary_path = Path(file.name)

                json.dump(
                    payload,
                    file,
                    ensure_ascii=False,
                    indent=2,
                    allow_nan=False,
                )
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())

            os.replace(temporary_path, self._path)

        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)