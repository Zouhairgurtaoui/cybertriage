import json
import re
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit
from typing import TypedDict

from cybertriage.application.policies.alert_triage import decoded_field
from cybertriage.domain.alert import SecurityAlert
from cybertriage.domain.investigation import AuthenticationSearchResult


class CodeDescription(TypedDict):
    registry_revision: str
    fields: dict[str, dict[str, str | None]]
    definitions: dict[str, dict[str, str]]
    limitations: str


class MicrosoftAuthenticationGrounder:
    """Resolve only documented registry entries; preserve unknown raw values."""

    def __init__(self, registry_path: Path):
        with registry_path.open("rb") as file:
            raw = file.read(65537)
        if len(raw) > 65536:
            raise ValueError("Authentication definition registry exceeds its size budget.")

        def unique(pairs):
            values = {}
            for key, value in pairs:
                if key in values:
                    raise ValueError("Duplicate authentication registry key.")
                values[key] = value
            return values

        payload = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique)
        if (not isinstance(payload, dict) or set(payload) != {"version", "definitions"}
                or type(payload["version"]) is not int or payload["version"] != 1
                or not isinstance(payload["definitions"], list) or len(payload["definitions"]) > 512):
            raise ValueError("Invalid authentication definition registry.")
        self._definitions: dict[str, dict[str, str]] = {}
        self.revision = sha256(raw).hexdigest()
        for entry in payload["definitions"]:
            if not isinstance(entry, dict) or set(entry) != {"namespace", "code", "symbol", "meaning", "source_url"}:
                raise ValueError("Invalid authentication definition entry.")
            if any(not isinstance(value, str) or not value or not value.isprintable()
                   or value != value.strip() or len(value) > 1000 for value in entry.values()):
                raise ValueError("Invalid authentication definition text.")
            namespace, code = entry["namespace"], entry["code"].lower()
            if (namespace == "ntstatus" and not re.fullmatch(r"0x[0-9a-f]{8}", code)
                    or namespace == "logon_type" and not re.fullmatch(r"[0-9]{1,3}", code)
                    or namespace not in ("ntstatus", "logon_type")):
                raise ValueError("Invalid authentication definition code.")
            url = urlsplit(entry["source_url"])
            if url.scheme != "https" or url.netloc != "learn.microsoft.com":
                raise ValueError("Authentication definitions require a Microsoft Learn source.")
            key = f"D:{namespace}:{code}"
            if key in self._definitions:
                raise ValueError("Duplicate authentication definition code.")
            self._definitions[key] = {"citation_id": key, **entry}

    def describe(self, status: str | None, substatus: str | None, logon_type: str | None) -> CodeDescription:
        definitions: dict[str, dict[str, str]] = {}
        fields: dict[str, dict[str, str | None]] = {}
        for name, namespace, value in (("status_code", "ntstatus", status),
                                        ("substatus_code", "ntstatus", substatus),
                                        ("logon_type", "logon_type", logon_type)):
            key = f"D:{namespace}:{value.lower()}" if isinstance(value, str) else None
            definition = self._definitions.get(key) if key else None
            fields[name] = {"raw_value": value, "definition_id": key if definition else None}
            if definition is not None and key is not None:
                definitions[key] = definition
        return {"registry_revision": self.revision, "fields": fields, "definitions": definitions,
                "limitations": "Unknown codes and %% resource tokens remain unresolved. Definitions describe the event time, not current account state or malicious intent."}

    def ground_alert(self, alert: SecurityAlert) -> dict[str, object]:
        if (alert.event is None or alert.event.provider != "Microsoft-Windows-Security-Auditing"
                or alert.event.channel != "Security" or alert.event.event_id not in (4624, 4625)):
            return {"definitions": {}, "limitations": "No authentication-code interpretation applies to this event identity."}
        data = json.loads(alert.decoded_data_json)
        return dict(self.describe(decoded_field(data, "win.eventdata.status"),
                                  decoded_field(data, "win.eventdata.subStatus"),
                                  decoded_field(data, "win.eventdata.logonType")))

    def ground(self, result: AuthenticationSearchResult) -> dict[str, object]:
        definitions = {}
        event_fields = []
        for event in result.events:
            description = self.describe(event.status_code, event.substatus_code, event.logon_type)
            definitions.update(description["definitions"])
            event_fields.append({
                "source_instance": event.source_instance, "source_alert_id": event.source_alert_id,
                "fields": description["fields"],
            })
        return {
            "registry_revision": self.revision,
            "definitions": definitions,
            "search_summary": {
                "start_inclusive": result.request.start.isoformat(),
                "end_exclusive": result.request.end.isoformat(),
                "duration_seconds": (result.request.end - result.request.start).total_seconds(),
                "event_ids_searched": [4624, 4625],
                "provider": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "agent_filter": None,
                "account_name": result.request.account_name,
                "account_domain": result.request.account_domain,
                "returned_event_count": len(result.events),
                "successful_logon_count": sum(event.event.event_id == 4624 for event in result.events),
                "failed_logon_count": sum(event.event.event_id == 4625 for event in result.events),
                "has_more": result.has_more,
                "coverage": result.coverage,
                "interpretation": "Counts describe only returned events under these filters. has_more=false does not describe other times, identities, event types, or uncollected logs. Account lockouts were not searched.",
            },
            "event_definitions": event_fields,
            "definition_limitations": "Unknown codes and %% resource tokens remain unresolved. Code definitions describe event-time conditions, not present account state or intent.",
        }
