from collections.abc import Mapping
from datetime import datetime, timezone
from dbm import error
import json

from cybertriage.domain.alert import InvalidAlertError, SecurityAlert
from cybertriage.domain.security_event import EventIdentity


def _object(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InvalidAlertError(f"{path} must be an object.")

    return value


def _text(data: Mapping[str, object], key: str, path: str) -> str:
    value = data.get(key)

    if not isinstance(value, str) or not value.strip():
        raise InvalidAlertError(f"{path} must be a nonempty string.")

    return value.strip()


def _optional_object(
    data: Mapping[str, object],
    key: str,
    path: str,
) -> Mapping[str, object]:
    value = data.get(key)

    if value is None:
        return {}

    return _object(value, path)


def _timestamp(value: str) -> datetime:
    # Convert a trailing Z into an explicit UTC offset.
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value

    try:
        timestamp = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise InvalidAlertError("timestamp must be a valid ISO timestamp.") from error

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise InvalidAlertError("timestamp must include a timezone.")

    return timestamp.astimezone(timezone.utc)


def _mitre_ids(rule: Mapping[str, object]) -> tuple[str, ...]:
    mitre = _optional_object(rule, "mitre", "rule.mitre")
    values = mitre.get("id")

    if values is None:
        return ()

    if not isinstance(values, list):
        raise InvalidAlertError("rule.mitre.id must be a list.")

    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise InvalidAlertError("MITRE IDs must be nonempty strings.")

    # Remove duplicates while preserving their original order.
    return tuple(dict.fromkeys(value.strip() for value in values))


def _event_identity(
    payload: Mapping[str, object],
) -> EventIdentity | None:
    data = _optional_object(payload, "data", "data")
    win = _optional_object(data, "win", "data.win")
    system = _optional_object(win, "system", "data.win.system")

    raw_id = system.get("eventID")
    provider = system.get("providerName")
    channel = system.get("channel")

    # A complete identity is required for exact catalogue lookup.
    # Missing metadata must not be filled with guessed values.
    if raw_id is None or provider is None or channel is None:
        return None

    if type(raw_id) is int:
        event_id = raw_id
    elif isinstance(raw_id, str):
        value = raw_id.strip()

        if not 1 <= len(value) <= 5 or not value.isascii() or not value.isdecimal():
            raise InvalidAlertError("data.win.system.eventID must be an integer.")

        event_id = int(value)
    else:
        raise InvalidAlertError("data.win.system.eventID must be an integer.")

    if not 0 <= event_id <= 65535:
        raise InvalidAlertError("Windows event ID is outside its valid range.")

    return EventIdentity(
        provider=_text(system, "providerName", "data.win.system.providerName"),
        channel=_text(system, "channel", "data.win.system.channel"),
        event_id=event_id,
    )

def _optional_text(value: object, path: str) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise InvalidAlertError(f"{path} must be a string.")

    # Preserve the log text, including its whitespace.
    return value


def _decoded_data(payload: Mapping[str, object]) -> str: # type: ignore
    data = _optional_object(payload, "data", "data")

    try:
        return json.dumps(
        dict(data),
            ensure_ascii=False,
            allow_nan=False,
            )
    except (TypeError, ValueError, RecursionError) as error:
        raise InvalidAlertError(
            "data must contain valid JSON-compatible values."
            ) from error

class WazuhAlertNormalizer:
    def normalize(
        self,
        payload: Mapping[str, object],
    ) -> SecurityAlert:
        payload = _object(payload, "alert")
        manager = _object(payload.get("manager"), "manager")
        agent = _object(payload.get("agent"), "agent")
        rule = _object(payload.get("rule"), "rule")
        

        level = rule.get("level")

        if type(level) is not int or not 0 <= level <= 16:
            raise InvalidAlertError("rule.level must be an integer from 0 to 16.")

        return SecurityAlert(
            source_alert_id=_text(payload, "id", "id"),
            source_instance=_text(manager, "name", "manager.name"),
            timestamp=_timestamp(_text(payload, "timestamp", "timestamp")),
            agent_id=_text(agent, "id", "agent.id"),
            agent_name=_text(agent, "name", "agent.name"),
            rule_id=_text(rule, "id", "rule.id"),
            rule_level=level,
            description=_text(rule, "description", "rule.description"),
            event=_event_identity(payload),
            mitre_ids=_mitre_ids(rule),
            full_log=_optional_text(payload.get("full_log"), "full_log"),
            decoded_data_json=_decoded_data(payload),
        )

   