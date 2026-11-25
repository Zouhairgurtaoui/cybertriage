from datetime import datetime, timezone
from ipaddress import ip_address

from cybertriage.domain.investigation import (
    AuthenticationEvent,
    AuthenticationSearchRequest,
    AuthenticationSearchResult,
    InvestigationSearchError,
)
from cybertriage.domain.security_event import EventIdentity


def _object(value: object, path: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object.")

    return value


def _text(
    value: object,
    path: str,
    *,
    limit: int = 256,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > limit
        or not value.isprintable()
    ):
        raise ValueError(f"{path} contains invalid text.")

    return value


def _optional_text(value: object, path: str) -> str | None:
    if value is None or value in ("", "-"):
        return None

    if type(value) is int:
        value = str(value)

    return _text(value, path, limit=128)


def _timestamp(value: object) -> datetime:
    text = _text(value, "timestamp", limit=64)

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    timestamp = datetime.fromisoformat(text)

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("timestamp must include a timezone.")

    return timestamp.astimezone(timezone.utc)


def _parse_hit(
    value: object,
    request: AuthenticationSearchRequest,
) -> AuthenticationEvent:
    hit = _object(value, "hit")
    index = _text(hit.get("_index"), "hit._index", limit=512)

    if not index.startswith("wazuh-alerts-"):
        raise ValueError("Unexpected source index.")

    source = _object(hit.get("_source"), "hit._source")
    manager = _object(source.get("manager"), "manager")
    agent = _object(source.get("agent"), "agent")
    data = _object(source.get("data"), "data")
    win = _object(data.get("win"), "data.win")
    system = _object(win.get("system"), "data.win.system")
    fields = _object(win.get("eventdata"), "data.win.eventdata")

    raw_event_id = system.get("eventID")

    if type(raw_event_id) is int:
        raw_event_id = str(raw_event_id)

    event_id_text = _text(raw_event_id, "eventID", limit=4)

    if event_id_text not in ("4624", "4625"):
        raise ValueError("Unexpected authentication event ID.")

    event = EventIdentity(
        provider=_text(system.get("providerName"), "providerName"),
        channel=_text(system.get("channel"), "channel"),
        event_id=int(event_id_text),
    )

    if (
        event.provider != "Microsoft-Windows-Security-Auditing"
        or event.channel != "Security"
    ):
        raise ValueError("Unexpected event provider or channel.")

    account_name = _text(
        fields.get("targetUserName"),
        "targetUserName",
    )
    account_domain = _text(
        fields.get("targetDomainName"),
        "targetDomainName",
    )

    if (
        account_name != request.account_name
        or account_domain != request.account_domain
    ):
        raise ValueError("Returned account does not match the request.")

    timestamp = _timestamp(source.get("timestamp"))

    if not request.start <= timestamp < request.end:
        raise ValueError("Returned event is outside the search window.")

    source_ip = _optional_text(fields.get("ipAddress"), "ipAddress")

    if source_ip is not None:
        source_ip = str(ip_address(source_ip))

    record_id = _optional_text(
        system.get("eventRecordID"),
        "eventRecordID",
    )

    if record_id is not None and (
        not record_id.isascii()
        or not record_id.isdecimal()
        or len(record_id) > 20
    ):
        raise ValueError("Invalid Windows event record ID.")

    logon_type = _optional_text(
        fields.get("logonType"),
        "logonType",
    )

    if logon_type is not None and (
        not logon_type.isascii()
        or not logon_type.isdecimal()
        or len(logon_type) > 3
    ):
        raise ValueError("Invalid logon type.")

    # A successful logon's target session ID belongs to the logged-on
    # account. Do not substitute the initiating subject's session ID.
    logon_id = (
        _optional_text(fields.get("targetLogonId"), "targetLogonId")
        if event.event_id == 4624
        else None
    )

    return AuthenticationEvent(
        source_alert_id=_text(source.get("id"), "id"),
        source_instance=_text(manager.get("name"), "manager.name"),
        timestamp=timestamp,
        agent_id=_text(agent.get("id"), "agent.id"),
        agent_name=_text(agent.get("name"), "agent.name"),
        event=event,
        account_name=account_name,
        account_domain=None if account_domain == "-" else account_domain,
        windows_record_id=record_id,
        source_ip=source_ip,
        logon_type=logon_type,
        logon_id=logon_id,
        status_code=_optional_text(
            fields.get("status"),
            "status",
        ),
        substatus_code=_optional_text(
            fields.get("subStatus"),
            "subStatus",
        ),
        failure_reason=_optional_text(
            fields.get("failureReason"),
            "failureReason",
        ),
    )


def parse_authentication_response(
    payload: dict[str, object],
    request: AuthenticationSearchRequest,
) -> AuthenticationSearchResult:
    """Map hits from a complete response validated by the HTTP client."""
    try:
        hits = _object(payload.get("hits"), "hits")
        documents = hits.get("hits")

        if (
            not isinstance(documents, list)
            or len(documents) > request.limit + 1
        ):
            raise ValueError("Invalid result collection.")

        events_by_identity: dict[
            tuple[str, str], AuthenticationEvent
        ] = {}

        for document in documents:
            event = _parse_hit(document, request)
            identity = (
                event.source_instance,
                event.source_alert_id,
            )

            existing = events_by_identity.get(identity)

            if existing is not None and existing != event:
                raise ValueError("Conflicting source alert identity.")

            events_by_identity[identity] = event

        events = sorted(
            events_by_identity.values(),
            key=lambda event: (
                event.timestamp,
                event.source_instance,
                event.source_alert_id,
            ),
        )

        return AuthenticationSearchResult(
            request=request,
            events=tuple(events[:request.limit]),
            searched_at=datetime.now(timezone.utc),
            has_more=len(documents) > request.limit,
        )

    except (TypeError, ValueError, KeyError, OverflowError):
        raise InvestigationSearchError(
            "Indexer returned malformed, conflicting, "
            "or out-of-scope authentication events."
        ) from None
