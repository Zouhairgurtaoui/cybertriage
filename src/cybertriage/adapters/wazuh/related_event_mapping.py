import json
from datetime import datetime, timezone
from hashlib import sha256

from cybertriage.adapters.wazuh.related_event_fields import (
    ACCOUNT_JOINED, ACCOUNT_PAIRS, DETAIL_FIELDS, LOGON_ID_FIELDS, PROCESS_GUID_FIELDS,
    SOURCE_IP_FIELDS, canonical_ip, field_at,
)
from cybertriage.application.policies.event_families import family_matches
from cybertriage.domain.investigation import InvestigationSearchError
from cybertriage.domain.related_events import (
    RelatedEvent, RelatedEventSearchRequest, RelatedEventSearchResult, ReportedEventField, bounded_identity,
)
from cybertriage.domain.security_event import EventIdentity


def _text(value: object, path: str, maximum: int = 256) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{path} is not text.")
    bounded_identity(value, path, maximum)
    return value


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("Expected an object.")
    return value


def _matches_filters(source: dict[str, object], request: RelatedEventSearchRequest) -> bool:
    if request.account_name is not None and request.account_domain is not None:
        paired = any(field_at(source, name) == request.account_name and field_at(source, domain) == request.account_domain
                     for name, domain in ACCOUNT_PAIRS)
        joined = any(field_at(source, path) == f"{request.account_domain}\\{request.account_name}" for path in ACCOUNT_JOINED)
        if not paired and not joined:
            return False
    if request.source_ip is not None:
        expected = canonical_ip(request.source_ip)
        matches = False
        for path in SOURCE_IP_FIELDS:
            raw = field_at(source, path)
            if isinstance(raw, str) and raw not in {"", "-"}:
                try:
                    matches = matches or canonical_ip(raw) == expected
                except ValueError:
                    continue
        if not matches:
            return False
    for value, paths in ((request.process_guid, PROCESS_GUID_FIELDS), (request.logon_id, LOGON_ID_FIELDS)):
        if value is not None and not any(field_at(source, path) == value for path in paths):
            return False
    return True


def _project(source: dict[str, object]) -> tuple[tuple[ReportedEventField, ...], tuple[str, ...]]:
    fields, omitted = [], []
    remaining = 3000
    for path in DETAIL_FIELDS:
        raw = field_at(source, path)
        if raw is None:
            continue
        if not isinstance(raw, (str, int, bool)):
            raise ValueError("Selected event detail must be scalar text or an integer.")
        value = str(raw)
        raw_bytes = value.encode("utf-8")
        maximum = 1024 if path.endswith("CommandLine") or path.endswith("commandLine") else 512
        if remaining <= 0:
            omitted.append(path)
            continue
        clipped = raw_bytes[:min(remaining, maximum)].decode("utf-8", errors="ignore")
        if raw_bytes and not clipped:
            omitted.append(path)
            continue
        fields.append(ReportedEventField(path, clipped, len(clipped.encode("utf-8")) < len(raw_bytes)))
        remaining -= len(clipped.encode("utf-8"))
    return tuple(fields), tuple(omitted)


def _parse_hit(value: object, request: RelatedEventSearchRequest) -> RelatedEvent:
    hit = _object(value)
    index = _text(hit.get("_index"), "_index", 512)
    if not index.startswith("wazuh-alerts-"):
        raise ValueError("Unexpected source index.")
    source = _object(hit.get("_source"))
    for path in ("data", "data.win", "data.win.eventdata"):
        value_at_path = field_at(source, path)
        if value_at_path is not None:
            _object(value_at_path)
    manager = _text(field_at(source, "manager.name"), "manager.name")
    agent_id = _text(field_at(source, "agent.id"), "agent.id", 64)
    if manager != request.source_instance or agent_id != request.agent_id:
        raise ValueError("Returned host is outside the query.")
    timestamp = datetime.fromisoformat(_text(source.get("timestamp"), "timestamp", 64))
    if timestamp.utcoffset() is None:
        raise ValueError("Source timestamp has no timezone.")
    timestamp = timestamp.astimezone(timezone.utc)
    if not request.start <= timestamp < request.end:
        raise ValueError("Event timestamp is outside the search window.")
    event = None
    system = field_at(source, "data.win.system")
    if system is not None:
        system = _object(system)
        event_id = system.get("eventID")
        if isinstance(event_id, str) and event_id.isascii() and event_id.isdecimal():
            event_id = int(event_id)
        if type(event_id) is not int:
            raise ValueError("Invalid event ID.")
        event = EventIdentity(_text(system.get("providerName"), "providerName"),
                              _text(system.get("channel"), "channel"), event_id)
    if not family_matches(request.family, event) or not _matches_filters(source, request):
        raise ValueError("Event does not satisfy the requested filters.")
    level = field_at(source, "rule.level")
    if type(level) is not int or not 0 <= level <= 16:
        raise ValueError("Invalid rule level.")
    fields, omitted = _project(source)
    digest = sha256(json.dumps(source, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()
    return RelatedEvent(manager, _text(source.get("id"), "id"), index, _text(hit.get("_id"), "_id", 512),
                         timestamp, agent_id, _text(field_at(source, "agent.name"), "agent.name"),
                         _text(field_at(source, "rule.id"), "rule.id"), level, event, fields, omitted, digest)


def parse_related_event_response(payload: dict[str, object], request: RelatedEventSearchRequest) -> RelatedEventSearchResult:
    """The HTTP client validates search completion; every selected hit is rechecked here."""
    try:
        hits = _object(payload.get("hits")).get("hits")
        if not isinstance(hits, list) or len(hits) > request.limit + 1:
            raise ValueError("Invalid result count.")
        unique: dict[tuple[str, str], RelatedEvent] = {}
        for hit in hits:
            event = _parse_hit(hit, request)
            key = event.source_instance, event.source_alert_id
            previous = unique.get(key)
            if previous is not None and previous.selected_source_sha256 != event.selected_source_sha256:
                raise ValueError("Conflicting source alert identity.")
            unique.setdefault(key, event)
        events = sorted(unique.values(), key=lambda row: (row.timestamp, row.source_instance, row.source_alert_id))
        return RelatedEventSearchResult(request, tuple(events[:request.limit]), datetime.now(timezone.utc), len(hits) > request.limit)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise InvestigationSearchError("Indexer returned malformed, conflicting or out-of-scope related events.") from None
