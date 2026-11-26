"""Bounded, host-scoped evidence searches independent of Indexer or LLM SDKs."""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from uuid import UUID

from cybertriage.domain.investigation import AuthenticationScope
from cybertriage.domain.security_event import EventIdentity

EVENT_FAMILIES = ("all", "authentication", "account_changes", "group_changes", "process_activity")


def bounded_identity(value: str, name: str, maximum: int = 256) -> None:
    if (not isinstance(value, str) or not value or value != value.strip() or value == "-"
            or len(value) > maximum or not value.isprintable()):
        raise ValueError(f"{name} requires bounded printable text without surrounding whitespace.")


def utc_window(start: datetime, end: datetime) -> tuple[datetime, datetime]:
    if any(not isinstance(value, datetime) or value.utcoffset() is None for value in (start, end)):
        raise ValueError("Search timestamps must include a timezone.")
    start, end = start.astimezone(timezone.utc), end.astimezone(timezone.utc)
    if not timedelta(0) < end - start <= timedelta(hours=24):
        raise ValueError("Search windows must be positive and at most 24 hours.")
    return start, end


@dataclass(frozen=True)
class RelatedEventSearchRequest:
    source_instance: str
    agent_id: str
    start: datetime
    end: datetime
    family: str = "all"
    limit: int = 10
    account_name: str | None = None
    account_domain: str | None = None
    source_ip: str | None = None
    process_guid: str | None = None
    logon_id: str | None = None

    def __post_init__(self) -> None:
        bounded_identity(self.source_instance, "source_instance")
        bounded_identity(self.agent_id, "agent_id", 64)
        start, end = utc_window(self.start, self.end)
        if self.family not in EVENT_FAMILIES:
            raise ValueError("Unsupported event family.")
        if type(self.limit) is not int or not 1 <= self.limit <= 100:
            raise ValueError("Result limit must be 1..100.")
        if (self.account_name is None) != (self.account_domain is None):
            raise ValueError("Account filters require both account_name and account_domain.")
        if self.account_name is not None and self.account_domain is not None:
            bounded_identity(self.account_name, "account_name")
            bounded_identity(self.account_domain, "account_domain")
        if self.source_ip is not None:
            bounded_identity(self.source_ip, "source_ip", 64)
            if "%" in self.source_ip:
                raise ValueError("IP filters must not contain interface zone identifiers.")
            ip_address(self.source_ip)
        if self.process_guid is not None:
            bounded_identity(self.process_guid, "process_guid", 38)
            if not re.fullmatch(r"(?:[0-9A-Fa-f-]{36}|\{[0-9A-Fa-f-]{36}\})", self.process_guid):
                raise ValueError("Process GUID must be a reported UUID, optionally in braces.")
            UUID(self.process_guid.strip("{}"))
        if self.logon_id is not None and (not isinstance(self.logon_id, str)
                or not re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", self.logon_id) or int(self.logon_id, 16) == 0):
            raise ValueError("Logon ID must be a nonzero reported hexadecimal ID.")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)


@dataclass(frozen=True)
class RelatedEventScope:
    hosts: tuple[tuple[str, str], ...]
    start: datetime
    end: datetime
    max_results: int = 10
    families: tuple[str, ...] = EVENT_FAMILIES

    def __post_init__(self) -> None:
        if (not isinstance(self.hosts, tuple) or not 1 <= len(self.hosts) <= 5
                or any(not isinstance(pair, tuple) or len(pair) != 2 for pair in self.hosts)):
            raise ValueError("Related-event authority requires 1..5 explicit manager/agent pairs.")
        for manager, agent in self.hosts:
            bounded_identity(manager, "source_instance")
            bounded_identity(agent, "agent_id", 64)
        if len(set(self.hosts)) != len(self.hosts):
            raise ValueError("Host scope identities must be unique.")
        start, end = utc_window(self.start, self.end)
        if type(self.max_results) is not int or not 1 <= self.max_results <= 10:
            raise ValueError("Related-event scope limit must be 1..10.")
        if (not isinstance(self.families, tuple) or not self.families
                or any(family not in EVENT_FAMILIES for family in self.families)
                or len(set(self.families)) != len(self.families)):
            raise ValueError("Related-event scope requires unique supported families.")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)

    def allows(self, request: RelatedEventSearchRequest) -> bool:
        return ((request.source_instance, request.agent_id) in self.hosts
                and self.start <= request.start < request.end <= self.end
                and request.limit <= self.max_results and request.family in self.families)

    def snapshot(self) -> dict[str, object]:
        return {"hosts": [{"source_instance": manager, "agent_id": agent} for manager, agent in self.hosts],
                "start_inclusive": self.start.isoformat(), "end_exclusive": self.end.isoformat(),
                "max_results": self.max_results, "families": list(self.families)}


@dataclass(frozen=True)
class InvestigationScope(AuthenticationScope):
    """Extends existing account authority with separately enforced host authority."""

    related_events: RelatedEventScope = field(kw_only=True)

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.related_events, RelatedEventScope):
            raise ValueError("A related-event scope is required.")
        if self.related_events.start != self.start or self.related_events.end != self.end:
            raise ValueError("Combined investigation scopes must use the same outer time interval.")

    def snapshot_json(self) -> str:
        payload = json.loads(super().snapshot_json())
        payload.update(version=2, related_events=self.related_events.snapshot())
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False)


@dataclass(frozen=True)
class ReportedEventField:
    path: str
    value: str
    truncated: bool = False


@dataclass(frozen=True)
class RelatedEvent:
    source_instance: str
    source_alert_id: str
    index: str
    document_id: str
    timestamp: datetime
    agent_id: str
    agent_name: str
    rule_id: str
    rule_level: int
    event: EventIdentity | None
    fields: tuple[ReportedEventField, ...]
    fields_omitted: tuple[str, ...]
    selected_source_sha256: str


@dataclass(frozen=True)
class RelatedEventSearchResult:
    request: RelatedEventSearchRequest
    events: tuple[RelatedEvent, ...]
    searched_at: datetime
    has_more: bool
    coverage: str = (
        "Indexed wazuh-alerts-* documents visible to the configured reader, within the exact manager/agent, "
        "Wazuh timestamp interval and filters. This is not a search of raw event archives or complete host telemetry. "
        "Collection, alert rules, retention, indexing delay, field mappings and reader permissions limit coverage."
    )
