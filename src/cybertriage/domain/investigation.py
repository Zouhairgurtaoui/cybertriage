from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json

from cybertriage.domain.security_event import EventIdentity


@dataclass(frozen=True)
class AuthenticationSearchRequest:
    account_name: str
    account_domain: str
    start: datetime
    end: datetime
    limit: int = 50

    def __post_init__(self):
        for field_name in ("account_name", "account_domain"):
            value = getattr(self, field_name)

            if (
                not isinstance(value, str)
                or not value.strip()
                or value != value.strip()
                or len(value) > 256
                or not value.isprintable()
            ):
                raise ValueError(
                    f"{field_name} must contain 1-256 printable "
                    "characters without surrounding whitespace."
                )

        for field_name in ("start", "end"):
            value = getattr(self, field_name)

            if (
                not isinstance(value, datetime)
                or value.tzinfo is None
                or value.utcoffset() is None
            ):
                raise ValueError(
                    f"{field_name} must be a timezone-aware datetime."
                )

        start = self.start.astimezone(timezone.utc)
        end = self.end.astimezone(timezone.utc)

        if end <= start:
            raise ValueError("end must be after start.")

        if end - start > timedelta(hours=24):
            raise ValueError("The search window cannot exceed 24 hours.")

        if type(self.limit) is not int or not 1 <= self.limit <= 100:
            raise ValueError("limit must be an integer from 1 to 100.")

        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)


@dataclass(frozen=True)
class AuthenticationEvent:
    source_alert_id: str
    source_instance: str
    timestamp: datetime
    agent_id: str
    agent_name: str
    event: EventIdentity

    account_name: str
    account_domain: str | None

    windows_record_id: str | None = None
    source_ip: str | None = None
    logon_type: str | None = None
    logon_id: str | None = None
    status_code: str | None = None
    substatus_code: str | None = None
    failure_reason: str | None = None


@dataclass(frozen=True)
class AuthenticationSearchResult:
    request: AuthenticationSearchRequest
    events: tuple[AuthenticationEvent, ...]
    searched_at: datetime
    has_more: bool

    coverage: str = (
        "Indexed Wazuh alerts visible to the configured reader. "
        "Collection, retention, permissions, and identity-field "
        "availability limit coverage."
    )


@dataclass(frozen=True)
class AuthenticationScope:
    """Per-investigation search authority, independent of model instructions."""

    accounts: tuple[tuple[str, str], ...]
    start: datetime
    end: datetime
    max_results: int = 10

    def __post_init__(self) -> None:
        if (not isinstance(self.accounts, tuple) or len(self.accounts) > 5
                or any(not isinstance(pair, tuple) or len(pair) != 2 for pair in self.accounts)):
            raise ValueError("Authentication scope requires at most five account/domain pairs.")
        for value in (self.start, self.end):
            if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("Scope timestamps must include a timezone.")
        start, end = self.start.astimezone(timezone.utc), self.end.astimezone(timezone.utc)
        if not timedelta(0) < end - start <= timedelta(hours=24):
            raise ValueError("Scope must cover more than zero and at most 24 hours.")
        if type(self.max_results) is not int or not 1 <= self.max_results <= 10:
            raise ValueError("Scope result limit must be an integer from 1 to 10.")
        for name, domain in self.accounts:
            AuthenticationSearchRequest(name, domain, start, end, self.max_results)
            if name == "-" or domain == "-":
                raise ValueError("Unknown identities cannot authorize a search.")
        if len(set(self.accounts)) != len(self.accounts):
            raise ValueError("Scope identities must be unique.")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)

    def allows(self, request: AuthenticationSearchRequest) -> bool:
        return (
            (request.account_name, request.account_domain) in self.accounts
            and self.start <= request.start < request.end <= self.end
            and request.limit <= self.max_results
        )

    def snapshot_json(self) -> str:
        return json.dumps({
            "version": 1,
            "accounts": [{"account_name": name, "account_domain": domain}
                         for name, domain in self.accounts],
            "start_inclusive": self.start.isoformat(),
            "end_exclusive": self.end.isoformat(),
            "max_results": self.max_results,
        }, ensure_ascii=False, sort_keys=True, allow_nan=False)


class InvestigationSearchError(RuntimeError):
    """The evidence source could not complete the search reliably."""
