from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

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


class InvestigationSearchError(RuntimeError):
    """The evidence source could not complete the search reliably."""