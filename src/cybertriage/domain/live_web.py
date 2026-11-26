"""Public knowledge refresh contracts; incident evidence is never a web request."""

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import re
from pathlib import Path
from time import monotonic

from cybertriage.domain.knowledge import KnowledgeDocument

WEB_DOCUMENT_POLICY = "web-text-v1"


class WebKnowledgeError(RuntimeError):
    code = "web_error"


class WebPolicyError(WebKnowledgeError):
    code = "policy_denied"


class WebFetchError(WebKnowledgeError):
    code = "fetch_failed"


class WebTransientError(WebFetchError):
    code = "temporarily_unavailable"


class WebCacheError(WebKnowledgeError):
    code = "cache_error"


class WebBudgetError(WebKnowledgeError):
    code = "request_budget_exhausted"


@dataclass(frozen=True)
class LiveWebSettings:
    enabled: bool = False
    sources: tuple[str, ...] = ("microsoft", "mitre")
    cache_path: Path = Path("data/cache/live-web.sqlite3")
    ttl_seconds: int = 86400
    not_found_ttl_seconds: int = 900
    max_stale_seconds: int = 604800
    allow_stale_on_error: bool = True
    max_targets: int = 2
    max_http_requests: int = 6

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool or type(self.allow_stale_on_error) is not bool:
            raise ValueError("Live-web flags must be booleans.")
        if (not isinstance(self.sources, tuple) or not self.sources
                or any(not isinstance(source, str) or source not in {"microsoft", "mitre"} for source in self.sources)
                or len(set(self.sources)) != len(self.sources)):
            raise ValueError("Live sources must be unique microsoft/mitre identifiers.")
        for name, lower, upper in (("ttl_seconds", 300, 604800), ("not_found_ttl_seconds", 60, 3600),
                                   ("max_stale_seconds", 0, 2592000), ("max_targets", 1, 3), ("max_http_requests", 1, 9)):
            value = getattr(self, name)
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError(f"Invalid live-web {name}.")
        if not isinstance(self.cache_path, Path):
            raise ValueError("Live cache path must be a Path.")


@dataclass(frozen=True)
class WebTarget:
    source: str
    identifier: str
    urls: tuple[str, ...]

    def __post_init__(self) -> None:
        pattern = r"[0-9]{1,5}" if self.source == "microsoft" else r"T[0-9]{4}(?:\.[0-9]{3})?"
        if self.source not in {"microsoft", "mitre"} or not isinstance(self.identifier, str) or not re.fullmatch(pattern, self.identifier):
            raise ValueError("Invalid public documentation identifier.")
        if self.source == "microsoft" and int(self.identifier) > 65535:
            raise ValueError("Invalid Windows event ID.")
        if not isinstance(self.urls, tuple) or not 1 <= len(self.urls) <= 3 or any(not isinstance(url, str) for url in self.urls):
            raise ValueError("Public targets require 1..3 fixed routes.")

    @property
    def key(self) -> str:
        return f"{WEB_DOCUMENT_POLICY}:{self.source}:{self.identifier}"


@dataclass
class WebRequestBudget:
    remaining: int
    deadline: float
    used: int = 0

    def consume(self) -> float:
        available = self.deadline - monotonic()
        if self.remaining <= 0 or available <= 0:
            raise WebBudgetError("Live request budget exhausted.")
        self.remaining -= 1
        self.used += 1
        return min(10.0, available)


@dataclass(frozen=True)
class WebResponse:
    url: str
    status: int
    body: bytes = b""
    etag: str | None = None
    last_modified: str | None = None


@dataclass(frozen=True)
class WebCacheEntry:
    target_key: str
    canonical_url: str
    document: KnowledgeDocument | None
    fetched_at: datetime
    validated_at: datetime
    expires_at: datetime
    etag: str | None = None
    last_modified: str | None = None

    def __post_init__(self) -> None:
        for value in (self.fetched_at, self.validated_at, self.expires_at):
            if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
                raise ValueError("Cache timestamps must be UTC-aware.")
        if not self.fetched_at <= self.validated_at < self.expires_at:
            raise ValueError("Cache timestamps are inconsistent.")
        if self.document is not None and (self.document.retrieved_at != self.fetched_at or self.document.source_url != self.canonical_url):
            raise ValueError("Cached document provenance is inconsistent.")
        for header in (self.etag, self.last_modified):
            if header is not None and (not isinstance(header, str) or len(header) > 1024 or not header.isascii() or not header.isprintable()):
                raise ValueError("Invalid cache validator.")


@dataclass(frozen=True)
class WebLookup:
    target: WebTarget
    status: str
    entry: WebCacheEntry | None
    diagnostic_codes: tuple[str, ...] = ()
    http_requests: int = 0


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
