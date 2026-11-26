"""Retrieval inputs and provenance, independent of vector-store SDKs."""

from dataclasses import dataclass
from datetime import datetime

from cybertriage.domain.security_event import EventIdentity
from cybertriage.domain.triage import RetrievedReference


class KnowledgeRetrievalError(RuntimeError):
    """Knowledge could not be retrieved consistently within its resource limits."""


@dataclass(frozen=True)
class RetrievalContext:
    event: EventIdentity | None = None
    event_description: str | None = None
    platform: str | None = None

    def __post_init__(self) -> None:
        if self.event is not None and not isinstance(self.event, EventIdentity):
            raise ValueError("Retrieval event context must be an EventIdentity.")
        if self.platform is not None and not isinstance(self.platform, str):
            raise ValueError("Host platform context must be text.")
        if self.platform not in {None, "windows", "linux", "macos"}:
            raise ValueError("Unsupported host platform context.")
        if (self.event is not None and self.event.provider in {
            "Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Sysmon", "Microsoft-Windows-PowerShell",
        } and self.platform not in {None, "windows"}):
            raise ValueError("Explicit platform contradicts the supplied Windows event provider.")
        if self.event_description is not None and (not isinstance(self.event_description, str)
                or not self.event_description.strip() or len(self.event_description.encode("utf-8")) > 2000):
            raise ValueError("Event descriptions must contain 1..2000 UTF-8 bytes.")

    @property
    def host_platform(self) -> str | None:
        if self.platform is not None:
            return self.platform
        if self.event is not None and self.event.provider in {
            "Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Sysmon", "Microsoft-Windows-PowerShell",
        }:
            return "windows"
        return None


@dataclass(frozen=True)
class IndexedPassage:
    reference: RetrievedReference
    source_name: str
    document_id: str
    source_revision: str
    document_hash: str
    retrieved_at: datetime
    position: int
    platforms: tuple[str, ...] = ()


@dataclass(frozen=True)
class RetrievalOutcome:
    references: tuple[RetrievedReference, ...]
    trace_json: str
