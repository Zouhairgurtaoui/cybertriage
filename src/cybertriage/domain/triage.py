from dataclasses import dataclass
from cybertriage.domain.security_event import SecurityEventDefinition


@dataclass(frozen=True)
class RetrievedReference:
    chunk_id: str
    title: str
    source_url: str
    text: str



@dataclass(frozen=True)
class TriageResult:
    analysis: str
    references: tuple[RetrievedReference, ...]
    event_definition: SecurityEventDefinition | None = None
