from dataclasses import dataclass
from cybertriage.domain.security_event import SecurityEventDefinition
from datetime import datetime

from cybertriage.domain.agent import ToolExecution


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
    tool_executions: tuple[ToolExecution, ...] = ()

@dataclass(frozen=True)
class AnalysisRecord:
    analysis_id: str
    alert_record_id: str
    completed_at: datetime
    retrieval_query: str
    evidence: str
    result: TriageResult


class AnalysisStorageError(RuntimeError):
    """An investigation report could not be persisted."""
