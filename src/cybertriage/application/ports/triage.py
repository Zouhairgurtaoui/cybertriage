from typing import Protocol

from typing import Protocol

from cybertriage.domain.security_event import EventIdentity
from cybertriage.domain.triage import (
    AnalysisRecord,
    RetrievedReference,
    TriageResult,
)


class KnowledgeRetriever(Protocol):
    def retrieve(
        self,
        query: str,
        k: int,
    ) -> list[RetrievedReference]:
        ...


class TriageModel(Protocol):
    def analyze(
        self,
        evidence: str,
        references: tuple[RetrievedReference, ...],
    ) -> str:
        ...

class AlertAnalyzer(Protocol):
    def execute(
        self,
        evidence: str,
        retrieval_query: str | None = None,
        event: EventIdentity | None = None,
    ) -> TriageResult:
        ...

class AnalysisWriter(Protocol):
    def save(self, record: AnalysisRecord) -> None:
        """Persist a new investigation without replacing earlier records."""
        ...