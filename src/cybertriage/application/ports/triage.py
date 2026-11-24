from typing import Protocol

from cybertriage.domain.triage import RetrievedReference


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
