from typing import Protocol

from cybertriage.domain.retrieval import IndexedPassage, RetrievalContext, RetrievalOutcome
from cybertriage.application.ports.triage import KnowledgeRetriever


class KnowledgeCandidateSource(Protocol):
    def snapshot(self) -> tuple[IndexedPassage, ...]:
        """Return a bounded consistent corpus, or raise KnowledgeRetrievalError."""
        ...

    def dense_candidates(self, query: str, limit: int) -> tuple[IndexedPassage, ...]: ...


class ContextualKnowledgeRetriever(KnowledgeRetriever, Protocol):
    def retrieve_for(self, query: str, context: RetrievalContext, k: int) -> RetrievalOutcome: ...
