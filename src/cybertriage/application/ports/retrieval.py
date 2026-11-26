from typing import Protocol

from cybertriage.domain.retrieval import IndexedPassage, RetrievalContext, RetrievalOutcome


class KnowledgeCandidateSource(Protocol):
    def snapshot(self) -> tuple[IndexedPassage, ...]:
        """Return a bounded consistent corpus, or raise KnowledgeRetrievalError."""
        ...

    def dense_candidates(self, query: str, limit: int) -> tuple[IndexedPassage, ...]: ...


class ContextualKnowledgeRetriever(Protocol):
    def retrieve_for(self, query: str, context: RetrievalContext, k: int) -> RetrievalOutcome: ...
