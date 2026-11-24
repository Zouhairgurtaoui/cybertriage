"""Combine source collections without comparing incompatible score scales."""

from cybertriage.application.ports.triage import KnowledgeRetriever
from cybertriage.domain.triage import RetrievedReference


class FederatedKnowledgeRetriever:
    def __init__(self, retrievers: tuple[KnowledgeRetriever, ...]):
        if not retrievers:
            raise ValueError("At least one knowledge retriever is required.")
        self._retrievers = retrievers

    def retrieve(self, query: str, k: int = 3) -> list[RetrievedReference]:
        if not query.strip() or not 1 <= k <= 20:
            raise ValueError("Supply a nonempty query and k between 1 and 20.")
        
        batches = [retriever.retrieve(query, k=k) for retriever in self._retrievers]
        selected = []
        seen = set()
        for rank in range(k):
            for batch in batches:
                if rank >= len(batch):
                    continue
                reference = batch[rank]
                if reference.chunk_id in seen:
                    continue
                selected.append(reference)
                seen.add(reference.chunk_id)
                if len(selected) == k:
                    return selected
        return selected
