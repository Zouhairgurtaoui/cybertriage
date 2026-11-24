from typing import Protocol

from cybertriage.domain.knowledge import KnowledgeChunk


class KnowledgeIndex(Protocol):
    def add_chunks(
        self,
        chunks: list[KnowledgeChunk],
        batch_size: int = 32,
    ) -> int:
        ...