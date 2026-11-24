from typing import Protocol

from cybertriage.domain.knowledge import KnowledgeDocument
from cybertriage.domain.knowledge import KnowledgeChunk


class KnowledgeSource(Protocol):
    def fetch(self) -> list[KnowledgeDocument]:
        """Fetch source documents.

        Return an empty list only when fetching succeeded
        but produced no eligible documents.

        Raise an exception when fetching or parsing fails.
        """
        ...

class KnowledgeChunker(Protocol):
    def split(
        self,
        document: KnowledgeDocument,
    ) -> list[KnowledgeChunk]:
        ...