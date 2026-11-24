from dataclasses import dataclass

from cybertriage.application.ports.knowledge import (
    KnowledgeChunker,
    KnowledgeSource,
)
from cybertriage.application.ports.knowledge_index import KnowledgeIndex


@dataclass(frozen=True)
class IngestionResult:
    documents: int
    chunks: int
    added: int


class IngestKnowledge:
    def __init__(
        self,
        source: KnowledgeSource,
        chunker: KnowledgeChunker,
        index: KnowledgeIndex,
    ):
        self._source = source
        self._chunker = chunker
        self._index = index

    def execute(self) -> IngestionResult:
        documents = self._source.fetch()

        if not documents:
            raise ValueError("The source returned no documents.")

        chunks = [
            chunk
            for document in documents
            for chunk in self._chunker.split(document)
        ]

        if not chunks:
            raise ValueError("The source produced no indexable chunks.")

        added = self._index.add_chunks(chunks)

        return IngestionResult(
            documents=len(documents),
            chunks=len(chunks),
            added=added,
        )