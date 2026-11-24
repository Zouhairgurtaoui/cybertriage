import logging
from pathlib import Path

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings

from cybertriage.domain.knowledge import KnowledgeChunk


logger = logging.getLogger(__name__)


class ChromaKnowledgeIndex:
    def __init__(
        self,
        directory: Path,
        embeddings: Embeddings,
        collection_name: str,
    ):
        self._store = Chroma(
            collection_name=collection_name,
            persist_directory=str(directory),
            embedding_function=embeddings,
        )

    def add_chunks(
        self,
        chunks: list[KnowledgeChunk],
        batch_size: int = 32,
    ) -> int:
        if batch_size <= 0:
            raise ValueError("batch_size must be positive.")

        ids = [chunk.chunk_id for chunk in chunks]

        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate chunk IDs in the input.")

        added = 0

        for start in range(0, len(chunks), batch_size):
            batch = chunks[start:start + batch_size]

            existing = set(
                self._store.get(
                    ids=[chunk.chunk_id for chunk in batch],
                    include=[],
                )["ids"]
            )

            pending = [
                chunk for chunk in batch
                if chunk.chunk_id not in existing
            ]

            if pending:
                self._store.add_documents(
                    documents=[self._to_document(chunk) for chunk in pending],
                    ids=[chunk.chunk_id for chunk in pending],
                )
                added += len(pending)

            logger.info(
                "Processed %d/%d chunks; added %d",
                min(start + batch_size, len(chunks)),
                len(chunks),
                added,
            )

        return added

    def search(self, query: str, k: int = 3) -> list[Document]:
        if not query.strip():
            raise ValueError("Search query must not be empty.")

        if not 1 <= k <= 20:
            raise ValueError("k must be between 1 and 20.")

        return self._store.similarity_search(query=query, k=k)

    @staticmethod
    def _to_document(chunk: KnowledgeChunk) -> Document:
        source = chunk.document

        return Document(
            page_content=f"{source.title}\n\n{chunk.text}",
            metadata={
                "chunk_id": chunk.chunk_id,
                "document_id": source.document_id,
                "source_name": source.source_name,
                "source_url": source.source_url,
                "source_revision": source.source_revision,
                "retrieved_at": source.retrieved_at.isoformat(),
                "document_hash": source.content_hash,
                "title": source.title,
                "position": chunk.position,
            },
        )