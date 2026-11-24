import logging
from pathlib import Path

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings

from cybertriage.domain.knowledge import KnowledgeChunk
from cybertriage.domain.triage import RetrievedReference


logger = logging.getLogger(__name__)


class ChromaKnowledgeIndex:
    def __init__(
        self,
        directory: Path,
        embeddings: Embeddings,
        collection_name: str,
        create_if_missing: bool = True,
    ):
        self._store = Chroma(
            collection_name=collection_name,
            persist_directory=str(directory),
            embedding_function=embeddings,
            create_collection_if_not_exists=create_if_missing,
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
    
    def retrieve(
        self,
        query: str,
        k: int = 3,
    ) -> list[RetrievedReference]:
        documents = self.search(query=query, k=k)
        selected = []
        seen = set()

        def append(text: str, metadata: dict) -> None:
            chunk_id = metadata["chunk_id"]
            if chunk_id not in seen and len(selected) < k:
                selected.append(RetrievedReference(
                    chunk_id=chunk_id,
                    title=metadata["title"],
                    source_url=metadata["source_url"],
                    text=text,
                ))
                seen.add(chunk_id)

        for document in documents:
            metadata = document.metadata
            if metadata["position"] != 0:
                # A matching example late in a page can omit the definition.
                # Include the same document's opening chunk with its own ID;
                # do not silently merge text under an unrelated chunk citation.
                lead = self._store.get(
                    where={"$and": [
                        {"document_id": metadata["document_id"]},
                        {"position": 0},
                    ]},
                    include=["documents", "metadatas"],
                    limit=1,
                )
                if lead["ids"]:
                    append(lead["documents"][0], lead["metadatas"][0])
            append(document.page_content, metadata)
            if len(selected) == k:
                break
        return selected

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
