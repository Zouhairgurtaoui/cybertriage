import logging
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import chromadb

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings

from cybertriage.domain.knowledge import KnowledgeChunk
from cybertriage.domain.triage import RetrievedReference
from cybertriage.domain.retrieval import IndexedPassage, KnowledgeRetrievalError


logger = logging.getLogger(__name__)


class ChromaKnowledgeIndex:
    def __init__(
        self,
        directory: Path,
        embeddings: Embeddings,
        collection_name: str,
        create_if_missing: bool = True,
    ):
        client = chromadb.PersistentClient(path=str(directory))
        self._store = Chroma(
            collection_name=collection_name,
            client=client,
            embedding_function=embeddings,
            create_collection_if_not_exists=create_if_missing,
        )
        self._collection = client.get_collection(collection_name, embedding_function=None)

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

            stored = self._store.get(
                    ids=[chunk.chunk_id for chunk in batch],
                    include=["documents", "metadatas"],
                )
            existing = set(stored["ids"])
            stored_texts = stored.get("documents")
            stored_metadata = stored.get("metadatas")
            if stored_texts is None or stored_metadata is None or not len(existing) == len(stored_texts) == len(stored_metadata):
                raise KnowledgeRetrievalError("Stored knowledge has incomplete records.")
            by_id = {key: (body, metadata) for key, body, metadata in zip(stored["ids"], stored_texts, stored_metadata)}
            refresh_ids, refresh_metadata = [], []
            for chunk in batch:
                if chunk.chunk_id not in existing:
                    continue
                document = self._to_document(chunk)
                previous_text, previous_metadata = by_id[chunk.chunk_id]
                if previous_text != document.page_content:
                    raise KnowledgeRetrievalError("A stored chunk ID conflicts with its original text.")
                if previous_metadata != document.metadata:
                    refresh_ids.append(chunk.chunk_id)
                    refresh_metadata.append(document.metadata)
            if refresh_ids:
                # Supplying metadata only retains existing text and embeddings.
                self._collection.update(ids=refresh_ids, metadatas=refresh_metadata)

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

    def snapshot(self) -> tuple[IndexedPassage, ...]:
        """Read a bounded corpus for lexical ranking; no embedding calls."""
        try:
            expected = self._collection.count()
            if expected > 10000:
                raise KnowledgeRetrievalError("A knowledge collection exceeds the 10000-passage snapshot budget.")
            passages, seen = [], set()
            byte_count = 0
            for offset in range(0, expected, 256):
                page = self._collection.get(limit=min(256, expected - offset), offset=offset,
                                            include=["documents", "metadatas"])
                bodies, metadata = page.get("documents"), page.get("metadatas")
                if bodies is None or metadata is None or not len(page["ids"]) == len(bodies) == len(metadata):
                    raise KnowledgeRetrievalError("Knowledge snapshot is incomplete.")
                for key, body, values in zip(page["ids"], bodies, metadata):
                    if key in seen or not isinstance(body, str) or not isinstance(values, dict) or values.get("chunk_id") != key:
                        raise KnowledgeRetrievalError("Knowledge snapshot has malformed or duplicate records.")
                    byte_count += len(body.encode("utf-8")) + len(json.dumps(values, ensure_ascii=False, allow_nan=False).encode("utf-8"))
                    if byte_count > 32 * 1024 * 1024:
                        raise KnowledgeRetrievalError("Knowledge snapshot exceeds its 32 MiB byte budget.")
                    seen.add(key)
                    passages.append(self._passage(Document(page_content=body, metadata=values)))
            if len(passages) != expected or self._collection.count() != expected:
                raise KnowledgeRetrievalError("Knowledge changed while reading; finish ingestion and restart analysis.")
            return tuple(passages)
        except KnowledgeRetrievalError:
            raise
        except Exception as error:
            raise KnowledgeRetrievalError("Could not read the knowledge snapshot.") from error

    def dense_candidates(self, query: str, limit: int) -> tuple[IndexedPassage, ...]:
        try:
            return tuple(self._passage(document) for document in self.search(query, limit))
        except KnowledgeRetrievalError:
            raise
        except Exception as error:
            raise KnowledgeRetrievalError("Semantic candidate search failed.") from error

    @staticmethod
    def _passage(document: Document) -> IndexedPassage:
        metadata = document.metadata
        for key, maximum in (("chunk_id", 128), ("document_id", 256), ("source_name", 128),
                             ("source_revision", 128), ("document_hash", 64), ("title", 512), ("source_url", 2048)):
            value = metadata.get(key)
            if not isinstance(value, str) or not value.strip() or len(value) > maximum or not value.isprintable():
                raise KnowledgeRetrievalError(f"Knowledge metadata has an invalid {key}.")
        if not re.fullmatch(r"[0-9a-f]{64}", metadata["document_hash"]):
            raise KnowledgeRetrievalError("Knowledge document hash is invalid.")
        url = urlsplit(metadata["source_url"])
        if url.scheme != "https" or not url.hostname or url.username is not None or url.password is not None:
            raise KnowledgeRetrievalError("Knowledge citations must use HTTPS URLs without credentials.")
        position = metadata.get("position")
        if type(position) is not int or not 0 <= position <= 100000:
            raise KnowledgeRetrievalError("Knowledge chunk position is invalid.")
        retrieved_at = datetime.fromisoformat(metadata["retrieved_at"])
        if retrieved_at.utcoffset() is None:
            raise KnowledgeRetrievalError("Knowledge retrieval timestamps require a timezone.")
        platforms = json.loads(metadata.get("platforms_json", "[]"))
        if (not isinstance(platforms, list) or len(platforms) > 32
                or any(not isinstance(value, str) or not value.strip() or len(value) > 64 for value in platforms)):
            raise KnowledgeRetrievalError("Knowledge platform metadata is invalid.")
        if not document.page_content.strip() or len(document.page_content) > 4000:
            raise KnowledgeRetrievalError("Knowledge passage exceeds its text budget or is empty.")
        return IndexedPassage(RetrievedReference(metadata["chunk_id"], metadata["title"], metadata["source_url"], document.page_content),
                              metadata["source_name"], metadata["document_id"], metadata["source_revision"], metadata["document_hash"],
                              retrieved_at.astimezone(timezone.utc), position, tuple(sorted({value.strip().casefold() for value in platforms})))

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
                "platforms_json": json.dumps(list(source.platforms), ensure_ascii=True),
            },
        )
