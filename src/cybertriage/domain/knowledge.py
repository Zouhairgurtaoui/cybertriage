from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256


@dataclass(frozen=True)
class KnowledgeDocument:
    document_id: str
    source_name: str
    title: str
    text: str
    source_url: str
    source_revision: str
    retrieved_at: datetime

    @property
    def content_hash(self) -> str:
        content = f"{self.title}\n{self.text}"
        return sha256(content.encode("utf-8")).hexdigest()

@dataclass(frozen=True)
class KnowledgeChunk:
    chunk_id: str
    document: KnowledgeDocument
    position: int
    text: str