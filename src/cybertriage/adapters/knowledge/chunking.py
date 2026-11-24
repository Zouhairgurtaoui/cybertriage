from hashlib import sha256

from langchain_text_splitters import RecursiveCharacterTextSplitter

from cybertriage.domain.knowledge import KnowledgeChunk, KnowledgeDocument


class RecursiveKnowledgeChunker:
    def __init__(
        self,
        chunk_size: int = 1200,
        chunk_overlap: int = 150,
    ):
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive.")

        if not 0 <= chunk_overlap < chunk_size:
            raise ValueError(
                "chunk_overlap must be non-negative and smaller than chunk_size."
            )

        self.policy_id = (
            f"recursive-v1:size={chunk_size}:overlap={chunk_overlap}"
        )

        self.splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
            length_function=len,
            is_separator_regex=False,
        )

    def split(self, document: KnowledgeDocument) -> list[KnowledgeChunk]:
        passages = self.splitter.split_text(document.text)
        chunks = []

        for position, text in enumerate(passages):
            identity = (
                f"{document.document_id}|"
                f"{document.source_revision}|"
                f"{document.content_hash}|"
                f"{self.policy_id}|"
                f"{position}"
            )

            chunks.append(
                KnowledgeChunk(
                    chunk_id=sha256(identity.encode("utf-8")).hexdigest(),
                    document=document,
                    position=position,
                    text=text,
                )
            )

        return chunks