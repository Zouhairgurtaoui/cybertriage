from datetime import datetime
from typing import Protocol

from cybertriage.domain.knowledge import KnowledgeDocument
from cybertriage.domain.live_web import WebCacheEntry, WebRequestBudget, WebResponse, WebTarget


class PublicDocumentFetcher(Protocol):
    def fetch(self, url: str, budget: WebRequestBudget, *, etag: str | None = None,
              last_modified: str | None = None) -> WebResponse: ...


class PublicDocumentParser(Protocol):
    def parse(self, target: WebTarget, response: WebResponse, fetched_at: datetime) -> KnowledgeDocument: ...


class PublicDocumentCache(Protocol):
    def get(self, key: str) -> WebCacheEntry | None: ...
    def claim(self, key: str, now: datetime) -> str | None: ...
    def save(self, entry: WebCacheEntry, claim: str, now: datetime) -> None: ...
    def release(self, key: str, claim: str) -> None: ...
