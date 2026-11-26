from typing import Protocol

from cybertriage.domain.related_events import RelatedEventSearchRequest, RelatedEventSearchResult


class RelatedEventSearcher(Protocol):
    def search(self, request: RelatedEventSearchRequest) -> RelatedEventSearchResult:
        """Return bounded related alerts or raise InvestigationSearchError; never hide source failures."""
        ...
