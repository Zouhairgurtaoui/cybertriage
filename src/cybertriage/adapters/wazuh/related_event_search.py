from cybertriage.adapters.wazuh.indexer_http import WazuhIndexerHttpClient
from cybertriage.adapters.wazuh.related_event_mapping import parse_related_event_response
from cybertriage.adapters.wazuh.related_event_query import build_related_event_query
from cybertriage.domain.related_events import RelatedEventSearchRequest, RelatedEventSearchResult


class WazuhRelatedEventSearcher:
    def __init__(self, client: WazuhIndexerHttpClient):
        self._client = client

    def search(self, request: RelatedEventSearchRequest) -> RelatedEventSearchResult:
        payload = self._client.search_alerts(build_related_event_query(request), max_hits=request.limit + 1)
        return parse_related_event_response(payload, request)
