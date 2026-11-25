from cybertriage.adapters.wazuh.authentication_mapping import (
    parse_authentication_response,
)
from cybertriage.adapters.wazuh.authentication_query import (
    build_authentication_query,
)
from cybertriage.adapters.wazuh.indexer_http import WazuhIndexerHttpClient
from cybertriage.domain.investigation import (
    AuthenticationSearchRequest,
    AuthenticationSearchResult,
)


class WazuhAuthenticationEventSearcher:
    def __init__(self, client: WazuhIndexerHttpClient):
        self._client = client

    def search(
        self,
        request: AuthenticationSearchRequest,
    ) -> AuthenticationSearchResult:
        payload = self._client.search_alerts(
            query=build_authentication_query(request),
            max_hits=request.limit + 1,
        )

        return parse_authentication_response(
            payload=payload,
            request=request,
        )
