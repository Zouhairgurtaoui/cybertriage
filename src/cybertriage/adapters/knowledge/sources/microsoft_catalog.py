import requests

from cybertriage.domain.security_event import SecurityEventDefinition

from cybertriage.adapters.event_catalog import (
    MICROSOFT_AUDIT_URL,
    MicrosoftSecurityEventCatalog,
)
from cybertriage.adapters.knowledge.sources.microsoft_http import (
    download_microsoft_html,
)


class MicrosoftCatalogSource:
    def __init__(self, url: str = MICROSOFT_AUDIT_URL):
        self._url = url

    def fetch(self) -> MicrosoftSecurityEventCatalog:
        with requests.Session() as session:
            html = download_microsoft_html(session, self._url)

        return MicrosoftSecurityEventCatalog.from_html(html, source_url=self._url)

    def fetch_definitions(self) -> list[SecurityEventDefinition]:
        return self.fetch().definitions()
