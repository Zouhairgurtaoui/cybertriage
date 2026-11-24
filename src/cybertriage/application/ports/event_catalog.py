from typing import Protocol

from cybertriage.domain.security_event import SecurityEventDefinition


class SecurityEventCatalog(Protocol):
    def lookup(
        self,
        provider: str,
        channel: str,
        event_id: int,
    ) -> SecurityEventDefinition | None:
        ...

class EventDefinitionSource(Protocol):
    def fetch_definitions(self) -> list[SecurityEventDefinition]:
        ...


class EventCatalogStore(Protocol):
    def save(
        self,
        definitions: list[SecurityEventDefinition],
    ) -> None:
        ...

    def load(self) -> list[SecurityEventDefinition]:
        ...