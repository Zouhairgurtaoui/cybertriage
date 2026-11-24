from cybertriage.application.ports.event_catalog import (
    EventCatalogStore,
    EventDefinitionSource,
)


class UpdateEventCatalog:
    def __init__(
        self,
        source: EventDefinitionSource,
        store: EventCatalogStore,
    ):
        self._source = source
        self._store = store

    def execute(self) -> int:
        definitions = self._source.fetch_definitions()

        if not definitions:
            raise ValueError("The source returned no event definitions.")

        self._store.save(definitions)

        return len(definitions)