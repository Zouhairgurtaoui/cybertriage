from typing import Protocol

from cybertriage.domain.response import ResponseSettings
from cybertriage.domain.configuration import (
    IndexerSettings,
    KnowledgeSettings,
)

class KnowledgeConfigurationProvider(Protocol):
    def load(self) -> KnowledgeSettings:
        ...


class ResponseConfigurationProvider(Protocol):
    def load(self) -> ResponseSettings:
        ...
class IndexerConfigurationProvider(Protocol):
    def load(self) -> IndexerSettings:
        ...