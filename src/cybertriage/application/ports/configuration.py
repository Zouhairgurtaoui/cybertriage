from typing import Protocol

from cybertriage.domain.configuration import KnowledgeSettings
from cybertriage.domain.response import ResponseSettings


class KnowledgeConfigurationProvider(Protocol):
    def load(self) -> KnowledgeSettings:
        ...


class ResponseConfigurationProvider(Protocol):
    def load(self) -> ResponseSettings:
        ...
