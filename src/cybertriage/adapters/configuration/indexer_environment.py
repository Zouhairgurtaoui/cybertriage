import os
from collections.abc import Mapping
from pathlib import Path

from cybertriage.domain.configuration import IndexerSettings


class EnvironmentIndexerConfiguration:
    def __init__(
        self,
        environment: Mapping[str, str] | None = None,
    ):
        self._environment = (
            environment if environment is not None else os.environ
        )

    def _required(self, name: str, limit: int) -> str:
        value = self._environment.get(name)

        if (
            not isinstance(value, str)
            or not value.strip()
            or value != value.strip()
            or len(value) > limit
            or not value.isprintable()
        ):
            raise ValueError(
                f"Set {name} to a valid value without surrounding whitespace."
            )

        return value

    def load(self) -> IndexerSettings:
        base_url = self._required(
            "CYBERTRIAGE_INDEXER_URL",
            2048,
        )
        username = self._required(
            "CYBERTRIAGE_INDEXER_USERNAME",
            256,
        )
        ca_bundle = Path(
            self._required(
                "CYBERTRIAGE_INDEXER_CA_BUNDLE",
                4096,
            )
        ).expanduser()

        if not ca_bundle.is_absolute():
            raise ValueError(
                "CYBERTRIAGE_INDEXER_CA_BUNDLE must be an absolute path."
            )

        if not ca_bundle.is_file():
            raise ValueError("The configured Indexer CA bundle was not found.")

        return IndexerSettings(
            base_url=base_url,
            username=username,
            ca_bundle=ca_bundle.resolve(),
        )