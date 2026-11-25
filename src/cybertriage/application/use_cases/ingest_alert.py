from collections.abc import Mapping

from cybertriage.application.ports.alerts import (
    AlertNormalizer,
    AlertRepository,
)
from cybertriage.domain.alert import IngestionReceipt


class IngestAlert:
    def __init__(
        self,
        normalizer: AlertNormalizer,
        repository: AlertRepository,
    ):
        self._normalizer = normalizer
        self._repository = repository

    def execute(
        self,
        payload: Mapping[str, object],
    ) -> IngestionReceipt:
        alert = self._normalizer.normalize(payload)
        return self._repository.save_and_schedule(alert)