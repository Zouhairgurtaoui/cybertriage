from collections.abc import Mapping
from typing import Protocol

from cybertriage.domain.alert import IngestionReceipt, SecurityAlert


class AlertNormalizer(Protocol):
    def normalize(
        self,
        payload: Mapping[str, object],
    ) -> SecurityAlert:
        ...


class AlertRepository(Protocol):
    def save_and_schedule(
        self,
        alert: SecurityAlert,
    ) -> IngestionReceipt:
        """
        Atomically store an alert and ensure its analysis job exists.

        Unchanged duplicate alerts reuse the existing alert and job.
        Conflicting content raises AlertConflictError.
        """
        ...

class AlertReader(Protocol):
    def get(self, record_id: str) -> SecurityAlert | None:
        """Return a stored alert, or None when it does not exist."""
        ...