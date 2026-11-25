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
        Atomically store an alert, audit its triage decision, and schedule
        eligible analysis or attach it to a pending grouped investigation.

        Suppressed alerts remain stored without an automatic job.
        Unchanged duplicates reuse the recorded decision and scheduling result.
        Conflicting content raises AlertConflictError.
        """
        ...

class AlertReader(Protocol):
    def get(self, record_id: str) -> SecurityAlert | None:
        """Return a stored alert, or None when it does not exist."""
        ...
