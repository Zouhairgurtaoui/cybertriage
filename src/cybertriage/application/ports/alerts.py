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
    def save_if_new(
        self,
        alert: SecurityAlert,
    ) -> IngestionReceipt:
        """
        Save an alert atomically.

        Identify duplicates by source_instance and source_alert_id.
        Return the existing receipt when the content is unchanged.
        Raise AlertConflictError when the identity matches but content differs.
        """
        ...