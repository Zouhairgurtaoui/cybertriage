"""Read models for the authorized analyst inbox."""

from collections.abc import Mapping
from typing import Protocol


class AnalystAlertReader(Protocol):
    def list_alerts(self, limit: int = 50, before: int | None = None) -> Mapping[str, object]: ...
    def alert_detail(self, record_id: str) -> Mapping[str, object]: ...
