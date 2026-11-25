from collections.abc import Mapping
from datetime import datetime
from typing import Protocol

from cybertriage.domain.alert import SecurityAlert
from cybertriage.domain.triage_policy import (
    AnalystFeedback, TriageEvaluationRow, TriagePlan, TriageSettings,
)


class TriageConfigurationProvider(Protocol):
    def load(self) -> TriageSettings: ...


class AlertTriageDecider(Protocol):
    def decide(self, alert: SecurityAlert, *, at: datetime) -> TriagePlan: ...


class GroupEvidenceReader(Protocol):
    def group_context(self, representative_record_id: str) -> str | None: ...


class AlertEvidenceGrounder(Protocol):
    def ground_alert(self, alert: SecurityAlert) -> Mapping[str, object]: ...


class TriageReviewRepository(Protocol):
    def feedback(self, feedback: AnalystFeedback) -> Mapping[str, object]: ...

    def release(self, alert_record_id: str, analyst: str, reason: str) -> Mapping[str, object]: ...

    def inspect(self, alert_record_id: str) -> Mapping[str, object]: ...

    def evaluation_rows(self) -> tuple[TriageEvaluationRow, ...]: ...
