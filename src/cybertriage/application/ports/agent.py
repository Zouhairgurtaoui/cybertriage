from typing import Protocol

from cybertriage.domain.agent import InvestigationReport, StoredInvestigationPlan
from cybertriage.domain.alert import SecurityAlert
from cybertriage.domain.investigation import AuthenticationScope
from cybertriage.domain.triage import RetrievedReference


class InvestigationModel(Protocol):
    def investigate(
        self,
        evidence: str,
        references: tuple[RetrievedReference, ...],
        *,
        task: str,
        scope: AuthenticationScope | None = None,
    ) -> InvestigationReport:
        ...


class StoredAlertInvestigationPlanner(Protocol):
    def plan(self, alert: SecurityAlert, group_context: str | None = None) -> StoredInvestigationPlan:
        ...
