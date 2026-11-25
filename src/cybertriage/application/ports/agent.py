from typing import Protocol

from cybertriage.domain.agent import InvestigationReport
from cybertriage.domain.triage import RetrievedReference


class InvestigationModel(Protocol):
    def investigate(
        self,
        evidence: str,
        references: tuple[RetrievedReference, ...],
        *,
        task: str,
    ) -> InvestigationReport:
        ...