"""Explicit analyst interpretations of evidence within the Cyber Kill Chain."""

from collections.abc import Sequence

from cybertriage.application.ports.graph import CaseStageRepository
from cybertriage.application.services.case_management import CaseManagement, identifier, page, text, version
from cybertriage.domain.case import CaseError
from cybertriage.domain.graph import KILL_CHAIN_STAGES


class CaseStages:
    def __init__(self, repository: CaseStageRepository):
        self._repository = repository

    def add(self, case_id: str, stage: str, kind: str, supporting_ids: Sequence[str],
            expected_version: int, actor: str, reason: str):
        if stage not in dict(KILL_CHAIN_STAGES) or kind not in {"hypothesis", "analyst_assessed"}:
            raise CaseError("Supply a supported Kill Chain stage and assessment kind.")
        if isinstance(supporting_ids, (str, bytes)):
            raise CaseError("Supporting alert IDs must be a sequence of identifiers.")
        support = CaseManagement._ids(supporting_ids)
        if not support:
            raise CaseError("A stage assessment requires attached supporting alert IDs.")
        return self._repository.add_stage(identifier(case_id), stage, kind, support, version(expected_version),
                                          text(actor, "Actor", 128), text(reason, "Reason"))

    def review(self, case_id: str, assertion_id: str, decision: str, expected_version: int, actor: str, reason: str):
        if decision not in {"accepted", "rejected", "retracted", "superseded"}:
            raise CaseError("Unsupported stage review decision.")
        return self._repository.review_stage(identifier(case_id), identifier(assertion_id), decision,
            version(expected_version), text(actor, "Actor", 128), text(reason, "Reason"))

    def list(self, case_id: str, limit: int = 50, after: int = 0):
        page(limit, after)
        return self._repository.stages(identifier(case_id), limit, after)
