"""Cases aggregate evidence; membership is not a finding of compromise."""

from dataclasses import dataclass
from typing import Literal

from cybertriage.domain.alert import SecurityAlert

CaseStatus = Literal["open", "investigating", "resolved", "closed"]
CasePriority = Literal["low", "medium", "high", "critical"]
CaseDisposition = Literal["unconfirmed", "benign", "confirmed_compromise"]
RelationshipKind = Literal["observed", "hypothesis"]


class CaseError(ValueError):
    """A case command cannot be applied."""


class CaseConflictError(CaseError):
    """Reload the case before retrying a stale version."""


class CaseStorageError(RuntimeError):
    """Case persistence failed; the transaction was rolled back."""


@dataclass(frozen=True)
class CaseAlertEvidence:
    record_id: str
    alert: SecurityAlert
    payload_hash: str


@dataclass(frozen=True)
class IncidentCase:
    case_id: str
    title: str
    description: str
    priority: CasePriority
    status: CaseStatus
    disposition: CaseDisposition
    version: int
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class RelationshipAssertion:
    source_alert_id: str
    target_alert_id: str
    kind: RelationshipKind
    predicate: str
    rationale: str
    supporting_alert_ids: tuple[str, ...]
    proof_json: str
    analysis_id: str | None = None
