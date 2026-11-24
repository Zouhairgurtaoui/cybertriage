"""Response proposals and approvals; neither is model-generated authority."""

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from hashlib import sha256
from types import MappingProxyType
from typing import Mapping


class IncidentDisposition(str, Enum):
    UNCONFIRMED = "unconfirmed"
    CONFIRMED_COMPROMISE = "confirmed_compromise"
    BENIGN = "benign"


@dataclass(frozen=True)
class ResponseActionRule:
    action: str
    enabled: bool
    requires_compromise_confirmation: bool
    requires_analyst_approval: bool
    allowed_targets: tuple[str, ...]
    required_parameters: tuple[str, ...]
    max_duration_seconds: int
    protected_networks: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.requires_compromise_confirmation is not True:
            raise ValueError("Response actions must require confirmed compromise.")
        if self.requires_analyst_approval is not True:
            raise ValueError("Response actions must require analyst approval.")


@dataclass(frozen=True)
class ResponseSettings:
    execution_enabled: bool
    approval_ttl_seconds: int
    rules: tuple[ResponseActionRule, ...]


@dataclass(frozen=True)
class ActionProposal:
    case_id: str
    action: str
    target: str
    parameters: Mapping[str, str | int]

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value.strip()
                   for value in (self.case_id, self.action, self.target)):
            raise ValueError("Case, action and target must be nonempty identifiers.")
        parameters = dict(self.parameters)
        if any(not isinstance(key, str) or type(value) not in (str, int)
               for key, value in parameters.items()):
            raise ValueError("Action parameters must have string keys and scalar string/integer values.")
        object.__setattr__(self, "parameters", MappingProxyType(parameters))

    @property
    def fingerprint(self) -> str:
        payload = {
            "case_id": self.case_id,
            "action": self.action,
            "target": self.target,
            "parameters": dict(self.parameters),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AnalystApproval:
    proposal_fingerprint: str
    analyst_id: str
    approved_at: datetime

    def __post_init__(self) -> None:
        if not self.analyst_id.strip():
            raise ValueError("Approval must identify the analyst.")
        if self.approved_at.tzinfo is None or self.approved_at.utcoffset() is None:
            raise ValueError("Approval time must include a timezone.")


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reasons: tuple[str, ...]
