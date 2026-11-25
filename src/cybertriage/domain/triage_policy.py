"""Typed inputs and decisions for pre-analysis resource policy."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal


@dataclass(frozen=True)
class SuppressionRule:
    rule_id: str
    source_instance: str
    agent_id: str
    wazuh_rule_id: str
    fields: tuple[tuple[str, str], ...]
    starts_at: datetime
    expires_at: datetime
    max_level: int
    reason: str


@dataclass(frozen=True)
class GroupingRule:
    rule_id: str
    wazuh_rule_ids: tuple[str, ...]
    provider: str | None
    channel: str | None
    event_ids: tuple[int, ...]
    fields: tuple[str, ...]
    window_seconds: int
    settle_seconds: int
    max_members: int


@dataclass(frozen=True)
class TriageSettings:
    enabled: bool = True
    force_investigate_level: int = 12
    protected_windows_event_ids: tuple[int, ...] = (1102, 4719, 4728, 4732, 4756)
    suppression_rules: tuple[SuppressionRule, ...] = ()
    grouping_rules: tuple[GroupingRule, ...] = ()


@dataclass(frozen=True)
class GroupingCandidate:
    fingerprint: str
    window_start: str
    window_end: str
    settle_seconds: int
    max_members: int


@dataclass(frozen=True)
class TriagePlan:
    action: Literal["investigate", "suppress"]
    reason: str
    rule_id: str | None
    policy_revision: str
    policy_snapshot_json: str
    grouping: GroupingCandidate | None = None


@dataclass(frozen=True)
class AnalystFeedback:
    alert_record_id: str
    analyst: str
    label: Literal["benign", "malicious", "uncertain"]
    reason: str

    def __post_init__(self) -> None:
        for name, limit in (("alert_record_id", 128), ("analyst", 128), ("reason", 2000)):
            value = getattr(self, name)
            if (not isinstance(value, str) or not value.strip()
                    or value != value.strip() or len(value) > limit
                    or not value.isprintable()):
                raise ValueError(f"{name} must be bounded printable text without surrounding whitespace.")
        if self.label not in ("benign", "malicious", "uncertain"):
            raise ValueError("Unknown feedback label.")


@dataclass(frozen=True)
class TriageEvaluationRow:
    action: str
    policy_revision: str
    label: str | None


class TriageReviewError(RuntimeError):
    """A triage review operation could not be completed."""
