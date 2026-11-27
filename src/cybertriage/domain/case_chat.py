"""Persistent analyst turns; assistant replies are provisional, never approvals."""

from dataclasses import dataclass

from cybertriage.domain.triage import TriageResult


@dataclass(frozen=True)
class ChatClaim:
    turn_id: str
    case_id: str
    claim_token: str
    attempt_count: int


@dataclass(frozen=True)
class ChatReply:
    reply_id: str
    evidence: str
    result: TriageResult
    input_alert_ids: tuple[str, ...]
    included_history_ids: tuple[str, ...]
    history_omitted: bool


class ChatLeaseLostError(RuntimeError):
    """A reply may only be saved by the current lease owner."""
