"""Persisted response authority and execution records, separate from model text."""

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Literal

from cybertriage.domain.response import ActionProposal, ResponseSettings


class ResponseError(ValueError):
    pass


class ResponseConflictError(ResponseError):
    pass


class ResponseStorageError(RuntimeError):
    pass


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


@dataclass(frozen=True)
class ResponsePolicySnapshot:
    settings: ResponseSettings
    target_revision: str = ""

    @property
    def json(self) -> str:
        return canonical({"response_settings": asdict(self.settings), "target_revision": self.target_revision})

    @property
    def revision(self) -> str:
        return sha256(self.json.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ExecutionRequest:
    execution_id: str
    claim_token: str
    proposal_id: str
    proposal: ActionProposal
    case_version: int
    policy_revision: str


@dataclass(frozen=True)
class ExecutionOutcome:
    status: Literal["succeeded", "failed", "unknown"]
    summary_json: str

    def __post_init__(self):
        if self.status not in {"succeeded", "failed", "unknown"} or len(self.summary_json.encode("utf-8")) > 16384:
            raise ResponseError("Invalid or oversized execution outcome.")
        data = json.loads(self.summary_json)
        if not isinstance(data, dict):
            raise ResponseError("Execution outcome must contain an object.")
        canonical(data)
        if self.status == "failed" and data.get("cleanup_required") is True:
            raise ResponseError("A possibly applied mutation must use an unknown outcome.")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
