from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class ToolExecution:
    call_id: str
    tool_name: str
    arguments_json: str
    result_json: str
    status: Literal["success", "error"]


@dataclass(frozen=True)
class InvestigationReport:
    analysis: str
    tool_executions: tuple[ToolExecution, ...]