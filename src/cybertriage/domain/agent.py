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


def validate_investigation_task(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("An investigation task is required.")

    task = value.strip()

    if len(task.encode("utf-8")) > 4_000:
        raise ValueError("Investigation task exceeds 4000 UTF-8 bytes.")

    if any(
        ord(character) < 32 and character not in "\n\r\t"
        for character in task
    ):
        raise ValueError(
            "Investigation task contains unsupported control characters."
        )

    return task