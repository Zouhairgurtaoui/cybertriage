"""Authenticated analyst identity and explicit case capabilities."""

from dataclasses import dataclass

PERMISSIONS = frozenset({"cases:read", "cases:write", "cases:review", "investigations:request",
    "reports:read_all", "responses:propose", "responses:approve", "responses:execute", "responses:reconcile", "triage:review"})


@dataclass(frozen=True)
class AnalystPrincipal:
    analyst_id: str
    permissions: frozenset[str]
    case_ids: tuple[str, ...]

    def permits(self, permission: str, case_id: str | None = None) -> bool:
        return permission in self.permissions and (case_id is None or self.case_ids == ("*",) or case_id in self.case_ids)
