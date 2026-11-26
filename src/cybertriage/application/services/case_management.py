"""Operator case commands. Model output cannot change case disposition."""

import re
from collections.abc import Mapping, Sequence

from cybertriage.application.policies.case_relationships import ObservedRelationshipPolicy
from cybertriage.application.ports.cases import CaseRepository
from cybertriage.domain.case import CaseError, IncidentCase, RelationshipAssertion, RelationshipKind

STATUSES = frozenset({"open", "investigating", "resolved", "closed"})
PRIORITIES = frozenset({"low", "medium", "high", "critical"})
DISPOSITIONS = frozenset({"unconfirmed", "benign", "confirmed_compromise"})


def text(value: str, label: str, maximum: int = 4000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > maximum:
        raise CaseError(f"{label} must be non-empty and at most {maximum} UTF-8 bytes.")
    if any(ord(char) < 32 and char not in "\n\t" for char in value):
        raise CaseError(f"{label} contains control characters.")
    if label in {"Actor", "Title"} and not value.isprintable():
        raise CaseError(f"{label} must be single-line printable text.")
    return value.strip()


def identifier(value: str) -> str:
    value = text(value, "Identifier", 128)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", value):
        raise CaseError("Invalid identifier.")
    return value


def page(limit: int, after: int = 0) -> None:
    if type(limit) is not int or not 1 <= limit <= 100 or type(after) is not int or after < 0:
        raise CaseError("Limit must be 1..100 and after must be a non-negative sequence.")


def version(value: int) -> int:
    if type(value) is not int or value < 1:
        raise CaseError("Expected version must be a positive integer.")
    return value


class CaseManagement:
    def __init__(self, repository: CaseRepository, relationships: ObservedRelationshipPolicy):
        self._repository = repository
        self._relationships = relationships

    def create(self, title: str, actor: str, priority: str = "medium", description: str = "") -> IncidentCase:
        if priority not in PRIORITIES:
            raise CaseError("Invalid priority.")
        return self._repository.create(text(title, "Title", 200),
                                       text(description, "Description", 8000) if description else "",
                                       priority, text(actor, "Actor", 128))

    def get(self, case_id: str) -> IncidentCase:
        return self._repository.get(identifier(case_id))

    def require_active_alert(self, case_id: str, alert_id: str) -> None:
        self._repository.require_active_alert(identifier(case_id), identifier(alert_id))

    def list_cases(self, status: str | None = None, limit: int = 50, after: str | None = None) -> Mapping[str, object]:
        page(limit)
        if status is not None and status not in STATUSES:
            raise CaseError("Invalid case status.")
        return self._repository.list_cases(status, limit, identifier(after) if after else None)

    def update(self, case_id: str, changes: Mapping[str, str], expected_version: int,
               actor: str, reason: str, supporting_ids: Sequence[str] = ()) -> IncidentCase:
        if not changes or set(changes) - {"title", "description", "status", "priority", "disposition"}:
            raise CaseError("Supply supported case fields to update.")
        cleaned = dict(changes)
        for key, choices in (("status", STATUSES), ("priority", PRIORITIES), ("disposition", DISPOSITIONS)):
            if key in cleaned and cleaned[key] not in choices:
                raise CaseError(f"Invalid {key}.")
        if "title" in cleaned:
            cleaned["title"] = text(cleaned["title"], "Title", 200)
        if "description" in cleaned:
            cleaned["description"] = text(cleaned["description"], "Description", 8000) if cleaned["description"] else ""
        ids = self._ids(supporting_ids)
        if cleaned.get("disposition") == "confirmed_compromise" and not ids:
            raise CaseError("Confirming compromise requires supporting attached alert IDs and an explicit reason.")
        return self._repository.update(identifier(case_id), cleaned, version(expected_version),
                                       text(actor, "Actor", 128), text(reason, "Reason"), ids)

    def attach(self, case_id: str, alert_ids: Sequence[str], actor: str, reason: str,
               group_id: str | None = None) -> Mapping[str, object]:
        ids = self._ids(alert_ids)
        if bool(ids) == bool(group_id):
            raise CaseError("Supply alert IDs or one group ID.")
        return self._repository.attach(identifier(case_id), ids, identifier(group_id) if group_id else None,
                                       text(actor, "Actor", 128), text(reason, "Reason"))

    def detach(self, case_id: str, alert_id: str, expected_version: int, actor: str, reason: str) -> IncidentCase:
        return self._repository.detach(identifier(case_id), identifier(alert_id), version(expected_version),
                                       text(actor, "Actor", 128), text(reason, "Reason"))

    def note(self, case_id: str, content: str, actor: str) -> IncidentCase:
        return self._repository.note(identifier(case_id), text(content, "Note", 8000), text(actor, "Actor", 128))

    def relate(self, case_id: str, source_id: str, target_id: str, kind: str, predicate: str,
               actor: str, reason: str, supporting_ids: Sequence[str] = (), analysis_id: str | None = None) -> Mapping[str, object]:
        source_id, target_id = identifier(source_id), identifier(target_id)
        if source_id == target_id or kind not in {"observed", "hypothesis"}:
            raise CaseError("Use distinct alert endpoints and an observed or hypothesis kind.")
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", predicate):
            raise CaseError("Predicate must be a lowercase identifier of at most 64 characters.")
        support = self._ids(supporting_ids)
        if kind == "hypothesis" and not support:
            raise CaseError("A hypothesis requires supporting attached alert IDs.")
        if kind == "observed":
            if analysis_id:
                raise CaseError("Model reports cannot establish observed relationships.")
            proof = self._relationships.prove(predicate, self._repository.alert_evidence(source_id),
                                              self._repository.alert_evidence(target_id))
            support = tuple(dict.fromkeys((source_id, target_id, *support)))
        else:
            proof = '{"limitation":"Analyst hypothesis; not an observed relationship."}'
        if len(proof.encode("utf-8")) > 16384:
            raise CaseError("Relationship proof exceeds 16384 UTF-8 bytes.")
        kind_value: RelationshipKind = "observed" if kind == "observed" else "hypothesis"
        assertion = RelationshipAssertion(source_id, target_id, kind_value, predicate, text(reason, "Rationale"),
                                           support, proof, identifier(analysis_id) if analysis_id else None)
        return self._repository.relate(identifier(case_id), assertion, text(actor, "Actor", 128))

    def review_relationship(self, case_id: str, relationship_id: str, decision: str,
                            expected_version: int, actor: str, reason: str) -> IncidentCase:
        if decision not in {"accepted", "rejected", "retracted", "superseded"}:
            raise CaseError("Invalid relationship review decision.")
        return self._repository.review_relationship(identifier(case_id), identifier(relationship_id), decision,
                                                    version(expected_version), text(actor, "Actor", 128), text(reason, "Reason"))

    def read(self, case_id: str, section: str, limit: int = 50, after: int = 0) -> Mapping[str, object]:
        page(limit, after)
        if section not in {"alerts", "history", "relationships", "investigations"}:
            raise CaseError("Unknown case section.")
        return self._repository.read(identifier(case_id), section, limit, after)

    def timeline(self, case_id: str, limit: int = 50, cursor: str | None = None) -> Mapping[str, object]:
        page(limit)
        if cursor is not None:
            text(cursor, "Cursor", 2048)
        return self._repository.timeline(identifier(case_id), limit, cursor)

    def report(self, case_id: str, analysis_id: str) -> Mapping[str, object]:
        return self._repository.report(identifier(case_id), identifier(analysis_id))

    @staticmethod
    def _ids(values: Sequence[str]) -> tuple[str, ...]:
        if len(values) > 100:
            raise CaseError("A command accepts at most 100 supporting or attachment IDs.")
        return tuple(dict.fromkeys(identifier(value) for value in values))
