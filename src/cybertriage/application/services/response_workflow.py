"""Operator-driven response proposals, reviews and at-most-one dispatch claims."""

from collections.abc import Mapping, Sequence
from ipaddress import ip_address

from cybertriage.application.ports.response_workflow import ActionExecutor, ResponseRepository
from cybertriage.application.services.case_management import CaseManagement, identifier, page, text, version
from cybertriage.domain.response import ActionProposal
from cybertriage.domain.response_workflow import ExecutionOutcome, ResponseError, ResponsePolicySnapshot, canonical


class ResponseWorkflow:
    def __init__(self, repository: ResponseRepository, snapshot: ResponsePolicySnapshot,
                 executors: Mapping[tuple[str, str], ActionExecutor] | None = None):
        self._repository, self._snapshot = repository, snapshot
        self._executors = dict(executors or {})

    def propose(self, case_id: str, action: str, target: str, parameters: Mapping[str, str | int],
                supporting_ids: Sequence[str], expected_version: int, actor: str, reason: str,
                idempotency_key: str, origin: str = "operator", analysis_id: str | None = None):
        if origin not in {"operator", "application", "model"}:
            raise ResponseError("Invalid proposal origin.")
        if isinstance(supporting_ids, (str, bytes)):
            raise ResponseError("Supporting alert IDs must be a sequence.")
        support = CaseManagement._ids(supporting_ids)
        if not support:
            raise ResponseError("Response proposals require supporting attached alerts.")
        if not isinstance(parameters, Mapping) or len(parameters) > 20 or len(canonical(dict(parameters)).encode("utf-8")) > 4096:
            raise ResponseError("Response parameters must be a bounded object.")
        parameters = dict(parameters)
        if action == "block_ip" and isinstance(parameters.get("ip_address"), str):
            address = ip_address(parameters["ip_address"])
            parameters["ip_address"] = str(getattr(address, "ipv4_mapped", None) or address)
        proposal = ActionProposal(identifier(case_id), identifier(action), identifier(target), parameters)
        return self._repository.propose(proposal, support, version(expected_version), text(actor, "Actor", 128),
            text(reason, "Reason"), origin, identifier(idempotency_key), identifier(analysis_id) if analysis_id else None, self._snapshot)

    def review(self, proposal_id: str, decision: str, expected_version: int, actor: str, reason: str):
        if decision not in {"approved", "rejected", "revoked"}:
            raise ResponseError("Review decision must be approved, rejected or revoked.")
        if decision == "approved":
            record = self.get(proposal_id)
            if (str(record["action"]), str(record["target"])) not in self._executors:
                raise ResponseError("Approval requires a configured executor for this exact action and target.")
        return self._repository.review(identifier(proposal_id), decision, version(expected_version),
            text(actor, "Actor", 128), text(reason, "Reason"), self._snapshot)

    def get(self, proposal_id: str):
        return self._repository.get(identifier(proposal_id))

    def capabilities(self):
        """Expose nonsecret constraints without granting response authority."""
        return {"execution_enabled": self._snapshot.settings.execution_enabled,
            "approval_ttl_seconds": self._snapshot.settings.approval_ttl_seconds,
            "policy_revision": self._snapshot.revision,
            "actions": [{"action": rule.action, "enabled": rule.enabled,
                "targets": [target for target in rule.allowed_targets if (rule.action, target) in self._executors],
                "required_parameters": list(rule.required_parameters), "max_duration_seconds": rule.max_duration_seconds}
                for rule in self._snapshot.settings.rules]}

    def list(self, case_id: str, limit: int = 50, after: int = 0):
        page(limit, after)
        return self._repository.list(identifier(case_id), limit, after)

    def execute(self, proposal_id: str, expected_version: int, actor: str, reason: str):
        record = self.get(proposal_id)
        executor = self._executors.get((str(record["action"]), str(record["target"])))
        if executor is None:
            raise ResponseError("No executor is registered for this exact action and target.")
        request = self._repository.claim(identifier(proposal_id), version(expected_version),
            text(actor, "Actor", 128), text(reason, "Reason"), self._snapshot)
        try:
            outcome = executor.execute(request)
            if not isinstance(outcome, ExecutionOutcome):
                raise ResponseError("Executor returned an invalid outcome.")
        except Exception:
            # A timeout or interrupted response does not establish that the action was not applied.
            outcome = ExecutionOutcome("unknown", canonical({"code": "executor_outcome_unknown", "requires_reconciliation": True}))
        return self._repository.finish(request, outcome)

    def reconcile(self, execution_id: str, outcome: str, actor: str, reason: str, evidence: str):
        if outcome not in {"applied", "not_applied"}:
            raise ResponseError("Reconciliation outcome must be applied or not_applied.")
        return self._repository.reconcile(identifier(execution_id), outcome, text(actor, "Actor", 128),
            text(reason, "Reason"), text(evidence, "Reconciliation evidence", 4000))

    def reconcile_release(self, execution_id: str, actor: str, reason: str, evidence: str):
        return self._repository.reconcile_block_release(identifier(execution_id), text(actor, "Actor", 128),
            text(reason, "Reason"), text(evidence, "Reconciliation evidence", 4000))
