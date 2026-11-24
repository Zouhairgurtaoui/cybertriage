"""Authorize a specific proposal. This policy never executes an action."""

from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Callable, Mapping

from cybertriage.application.ports.response import ActionParameterValidator
from cybertriage.domain.response import (
    ActionProposal,
    AnalystApproval,
    IncidentDisposition,
    PolicyDecision,
    ResponseActionRule,
    ResponseSettings,
)


class BlockIpParameterValidator:
    def validate(self, proposal: ActionProposal, rule: ResponseActionRule) -> tuple[str, ...]:
        errors = []
        if set(proposal.parameters) != {"ip_address", "duration_seconds"}:
            return ("IP blocking requires exactly ip_address and duration_seconds.",)
        raw_ip = proposal.parameters["ip_address"]
        try:
            if not isinstance(raw_ip, str):
                raise ValueError("Expected an IP string.")
            address = ip_address(raw_ip)
            effective_address = getattr(address, "ipv4_mapped", None) or address
            if any(candidate in ip_network(network)
                   for network in rule.protected_networks
                   for candidate in (address, effective_address)):
                errors.append("The address belongs to a protected network.")
        except ValueError:
            errors.append("Invalid IP address or protected-network configuration.")
        duration = proposal.parameters["duration_seconds"]
        if type(duration) is not int or not 1 <= duration <= rule.max_duration_seconds:
            errors.append("Block duration exceeds the configured bounds.")
        return tuple(errors)


class ResponseActionPolicy:
    def __init__(
        self,
        settings: ResponseSettings,
        validators: Mapping[str, ActionParameterValidator],
        clock: Callable[[], datetime] | None = None,
    ):
        self._settings = settings
        self._validators = dict(validators)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._rules = {rule.action: rule for rule in settings.rules}
        if len(self._rules) != len(settings.rules):
            raise ValueError("Duplicate response action rules.")

    def evaluate(
        self,
        proposal: ActionProposal,
        disposition: IncidentDisposition,
        approval: AnalystApproval | None,
    ) -> PolicyDecision:
        rule = self._rules.get(proposal.action)
        if rule is None:
            return PolicyDecision(False, ("Action is not in the configured allowlist.",))
        errors = []
        if not self._settings.execution_enabled:
            errors.append("Response execution is disabled in configuration.")
        if not rule.enabled:
            errors.append("This response action is disabled.")
        if proposal.target not in rule.allowed_targets:
            errors.append("Target is not approved for this action.")
        if set(proposal.parameters) != set(rule.required_parameters):
            errors.append("Parameters do not match the configured action contract.")
        validator = self._validators.get(proposal.action)
        if validator is None:
            errors.append("No parameter validator is registered for this action.")
        else:
            errors.extend(validator.validate(proposal, rule))
        if disposition is not IncidentDisposition.CONFIRMED_COMPROMISE:
            errors.append("Compromise has not been confirmed through the case-review workflow.")
        if approval is None:
            errors.append("Explicit analyst approval is required for this exact proposal.")
        else:
            if approval.proposal_fingerprint != proposal.fingerprint:
                errors.append("Approval does not match the current proposal.")
            age = (self._clock() - approval.approved_at).total_seconds()
            if not 0 <= age <= self._settings.approval_ttl_seconds:
                errors.append("Approval is expired or dated in the future.")
        return PolicyDecision(not errors, tuple(errors))
