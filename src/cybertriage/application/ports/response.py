from typing import Protocol

from cybertriage.domain.response import (
    ActionProposal, AnalystApproval, IncidentDisposition, PolicyDecision, ResponseActionRule,
)


class ActionParameterValidator(Protocol):
    def validate(self, proposal: ActionProposal, rule: ResponseActionRule) -> tuple[str, ...]:
        ...


class ResponsePolicy(Protocol):
    def evaluate(
        self,
        proposal: ActionProposal,
        disposition: IncidentDisposition,
        approval: AnalystApproval | None,
    ) -> PolicyDecision:
        ...
