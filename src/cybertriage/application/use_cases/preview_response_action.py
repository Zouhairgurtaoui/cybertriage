from cybertriage.application.ports.response import ResponsePolicy
from cybertriage.domain.response import ActionProposal, IncidentDisposition, PolicyDecision


class PreviewResponseAction:
    """Inspect policy eligibility without creating approval or executing anything."""

    def __init__(self, policy: ResponsePolicy):
        self._policy = policy

    def execute(
        self,
        proposal: ActionProposal,
        disposition: IncidentDisposition = IncidentDisposition.UNCONFIRMED,
    ) -> PolicyDecision:
        return self._policy.evaluate(proposal, disposition, approval=None)
