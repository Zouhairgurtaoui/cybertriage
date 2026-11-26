"""Vendor-independent block lifecycle over a configured firewall gateway."""

from collections.abc import Mapping

from cybertriage.application.ports.firewall import FirewallGateway
from cybertriage.application.ports.response_workflow import BlockLeaseRepository
from cybertriage.domain.response_workflow import ExecutionOutcome, ExecutionRequest, ResponseError, canonical


class ManagedIpBlockExecutor:
    def __init__(self, gateway: FirewallGateway):
        self._gateway = gateway

    def execute(self, request: ExecutionRequest) -> ExecutionOutcome:
        address = str(request.proposal.parameters["ip_address"])
        try:
            self._gateway.validate_container()
            if self._gateway.contains(address):
                return ExecutionOutcome("failed", canonical({"code": "address_already_present", "cleanup_required": False}))
        except Exception:
            return ExecutionOutcome("failed", canonical({"code": "firewall_preflight_failed", "cleanup_required": False}))
        try:
            self._gateway.add(address)
            if not self._gateway.contains(address):
                raise ResponseError("Alias membership was not observed after mutation.")
        except Exception:
            return ExecutionOutcome("unknown", canonical({"code": "firewall_mutation_unknown", "cleanup_required": True}))
        return ExecutionOutcome("succeeded", canonical({"code": "alias_membership_observed", "cleanup_required": True,
            "expiry_enforcement": "application_worker", "traffic_block_verified": False,
            "limitation": "Requires a correctly placed block rule referencing this alias; existing firewall states are not removed."}))


class ExpireIpBlocks:
    def __init__(self, repository: BlockLeaseRepository, gateways: Mapping[str, FirewallGateway], target_revision: str):
        self._repository, self._gateways, self._revision = repository, dict(gateways), target_revision

    def execute(self):
        lease = self._repository.claim_expired_block(self._revision)
        if lease is None:
            return {"status": "idle"}
        released = False
        try:
            gateway = self._gateways.get(str(lease["target"]))
            if gateway is None:
                raise ResponseError("No configured gateway for the expired block.")
            gateway.validate_container()
            gateway.remove(str(lease["address"]))
            released = not gateway.contains(str(lease["address"]))
        except Exception:
            pass
        return self._repository.finish_block_release(lease, released)
