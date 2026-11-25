from typing import Protocol

from cybertriage.domain.jobs import ClaimedAnalysisJob


class JobClaimer(Protocol):
    def claim_next(
        self,
        *,
        lease_seconds: int = 600,
        max_attempts: int = 3,
    ) -> ClaimedAnalysisJob | None:
        """
        Reserve one eligible job atomically.

        Recover expired reservations when attempts remain.
        Return None when no eligible job exists.
        """
        ...