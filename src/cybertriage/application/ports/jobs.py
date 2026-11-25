from typing import Protocol

from cybertriage.domain.jobs import ClaimedAnalysisJob
from cybertriage.domain.triage import AnalysisRecord


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

class JobCompleter(Protocol):
    def complete(
        self,
        job: ClaimedAnalysisJob,
        record: AnalysisRecord,
    ) -> None:
        """Atomically save the report and complete a valid claim."""
        ...


class JobFailureRecorder(Protocol):
    def fail(
        self,
        job: ClaimedAnalysisJob,
        *,
        error_code: str,
        retryable: bool = True,
        max_attempts: int = 3,
        retry_delay_seconds: int = 30,
    ) -> None:
        """Reschedule or fail a job while its claim remains valid."""
        ...