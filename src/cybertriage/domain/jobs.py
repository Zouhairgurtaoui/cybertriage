from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class ClaimedAnalysisJob:
    job_id: str
    alert_record_id: str
    claim_token: str
    attempt_count: int
    lease_expires_at: datetime


class JobStorageError(RuntimeError):
    """The analysis queue could not be accessed."""