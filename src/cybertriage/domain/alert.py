from dataclasses import dataclass
from datetime import datetime

from cybertriage.domain.security_event import EventIdentity



@dataclass(frozen=True)
class SecurityAlert:
    source_alert_id: str
    source_instance: str
    timestamp: datetime

    agent_id: str
    agent_name: str

    rule_id: str
    rule_level: int
    description: str

    event: EventIdentity | None = None
    mitre_ids: tuple[str, ...] = ()
    full_log: str | None = None
    decoded_data_json: str = "{}"

@dataclass(frozen=True)
class IngestionReceipt:
    record_id: str
    created: bool

class InvalidAlertError(ValueError):
    """Incoming alert data cannot be normalized."""


class AlertConflictError(ValueError):
    """The same source alert identity has different content."""


class AlertStorageError(RuntimeError):
    """An alert could not be persisted."""

class AlertNotFoundError(LookupError):
    """The requested stored alert does not exist."""