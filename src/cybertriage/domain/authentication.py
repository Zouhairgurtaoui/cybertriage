"""Password identities and revocable analyst sessions."""

from dataclasses import dataclass, field
from datetime import datetime

from cybertriage.domain.analyst import AnalystPrincipal


@dataclass(frozen=True)
class PasswordIdentity:
    username: str
    password_hash: str = field(repr=False)
    revision: str
    expires_at: datetime
    principal: AnalystPrincipal


class LoginRateLimitedError(RuntimeError):
    """Login attempts exceeded their bounded window."""


class AuthenticationStorageError(RuntimeError):
    """Session storage is unavailable."""
