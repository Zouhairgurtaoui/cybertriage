"""Password login issues short-lived opaque bearer sessions; authorization stays server-side."""

from datetime import datetime, timezone
from hashlib import sha256
import hmac
import secrets
from threading import BoundedSemaphore
import time

from cybertriage.application.ports.authentication import PasswordHasher, PasswordIdentities, SessionRepository
from cybertriage.domain.authentication import LoginRateLimitedError


class AnalystSessions:
    def __init__(self, identities: PasswordIdentities, passwords: PasswordHasher, sessions: SessionRepository):
        self._identities, self._passwords, self._sessions = identities, passwords, sessions
        self._capacity = BoundedSemaphore(2)

    def login(self, username: str, password: str, client: str):
        username = username.strip().lower()
        self._sessions.admit_login(username,client)
        if not self._capacity.acquire(blocking=False):
            raise LoginRateLimitedError("Login capacity reached.")
        try:
            identity = self._identities.password_identity(username)
            valid = self._passwords.verify(password,identity.password_hash if identity else None)
        finally:
            self._capacity.release()
        now = int(time.time())
        if not valid or identity is None or identity.expires_at.timestamp()<=now:
            return None
        expires = min(now+900,int(identity.expires_at.timestamp()))
        token = "cts_"+secrets.token_urlsafe(32)
        self._sessions.create(sha256(token.encode("ascii")).hexdigest(),username,identity.revision,expires)
        return {"access_token":token,"token_type":"Bearer","expires_in":expires-now,
                "expires_at":datetime.fromtimestamp(expires,timezone.utc).isoformat()}

    def authenticate(self, token: str):
        if not token.startswith("cts_") or not 32 <= len(token) <= 128 or not token.isascii():
            return None
        digest = sha256(token.encode("ascii")).hexdigest()
        saved = self._sessions.get_active(digest)
        if saved is None:
            return None
        identity = self._identities.password_identity(str(saved["username"]))
        if (identity is None or identity.expires_at.timestamp()<=time.time()
                or not hmac.compare_digest(identity.revision,str(saved["credential_revision"]))):
            self._sessions.revoke(digest)
            return None
        return identity.principal

    def logout(self, token: str):
        if token.startswith("cts_") and token.isascii() and len(token)<=128:
            self._sessions.revoke(sha256(token.encode("ascii")).hexdigest())
