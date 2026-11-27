"""Reloadable hashed analyst credentials with expiry and per-case capabilities."""

import hmac
import os
import re
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from cybertriage.adapters.configuration.yaml_files import _fields, _read_yaml
from cybertriage.application.services.case_management import identifier
from cybertriage.domain.analyst import AnalystPrincipal, PERMISSIONS
from cybertriage.domain.authentication import PasswordIdentity
from cybertriage.adapters.configuration.password_hashing import ScryptPasswords
import json


class AnalystKeyStore:
    def __init__(self, path: Path):
        self._path = path

    def load(self, document=None):
        root = _fields(_read_yaml(self._path) if document is None else document, {"schema_version", "principals"}, "analyst credentials")
        if type(root["schema_version"]) is not int or root["schema_version"] != 1 or not isinstance(root["principals"], list) or not 1 <= len(root["principals"]) <= 100:
            raise ValueError("Configure 1..100 analyst principals before starting the analyst API.")
        result, names, hashes, usernames = [], set(), set(), set()
        ingestion_token = os.environ.get("CYBERTRIAGE_INGEST_TOKEN", "")
        ingestion_hash = sha256(ingestion_token.encode()).hexdigest() if ingestion_token else None
        for value in root["principals"]:
            required = {"id", "token_sha256", "permissions", "case_ids", "expires_at"}
            optional = {"username", "password_hash"}
            row = _fields(value, required | (set(value) & optional) if isinstance(value,dict) else required, "analyst principal")
            if ("username" in row) != ("password_hash" in row):
                raise ValueError("Password login requires both username and password_hash.")
            if "username" in row:
                username = row["username"]
                if (not isinstance(username,str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{2,63}",username)
                        or username in usernames or not ScryptPasswords.valid_hash(row["password_hash"])):
                    raise ValueError("Configure unique lowercase usernames and supported password hashes.")
                usernames.add(username)
            name, digest = identifier(row["id"]), row["token_sha256"]
            if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest) or digest in hashes or name in names or digest == ingestion_hash:
                raise ValueError("Analyst identifiers and token hashes must be unique and separate from ingestion credentials.")
            if not isinstance(row["permissions"], list) or not row["permissions"] or any(not isinstance(p, str) or p not in PERMISSIONS for p in row["permissions"]):
                raise ValueError("Configure explicit supported analyst permissions.")
            cases = row["case_ids"]
            if not isinstance(cases, list) or not 1 <= len(cases) <= 1000 or any(not isinstance(value, str) for value in cases) or len(set(cases)) != len(cases):
                raise ValueError("Configure a bounded distinct case scope.")
            case_ids = ("*",) if cases == ["*"] else tuple(identifier(case_id) for case_id in cases)
            if not isinstance(row["expires_at"], str):
                raise ValueError("Analyst expiry must be an ISO timestamp with timezone.")
            expires = datetime.fromisoformat(row["expires_at"])
            if expires.utcoffset() is None:
                raise ValueError("Analyst expiry must include a timezone.")
            names.add(name)
            hashes.add(digest)
            result.append((digest, expires.astimezone(timezone.utc), AnalystPrincipal(name, frozenset(row["permissions"]), case_ids)))
        return result

    def authenticate(self, token: str) -> AnalystPrincipal | None:
        if not isinstance(token, str) or not 32 <= len(token) <= 512 or not token.isascii() or any(c.isspace() for c in token):
            return None
        digest = sha256(token.encode("ascii")).hexdigest()
        selected = None
        now = datetime.now(timezone.utc)
        for expected, expiry, principal in self.load():
            if hmac.compare_digest(digest, expected) and expiry > now:
                selected = principal
        return selected

    def password_identity(self, username: str) -> PasswordIdentity | None:
        document = _read_yaml(self._path)
        validated = {principal.analyst_id: (expiry,principal) for _,expiry,principal in self.load(document)}
        for row in document["principals"]:
            if row.get("username") == username:
                expiry,principal = validated[row["id"]]
                revision = sha256(json.dumps(row,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")).hexdigest()
                return PasswordIdentity(username,row["password_hash"],revision,expiry,principal)
        return None
