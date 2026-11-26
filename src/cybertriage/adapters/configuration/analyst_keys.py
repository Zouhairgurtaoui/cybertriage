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


class AnalystKeyStore:
    def __init__(self, path: Path):
        self._path = path

    def load(self):
        root = _fields(_read_yaml(self._path), {"schema_version", "principals"}, "analyst credentials")
        if type(root["schema_version"]) is not int or root["schema_version"] != 1 or not isinstance(root["principals"], list) or not 1 <= len(root["principals"]) <= 100:
            raise ValueError("Configure 1..100 analyst principals before starting the analyst API.")
        result, names, hashes = [], set(), set()
        ingestion_token = os.environ.get("CYBERTRIAGE_INGEST_TOKEN", "")
        ingestion_hash = sha256(ingestion_token.encode()).hexdigest() if ingestion_token else None
        for value in root["principals"]:
            row = _fields(value, {"id", "token_sha256", "permissions", "case_ids", "expires_at"}, "analyst principal")
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
