"""Fixed-cost scrypt password hashes, without an additional native dependency."""

import hashlib
import hmac
import re
import secrets


class ScryptPasswords:
    _pattern = re.compile(r"scrypt\$131072\$8\$1\$([a-f0-9]{32})\$([a-f0-9]{64})")

    @classmethod
    def valid_hash(cls, value: object) -> bool:
        return isinstance(value, str) and cls._pattern.fullmatch(value) is not None

    @staticmethod
    def _derive(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=131072, r=8, p=1,
                              dklen=32, maxmem=256*1024*1024)

    def hash(self, password: str) -> str:
        if not isinstance(password, str) or not 15 <= len(password) <= 128 or len(password.encode("utf-8")) > 512:
            raise ValueError("Choose a password with 15-128 characters and at most 512 UTF-8 bytes.")
        salt = secrets.token_bytes(16)
        return f"scrypt$131072$8$1${salt.hex()}${self._derive(password,salt).hex()}"

    def verify(self, password: str, encoded: str | None) -> bool:
        if not isinstance(password,str) or not 1 <= len(password) <= 128 or len(password.encode("utf-8"))>512:
            return False
        match = self._pattern.fullmatch(encoded) if isinstance(encoded,str) else None
        # Unknown users pay the same hashing cost; no plaintext password is logged.
        salt = bytes.fromhex(match[1]) if match else b"\0"*16
        expected = bytes.fromhex(match[2]) if match else b"\0"*32
        actual = self._derive(password,salt)
        return hmac.compare_digest(actual,expected) and match is not None
