"""Bounded public-document cache with atomic refresh leases and integrity checks."""

import json
import sqlite3
from contextlib import closing, contextmanager
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from threading import RLock
from uuid import uuid4

from cybertriage.domain.knowledge import KnowledgeDocument
from cybertriage.domain.live_web import WebCacheEntry, WebCacheError

MAX_CACHE_ENTRIES = 512
MAX_CACHE_PAYLOAD_BYTES = 64 * 1024 * 1024


def _encode(entry: WebCacheEntry) -> str:
    def convert(value: object) -> str:
        if isinstance(value, datetime):
            return value.isoformat()
        raise TypeError("Unsupported cache value.")
    result = json.dumps(asdict(entry), default=convert, sort_keys=True, ensure_ascii=False, allow_nan=False)
    if len(result.encode("utf-8")) > 1024 * 1024:
        raise WebCacheError("Public cache entry exceeds 1 MiB.")
    return result


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate cache JSON key.")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("Invalid cache JSON constant.")


def _utc_stamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        raise WebCacheError("Cache operations require an explicit UTC clock.")
    return value.isoformat()


def _decode(payload: str) -> WebCacheEntry:
    if len(payload.encode("utf-8")) > 1024 * 1024:
        raise WebCacheError("Public cache entry exceeds its read budget.")
    value = json.loads(payload, object_pairs_hook=_unique, parse_constant=_reject_constant)
    for key in ("fetched_at", "validated_at", "expires_at"):
        value[key] = datetime.fromisoformat(value[key])
    if value["document"] is not None:
        document = value["document"]
        for key, maximum in (("document_id", 128), ("source_name", 128), ("title", 512), ("source_url", 2048), ("source_revision", 128)):
            if not isinstance(document.get(key), str) or not document[key].strip() or len(document[key]) > maximum:
                raise ValueError("Invalid cached document metadata.")
        document["retrieved_at"] = datetime.fromisoformat(document["retrieved_at"])
        if not isinstance(document.get("platforms"), list):
            raise ValueError("Invalid cached platform list.")
        document["platforms"] = tuple(document["platforms"])
        if not isinstance(document.get("text"), str) or not 100 <= len(document["text"]) <= 150000:
            raise ValueError("Invalid cached document text.")
        value["document"] = KnowledgeDocument(**document)
    return WebCacheEntry(**value)


class SqlitePublicDocumentCache:
    def __init__(self, path: Path):
        self._path = path.resolve()
        self._ready = False
        self._lock = RLock()

    def _initialize(self) -> None:
        with self._lock:
            if self._ready:
                return
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with closing(sqlite3.connect(self._path, timeout=5)) as connection:
                    with connection:
                        connection.execute("BEGIN IMMEDIATE")
                        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'") if not row[0].startswith("sqlite_")}
                        if tables - {"public_web_documents", "public_web_refreshes"}:
                            raise WebCacheError("Public cache path belongs to another database.")
                        connection.execute("""CREATE TABLE IF NOT EXISTS public_web_documents (
                            target_key TEXT PRIMARY KEY, payload_json TEXT NOT NULL, payload_hash TEXT NOT NULL,
                            validated_at TEXT NOT NULL, size_bytes INTEGER NOT NULL CHECK(size_bytes>0))""")
                        connection.execute("""CREATE TABLE IF NOT EXISTS public_web_refreshes (
                            target_key TEXT PRIMARY KEY, token TEXT NOT NULL, expires_at TEXT NOT NULL)""")
                self._ready = True
            except (OSError, sqlite3.Error) as error:
                raise WebCacheError("Could not initialize public knowledge cache.") from error

    @contextmanager
    def _session(self, write=False):
        self._initialize()
        try:
            with closing(sqlite3.connect(self._path.as_uri() + "?mode=rw", uri=True, timeout=5)) as connection:
                with connection:
                    connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                    yield connection
        except (OSError, sqlite3.Error, ValueError, TypeError, KeyError, RecursionError) as error:
            raise WebCacheError("Public knowledge cache operation failed.") from error

    def get(self, key: str) -> WebCacheEntry | None:
        with self._session() as connection:
            row = connection.execute("SELECT payload_json,payload_hash FROM public_web_documents WHERE target_key=?", (key,)).fetchone()
            if row is None:
                return None
            if sha256(row[0].encode("utf-8")).hexdigest() != row[1]:
                raise WebCacheError("Public cache payload failed its integrity check.")
            entry = _decode(row[0])
            if entry.target_key != key:
                raise WebCacheError("Public cache identity mismatch.")
            return entry

    def claim(self, key: str, now: datetime) -> str | None:
        token = uuid4().hex
        stamp = _utc_stamp(now)
        with self._session(True) as connection:
            connection.execute("DELETE FROM public_web_refreshes WHERE expires_at<=?", (stamp,))
            if connection.execute("SELECT 1 FROM public_web_refreshes WHERE target_key=?", (key,)).fetchone():
                return None
            if connection.execute("SELECT COUNT(*) FROM public_web_refreshes").fetchone()[0] >= 1024:
                raise WebCacheError("Public cache refresh capacity exceeded.")
            connection.execute("INSERT INTO public_web_refreshes VALUES(?,?,?)", (key, token, (now + timedelta(seconds=60)).isoformat()))
            return token

    def save(self, entry: WebCacheEntry, claim: str, now: datetime) -> None:
        stamp = _utc_stamp(now)
        payload = _encode(entry)
        size = len(payload.encode("utf-8"))
        with self._session(True) as connection:
            owner = connection.execute("SELECT 1 FROM public_web_refreshes WHERE target_key=? AND token=? AND expires_at>?",
                (entry.target_key, claim, stamp)).fetchone()
            if owner is None:
                raise WebCacheError("Public cache refresh lease was lost.")
            connection.execute("""INSERT INTO public_web_documents VALUES(?,?,?,?,?)
                ON CONFLICT(target_key) DO UPDATE SET payload_json=excluded.payload_json,payload_hash=excluded.payload_hash,
                    validated_at=excluded.validated_at,size_bytes=excluded.size_bytes""",
                (entry.target_key, payload, sha256(payload.encode("utf-8")).hexdigest(), entry.validated_at.isoformat(), size))
            while True:
                count, total = connection.execute("SELECT COUNT(*),COALESCE(SUM(size_bytes),0) FROM public_web_documents").fetchone()
                if count <= MAX_CACHE_ENTRIES and total <= MAX_CACHE_PAYLOAD_BYTES:
                    break
                oldest = connection.execute("SELECT target_key FROM public_web_documents WHERE target_key<>? ORDER BY validated_at,target_key LIMIT 1", (entry.target_key,)).fetchone()
                if oldest is None:
                    raise WebCacheError("Public cache storage budget exceeded.")
                connection.execute("DELETE FROM public_web_documents WHERE target_key=?", oldest)

    def release(self, key: str, claim: str) -> None:
        with self._session(True) as connection:
            connection.execute("DELETE FROM public_web_refreshes WHERE target_key=? AND token=?", (key, claim))
