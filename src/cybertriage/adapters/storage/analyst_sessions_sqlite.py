"""Hashed bearer sessions and shared login throttling; no plaintext credentials."""

from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
import sqlite3
import time

from cybertriage.domain.authentication import AuthenticationStorageError, LoginRateLimitedError


class SqliteAnalystSessions:
    def __init__(self, path: Path):
        self._path=path
        path.parent.mkdir(parents=True,exist_ok=True)
        with self._connection() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS analyst_sessions(
                token_hash TEXT PRIMARY KEY,username TEXT NOT NULL,credential_revision TEXT NOT NULL,
                created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,last_seen INTEGER NOT NULL,
                revoked_at INTEGER)""")
            connection.execute("CREATE INDEX IF NOT EXISTS analyst_session_user ON analyst_sessions(username,created_at)")
            connection.execute("""CREATE TABLE IF NOT EXISTS login_windows(
                bucket TEXT PRIMARY KEY,window_start INTEGER NOT NULL,attempts INTEGER NOT NULL)""")
        path.chmod(0o600)

    @contextmanager
    def _connection(self):
        connection=None
        try:
            connection=sqlite3.connect(self._path,timeout=5)
            connection.row_factory=sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.Error as error:
            if connection: connection.rollback()
            raise AuthenticationStorageError("Analyst session storage is unavailable.") from error
        finally:
            if connection: connection.close()

    def admit_login(self, username, client):
        now=int(time.time());blocked=False
        with self._connection() as connection:
            connection.execute("DELETE FROM login_windows WHERE window_start<=?",(now-300,))
            for prefix,value,maximum in (("user:",username,10),("client:",client,40)):
                key=sha256((prefix+value).encode("utf-8")).hexdigest()
                row=connection.execute("SELECT attempts FROM login_windows WHERE bucket=?",(key,)).fetchone()
                if row is None:
                    if connection.execute("SELECT COUNT(*) FROM login_windows").fetchone()[0]>=10000:
                        blocked=True;continue
                    connection.execute("INSERT INTO login_windows VALUES(?,?,1)",(key,now))
                elif row[0]>=maximum:
                    blocked=True
                else:
                    connection.execute("UPDATE login_windows SET attempts=attempts+1 WHERE bucket=?",(key,))
        if blocked: raise LoginRateLimitedError("Too many login attempts. Try again later.")

    def create(self, token_hash, username, revision, expires_at):
        now=int(time.time())
        with self._connection() as connection:
            connection.execute("DELETE FROM analyst_sessions WHERE expires_at<=? OR revoked_at IS NOT NULL",(now,))
            rows=connection.execute("SELECT token_hash FROM analyst_sessions WHERE username=? ORDER BY created_at DESC",(username,)).fetchall()
            for row in rows[4:]: connection.execute("UPDATE analyst_sessions SET revoked_at=? WHERE token_hash=?",(now,row[0]))
            connection.execute("INSERT INTO analyst_sessions VALUES(?,?,?,?,?,?,NULL)",(token_hash,username,revision,now,expires_at,now))

    def get_active(self, token_hash):
        now=int(time.time())
        with self._connection() as connection:
            row=connection.execute("""SELECT username,credential_revision,last_seen FROM analyst_sessions
                WHERE token_hash=? AND revoked_at IS NULL AND expires_at>? AND last_seen>?""",(token_hash,now,now-900)).fetchone()
            if row is None:return None
            if now-row["last_seen"]>=30:
                connection.execute("UPDATE analyst_sessions SET last_seen=? WHERE token_hash=?",(now,token_hash))
            return dict(row)

    def revoke(self, token_hash):
        with self._connection() as connection:
            connection.execute("UPDATE analyst_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",(int(time.time()),token_hash))
