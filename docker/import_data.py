"""Explicit one-time copy of existing evidence/knowledge into an empty named volume."""

import fcntl
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile


SOURCE, TARGET = Path("/import"), Path("/app/data")
NAMES = ("alerts", "catalogs", "chroma")


def copy_file(source: str, target: str):
    path = Path(source)
    if path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}:
        # A database snapshot includes committed WAL data without copying a live WAL file.
        with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as original, sqlite3.connect(target) as snapshot:
            original.backup(snapshot)
    elif not path.name.endswith(("-wal", "-shm", "-journal")):
        shutil.copy2(source, target)
    return target


def main():
    if not (TARGET / ".container-initialized.json").is_file():
        raise ValueError("Run the bootstrap service before importing data.")
    with (TARGET / ".runtime.lock").open("a+b") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("Stop all backend containers before importing data.") from error
        for name in NAMES:
            destination = TARGET / name
            if destination.exists() and any(destination.iterdir()):
                raise ValueError("Import requires empty alerts/catalogs/chroma destinations. Existing container data is never overwritten.")
        if not (SOURCE / "alerts/alerts.sqlite3").is_file() or not (SOURCE / "catalogs/windows-security.json").is_file() or not (SOURCE / "chroma/chroma.sqlite3").is_file():
            raise ValueError("The import directory must contain the existing alert database, event catalogue and Chroma database.")
        with sqlite3.connect((SOURCE / "alerts/alerts.sqlite3").resolve().as_uri() + "?mode=ro", uri=True) as original:
            tables = {row[0] for row in original.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "response_executions" in tables and original.execute("SELECT 1 FROM response_executions WHERE status IN ('dispatching','unknown') LIMIT 1").fetchone():
                raise ValueError("Reconcile unresolved response executions on the original deployment before migration.")
            if "response_block_leases" in tables and original.execute("SELECT 1 FROM response_block_leases WHERE status IN ('scheduled','releasing','unknown') LIMIT 1").fetchone():
                raise ValueError("Release or reconcile existing IP-block leases before changing deployment bindings.")
        with tempfile.TemporaryDirectory(prefix="import-", dir=TARGET) as directory:
            staging = Path(directory)
            for name in NAMES:
                origin = SOURCE / name
                for candidate in origin.rglob("*"):
                    if candidate.is_symlink():
                        raise ValueError("Symlinks are not allowed in imported data.")
                shutil.copytree(origin, staging / name, copy_function=copy_file)
                for candidate in (staging / name, *(staging / name).rglob("*")):
                    os.chown(candidate, 10001, 10001)
            published = []
            try:
                for name in NAMES:
                    destination = TARGET / name
                    if destination.exists():
                        destination.rmdir()  # Only verified-empty named-volume directories.
                    (staging / name).replace(destination)
                    published.append(name)
            except BaseException:
                for name in reversed(published):
                    (TARGET / name).replace(staging / name)
                raise
        print("Imported alerts, catalogue and Chroma data. Host source files were not modified.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(f"Import failed: {type(error).__name__}: {error}") from None
