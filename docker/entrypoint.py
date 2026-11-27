"""Container-only process boundary: file secrets, maintenance lock and shutdown."""

import fcntl
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

import requests


def load_file_secrets():
    for name, filename in tuple(os.environ.items()):
        if not re.fullmatch(r"CYBERTRIAGE_[A-Z0-9_]+_FILE", name) or not filename:
            continue
        target = name[:-5]
        if os.environ.get(target):
            raise ValueError(f"Configure either {target} or its _FILE variant, not both.")
        with Path(filename).open("rb") as file:
            content = file.read(8193)
        if len(content) > 8192:
            raise ValueError(f"Secret file exceeds its size limit: {name}.")
        value = content.decode("utf-8-sig").rstrip("\r\n")
        if not value or any(ord(character) < 32 for character in value):
            raise ValueError(f"Secret file must contain one nonempty line: {name}.")
        os.environ[target] = value
        del os.environ[name]


def model_prerequisites(command: str):
    from cybertriage.adapters.configuration.ollama_environment import ollama_base_url
    required = {"nomic-embed-text"}
    if command != "ingest":
        required.add(os.environ.get("CYBERTRIAGE_MODEL", "qwen3:4b-instruct"))
    session = requests.Session()
    session.trust_env = False
    try:
        response = session.get(f"{ollama_base_url()}/api/tags", timeout=10, allow_redirects=False)
        response.raise_for_status()
        if len(response.content) > 1024 * 1024:
            raise ValueError("Ollama model listing exceeds its size limit.")
        available = {item["name"] for item in response.json()["models"]}
    finally:
        session.close()
    normalized = lambda name: name if ":" in name else name + ":latest"
    missing = {name for name in required if normalized(name) not in available}
    if missing:
        raise ValueError("Required existing models were not found: " + ", ".join(sorted(missing)) + ". Check the configured external Ollama service. No model is downloaded automatically.")
    if command in {"worker", "investigation-worker", "case-chat-worker"}:
        if not Path("data/catalogs/windows-security.json").is_file() or not Path("data/chroma/chroma.sqlite3").is_file():
            raise ValueError("Knowledge data is missing. Import the existing data or populate the catalogue/collections before starting workers.")
        from cybertriage.adapters.configuration.indexer_environment import EnvironmentIndexerConfiguration
        EnvironmentIndexerConfiguration().load()
        if not os.environ.get("CYBERTRIAGE_INDEXER_PASSWORD"):
            raise ValueError("Configure the read-only Indexer password file for noninteractive workers.")


def verify_indexer_connection():
    """Verify TLS/auth/search permission without retrieving incident documents."""
    from cybertriage.adapters.configuration.indexer_environment import EnvironmentIndexerConfiguration
    from cybertriage.adapters.wazuh.indexer_http import WazuhIndexerHttpClient
    settings = EnvironmentIndexerConfiguration().load()
    client = WazuhIndexerHttpClient(settings.base_url, settings.username,
        os.environ["CYBERTRIAGE_INDEXER_PASSWORD"], settings.ca_bundle)
    client.search_alerts({"size": 1, "query": {"match_none": {}}}, max_hits=1)


def main() -> int:
    arguments = sys.argv[1:]
    if not arguments:
        raise ValueError("Supply a CyberTriage CLI command to the container.")
    load_file_secrets()
    command = arguments[0]
    maintenance = command in {"ingest", "catalog-update"}
    with ExitStack() as resources:
        lock = resources.enter_context(Path("data/.runtime.lock").open("a+b"))
        try:
            fcntl.flock(lock.fileno(), (fcntl.LOCK_EX if maintenance else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("A maintenance task or running service owns the data volume. Stop backend services before import or ingestion.") from error
        if command in {"worker", "investigation-worker", "case-chat-worker", "ingest"}:
            model_prerequisites(command)
        if command in {"worker", "investigation-worker", "case-chat-worker"}:
            from indexer_forward import configured_indexer_forward
            resources.enter_context(configured_indexer_forward())
            if command != "case-chat-worker":
                verify_indexer_connection()
        child = subprocess.Popen([sys.executable, "-m", "cybertriage", *arguments], stdin=subprocess.DEVNULL)
        stopping = False
        deadline = None
        def stop(_signum, _frame):
            nonlocal stopping, deadline
            if not stopping:
                stopping, deadline = True, time.monotonic() + 195
                if child.poll() is None:
                    child.send_signal(signal.SIGINT)
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        heartbeat = Path("/tmp/cybertriage-worker.json")
        try:
            while child.poll() is None:
                heartbeat.write_text(json.dumps({"pid": child.pid, "heartbeat": time.time(), "stopping": stopping}), encoding="utf-8")
                if deadline is not None and time.monotonic() >= deadline:
                    print("Shutdown deadline reached; terminating owned child. Inspect interrupted response operations before reconciliation.", file=sys.stderr, flush=True)
                    child.kill()
                    break
                time.sleep(1)
            result = child.wait()
            return 0 if stopping and result in {0, 130, -signal.SIGINT} else result
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            heartbeat.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        # Source exceptions can contain connection details; keep startup diagnostics bounded.
        message = str(error) if isinstance(error, ValueError) else "Dependency or startup failure; check mounted configuration, credentials and service availability."
        print(f"Container startup failed ({type(error).__name__}): {message}", file=sys.stderr)
        raise SystemExit(1) from None
