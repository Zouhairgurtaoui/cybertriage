"""Process health only; no model generation, firewall change or fabricated job."""

import json
from pathlib import Path
import sys
import time

import requests


def main():
    kind = sys.argv[1]
    if kind == "worker":
        value = json.loads(Path("/tmp/cybertriage-worker.json").read_text(encoding="utf-8"))
        if value["stopping"] or not 0 <= time.time() - value["heartbeat"] < 15:
            raise ValueError("Worker wrapper heartbeat is stale.")
        return
    session = requests.Session()
    session.trust_env = False
    with session:
        if kind == "analyst":
            response = session.get("https://127.0.0.1:8001/healthz", verify="/run/api-tls/ca.pem", timeout=3, allow_redirects=False)
        elif kind == "ingestion":
            response = session.get("http://127.0.0.1:8000/healthz", timeout=3, allow_redirects=False)
        else:
            raise ValueError("Unknown healthcheck.")
        if response.status_code != 200 or response.json().get("status") != "up":
            raise ValueError("Service is not healthy.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(1) from None
