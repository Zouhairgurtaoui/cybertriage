"""Explicit model-service origin, supporting native and container deployments."""

import os
from urllib.parse import urlsplit


def ollama_base_url() -> str:
    value = os.environ.get("CYBERTRIAGE_OLLAMA_URL", "http://localhost:11434")
    try:
        url = urlsplit(value)
        valid_port = url.port is None or 1 <= url.port <= 65535
    except ValueError as error:
        raise ValueError("Invalid CYBERTRIAGE_OLLAMA_URL.") from error
    if (value != value.strip() or len(value) > 2048 or not value.isprintable() or any(c.isspace() for c in value)
            or url.scheme not in {"http", "https"} or not url.hostname or not valid_port
            or url.username is not None or url.password is not None or url.query or url.fragment
            or url.path not in {"", "/"}):
        raise ValueError("CYBERTRIAGE_OLLAMA_URL must be an HTTP(S) origin without credentials or paths.")
    if url.scheme == "http" and url.hostname not in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}:
        raise ValueError("Remote Ollama origins require HTTPS; plaintext is limited to loopback and the Docker Desktop host gateway.")
    return value.rstrip("/")
