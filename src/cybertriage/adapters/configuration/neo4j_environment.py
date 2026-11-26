"""Operator configuration for the optional graph projection sink."""

import ipaddress
import os
import re
from collections.abc import Mapping
from urllib.parse import urlsplit

from cybertriage.application.services.case_graph import namespace_name
from cybertriage.domain.graph import GraphError, Neo4jSettings


def validate_settings(settings: Neo4jSettings) -> Neo4jSettings:
    uri = settings.uri
    if not isinstance(uri, str) or len(uri) > 2048 or not uri.isprintable() or uri != uri.strip():
        raise GraphError("Set CYBERTRIAGE_NEO4J_URI to a valid URI without surrounding whitespace.")
    try:
        parsed = urlsplit(uri)
        port = parsed.port
        host = parsed.hostname
        if not host or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
            raise ValueError()
        if port is not None and not 1 <= port <= 65535:
            raise ValueError()
    except ValueError as error:
        raise GraphError("Neo4j URI must have a host, optional port, and no credentials, query, fragment or path.") from error
    loopback = host.lower() == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if parsed.scheme not in {"neo4j+s", "bolt+s"} and not (parsed.scheme == "bolt" and loopback):
        raise GraphError("Use verified TLS (neo4j+s or bolt+s); plaintext bolt is allowed only on loopback.")
    if not isinstance(settings.username, str) or not 1 <= len(settings.username) <= 256 or not settings.username.isprintable() or settings.username != settings.username.strip():
        raise GraphError("Set CYBERTRIAGE_NEO4J_USERNAME to a valid username.")
    if not isinstance(settings.database, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", settings.database) or settings.database.lower() == "system":
        raise GraphError("Choose a valid application Neo4j database, not system.")
    namespace_name(settings.namespace)
    return settings


class EnvironmentNeo4jConfiguration:
    def __init__(self, environment: Mapping[str, str] | None = None):
        self._environment = environment if environment is not None else os.environ

    def load(self) -> Neo4jSettings:
        return validate_settings(Neo4jSettings(self._environment.get("CYBERTRIAGE_NEO4J_URI", ""),
            self._environment.get("CYBERTRIAGE_NEO4J_USERNAME", ""),
            self._environment.get("CYBERTRIAGE_NEO4J_DATABASE", "neo4j"),
            self._environment.get("CYBERTRIAGE_GRAPH_NAMESPACE", "cybertriage")))
