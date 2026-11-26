"""Case-owned graph projections; identifiers and chronology are not attribution."""

import json
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Literal

from cybertriage.domain.alert import SecurityAlert
from cybertriage.domain.case import IncidentCase

GRAPH_POLICY = "case-graph-v1"
MAX_GRAPH_NODES = 30000
MAX_GRAPH_EDGES = 150000
MAX_GRAPH_BYTES = 16 * 1024 * 1024

KILL_CHAIN_STAGES = (
    ("reconnaissance", "Reconnaissance"),
    ("weaponization", "Weaponization"),
    ("delivery", "Delivery"),
    ("exploitation", "Exploitation"),
    ("installation", "Installation"),
    ("command_and_control", "Command and Control"),
    ("actions_on_objectives", "Actions on Objectives"),
)


class GraphError(ValueError):
    pass


class GraphStorageError(RuntimeError):
    pass


class GraphConflictError(GraphError):
    pass


@dataclass(frozen=True)
class Neo4jSettings:
    uri: str
    username: str
    database: str = "neo4j"
    namespace: str = "cybertriage"


@dataclass(frozen=True)
class GraphAlert:
    record_id: str
    alert: SecurityAlert
    payload_hash: str
    received_at: str
    active: bool
    first_attached_at: str
    changed_at: str


@dataclass(frozen=True)
class CaseGraphSnapshot:
    case: IncidentCase
    alerts: tuple[GraphAlert, ...]
    relationships_json: str
    relationship_reviews_json: str
    stages_json: str
    stage_reviews_json: str
    history_json: str
    reports_json: str
    snapshot_hash: str
    read_at: str


@dataclass(frozen=True)
class GraphNode:
    key: str
    kind: str
    properties_json: str


@dataclass(frozen=True)
class GraphEdge:
    key: str
    kind: str
    source: str
    target: str
    properties_json: str


@dataclass(frozen=True)
class CaseGraph:
    namespace: str
    case_id: str
    case_key: str
    source_version: int
    snapshot_hash: str
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    timeline_json: str
    stage_summary_json: str
    policy: str = GRAPH_POLICY

    def payload(self) -> dict[str, object]:
        return {"policy": self.policy, "namespace": self.namespace, "case_id": self.case_id,
                "case_key": self.case_key, "source_version": self.source_version, "snapshot_hash": self.snapshot_hash,
                "nodes": [{"key": node.key, "kind": node.kind, "properties": json.loads(node.properties_json)} for node in self.nodes],
                "edges": [{"key": edge.key, "kind": edge.kind, "source": edge.source, "target": edge.target,
                           "properties": json.loads(edge.properties_json)} for edge in self.edges],
                "timeline": json.loads(self.timeline_json), "kill_chain": json.loads(self.stage_summary_json)}

    @property
    def payload_hash(self) -> str:
        return sha256(canonical_json(self.payload()).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GraphProjectionReceipt:
    case_id: str
    namespace: str
    source_version: int
    snapshot_hash: str
    payload_hash: str
    status: Literal["projected", "unchanged"]
    node_count: int
    edge_count: int
    projected_at: str


def canonical_json(value: object) -> str:
    def convert(item: object) -> str:
        if isinstance(item, datetime):
            if item.utcoffset() is None:
                raise GraphError("Graph timestamps require a timezone.")
            return item.isoformat()
        raise TypeError("Unsupported graph value.")
    return json.dumps(value, default=convert, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def graph_key(namespace: str, case_id: str, kind: str, *identity: str) -> str:
    return sha256(canonical_json([namespace, case_id, kind, *identity]).encode("utf-8")).hexdigest()
