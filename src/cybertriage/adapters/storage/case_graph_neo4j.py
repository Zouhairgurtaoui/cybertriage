"""Atomic, version-checked publication to an optional dedicated Neo4j projection."""

import importlib
import re
from datetime import datetime, timezone
from typing import Any

from cybertriage.adapters.configuration.neo4j_environment import validate_settings
from cybertriage.application.services.case_graph import EDGE_TYPES
from cybertriage.domain.graph import (CaseGraph, GraphConflictError, GraphError, GraphProjectionReceipt,
    GraphStorageError, MAX_GRAPH_BYTES, MAX_GRAPH_EDGES, MAX_GRAPH_NODES, Neo4jSettings, canonical_json, graph_key)

CONSTRAINT_NAME = "cybertriage_graph_key"
OWNER = "cybertriage-case-projection"
NODE_LABELS = {
    "case": "CTCase", "alert": "CTAlert", "host": "CTHost", "account": "CTAccount",
    "address": "CTAddress", "process": "CTProcessIdentifier", "session": "CTSessionIdentifier",
    "relationship": "CTAssertion", "review": "CTReview", "history": "CTCaseEvent",
    "analysis": "CTAnalysis", "time": "CTTimeBucket", "stage": "CTKillChainStage",
    "stage_assessment": "CTStageAssessment",
}
RESERVED = frozenset({"key", "namespace", "case_key", "projection_hash", "owner", "source_version",
    "snapshot_hash", "payload_hash", "policy", "projected_at", "_lock_counter"})


class Neo4jCaseGraphSink:
    def __init__(self, driver: Any, settings: Neo4jSettings):
        self._driver, self._settings = driver, validate_settings(settings)
        self._transaction = self._publish

    @classmethod
    def connect(cls, settings: Neo4jSettings, password: str):
        settings = validate_settings(settings)
        if not isinstance(password, str) or not 1 <= len(password) <= 1024 or any(ord(c) < 32 for c in password):
            raise GraphError("A valid Neo4j password is required.")
        try:
            module = importlib.import_module("neo4j")
        except ImportError as error:
            raise GraphError('Install the optional graph dependency: python -m pip install -e ".[graph]"') from error
        driver = module.GraphDatabase.driver(settings.uri, auth=(settings.username, password),
            connection_timeout=5, connection_acquisition_timeout=10, max_transaction_retry_time=10,
            max_connection_pool_size=4)
        sink = cls(driver, settings)
        sink._transaction = module.unit_of_work(timeout=30)(cls._publish)
        return sink

    def close(self) -> None:
        self._driver.close()

    def initialize_schema(self) -> None:
        try:
            with self._driver.session(database=self._settings.database) as session:
                session.run("CREATE CONSTRAINT cybertriage_graph_key IF NOT EXISTS FOR (n:CTGraphNode) REQUIRE n.key IS UNIQUE").consume()
                self._require_schema(session)
        except GraphError:
            raise
        except Exception as error:
            raise GraphStorageError("Neo4j schema initialization failed; check connectivity and schema privileges.") from error

    @staticmethod
    def _require_schema(session: Any) -> None:
        records = session.run("SHOW CONSTRAINTS YIELD name, type, labelsOrTypes, properties RETURN name,type,labelsOrTypes,properties")
        if not any(row["name"] == CONSTRAINT_NAME and row["labelsOrTypes"] == ["CTGraphNode"] and row["properties"] == ["key"]
                   and row["type"] in {"UNIQUENESS", "NODE_PROPERTY_UNIQUENESS"} for row in records):
            raise GraphError("Required graph uniqueness constraint is missing or incompatible; run graph-schema.")

    def publish(self, graph: CaseGraph) -> GraphProjectionReceipt:
        payload = self._validate(graph)
        digest = graph.payload_hash
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._driver.session(database=self._settings.database) as session:
                self._require_schema(session)
                # Retry callbacks contain only deterministic graph writes; SQLite is never mutated here.
                return session.execute_write(self._transaction, graph, payload, digest, now)
        except (GraphError, GraphStorageError):
            raise
        except Exception as error:
            # Do not print driver messages that may expose infrastructure or submitted properties.
            raise GraphStorageError("Neo4j publication failed; no partial projection was accepted.") from error

    def _validate(self, graph: CaseGraph) -> dict:
        if graph.namespace != self._settings.namespace or graph.case_key != graph_key(graph.namespace, graph.case_id, "case", graph.case_id):
            raise GraphError("Graph namespace or case key does not match this projection sink.")
        if type(graph.source_version) is not int or graph.source_version < 1:
            raise GraphError("Graph source version must be positive.")
        if len(graph.nodes) > MAX_GRAPH_NODES or len(graph.edges) > MAX_GRAPH_EDGES:
            raise GraphError("Graph projection exceeds its node/edge budget.")
        payload = graph.payload()
        if len(canonical_json(payload).encode("utf-8")) > MAX_GRAPH_BYTES:
            raise GraphError("Graph projection exceeds 16 MiB.")
        keys = set()
        case_nodes = []
        for node in payload["nodes"]:
            if node["kind"] not in NODE_LABELS or not re.fullmatch(r"[a-f0-9]{64}", node["key"]) or node["key"] in keys:
                raise GraphError("Invalid or duplicate graph node.")
            keys.add(node["key"])
            if node["kind"] == "case":
                case_nodes.append(node["key"])
            self._properties(node["properties"])
        if case_nodes != [graph.case_key]:
            raise GraphError("Projection requires exactly its own case root.")
        edge_keys = set()
        for edge in payload["edges"]:
            if edge["kind"] not in EDGE_TYPES or edge["source"] not in keys or edge["target"] not in keys or edge["key"] in edge_keys or not re.fullmatch(r"[a-f0-9]{64}", edge["key"]):
                raise GraphError("Invalid or duplicate graph edge.")
            edge_keys.add(edge["key"])
            self._properties(edge["properties"])
        return payload

    @staticmethod
    def _properties(properties: dict) -> None:
        if not isinstance(properties, dict) or RESERVED.intersection(properties):
            raise GraphError("Projection properties use reserved storage keys.")
        for value in properties.values():
            if value is None or type(value) in {str, int, float, bool}:
                continue
            if isinstance(value, list) and (not value or (type(value[0]) in {str, int, float, bool} and all(type(v) is type(value[0]) for v in value))):
                continue
            raise GraphError("Neo4j properties must be scalars or homogeneous scalar lists.")

    @staticmethod
    def _publish(tx: Any, graph: CaseGraph, payload: dict, digest: str, now: str) -> GraphProjectionReceipt:
        base = {"key": graph.case_key, "namespace": graph.namespace, "case_key": graph.case_key,
                "case_id": graph.case_id, "owner": OWNER, "digest": digest}
        root = tx.run("""MERGE (c:CTGraphNode:CTCase {key:$key})
            ON CREATE SET c.owner=$owner,c.namespace=$namespace,c.case_key=$case_key,c.case_id=$case_id,c.source_version=0
            SET c._lock_counter=coalesce(c._lock_counter,0)+1
            RETURN c.source_version AS version,c.snapshot_hash AS snapshot_hash,c.payload_hash AS payload_hash,
                   c.projected_at AS projected_at,c.owner AS owner,c.namespace AS namespace,c.case_id AS case_id""", base).single()
        if root is None or root["owner"] != OWNER or root["namespace"] != graph.namespace or root["case_id"] != graph.case_id:
            raise GraphConflictError("Existing graph root belongs to a different projection owner or case.")
        if root["version"] > graph.source_version:
            raise GraphConflictError("A newer case version is already projected; export the current case.")
        if root["version"] == graph.source_version:
            if root["snapshot_hash"] != graph.snapshot_hash or root["payload_hash"] != digest:
                raise GraphConflictError("Conflicting content for an already projected case version.")
            return GraphProjectionReceipt(graph.case_id, graph.namespace, graph.source_version, graph.snapshot_hash,
                digest, "unchanged", len(graph.nodes), len(graph.edges), root["projected_at"])
        keys = [row["key"] for row in payload["nodes"]]
        for offset in range(0, len(keys), 250):
            conflict = tx.run("""UNWIND $keys AS key MATCH (n:CTGraphNode {key:key})
                WHERE n.owner IS NULL OR n.owner<>$owner OR n.namespace IS NULL OR n.namespace<>$namespace
                   OR n.case_key IS NULL OR n.case_key<>$case_key RETURN n.key AS key LIMIT 1""",
                {**base, "keys": keys[offset:offset + 250]}).single()
            if conflict is not None:
                raise GraphConflictError("A graph node belongs to another projection owner or case.")
        for kind, label in NODE_LABELS.items():
            values = [row for row in payload["nodes"] if row["kind"] == kind]
            for offset in range(0, len(values), 250):
                tx.run(f"""UNWIND $rows AS row MERGE (n:CTGraphNode {{key:row.key}})
                    SET n:{label} SET n += row.properties,
                        n.owner=$owner,n.namespace=$namespace,n.case_key=$case_key,n.projection_hash=$digest""",
                    {**base, "rows": values[offset:offset + 250]}).consume()
        for kind in sorted(EDGE_TYPES):
            values = [row for row in payload["edges"] if row["kind"] == kind]
            for offset in range(0, len(values), 250):
                tx.run(f"""UNWIND $rows AS row MATCH (s:CTGraphNode {{key:row.source}}),(t:CTGraphNode {{key:row.target}})
                    MERGE (s)-[r:{kind} {{key:row.key}}]->(t) SET r += row.properties,
                        r.owner=$owner,r.namespace=$namespace,r.case_key=$case_key,r.projection_hash=$digest""",
                    {**base, "rows": values[offset:offset + 250]}).consume()
        # Only this adapter's case-owned projection is replaceable; authoritative history stays in SQLite.
        tx.run("""MATCH ()-[r]->() WHERE r.owner=$owner AND r.namespace=$namespace AND r.case_key=$case_key
            AND (r.projection_hash IS NULL OR r.projection_hash<>$digest) DELETE r""", base).consume()
        # DELETE (not DETACH DELETE) fails on unexpected external edges and rolls the transaction back.
        tx.run("""MATCH (n:CTGraphNode) WHERE n.owner=$owner AND n.namespace=$namespace AND n.case_key=$case_key
            AND n.key<>$key AND (n.projection_hash IS NULL OR n.projection_hash<>$digest) DELETE n""", base).consume()
        tx.run("""MATCH (c:CTGraphNode {key:$key}) SET c.source_version=$version,c.snapshot_hash=$snapshot,
            c.payload_hash=$digest,c.policy=$policy,c.projected_at=$now""",
            {**base, "version": graph.source_version, "snapshot": graph.snapshot_hash, "policy": graph.policy, "now": now}).consume()
        return GraphProjectionReceipt(graph.case_id, graph.namespace, graph.source_version, graph.snapshot_hash,
            digest, "projected", len(graph.nodes), len(graph.edges), now)
