"""Deterministic graph assembly from stored evidence, never model-generated edges."""

import ipaddress
import json
import re
from dataclasses import asdict
from datetime import timezone

from cybertriage.application.ports.graph import CaseGraphReader, CaseGraphSink
from cybertriage.application.services.case_management import identifier
from cybertriage.domain.graph import (
    CaseGraph, CaseGraphSnapshot, GraphEdge, GraphError, GraphNode, KILL_CHAIN_STAGES,
    MAX_GRAPH_BYTES, MAX_GRAPH_EDGES, MAX_GRAPH_NODES, canonical_json, graph_key,
)

# Storage-independent graph relationship vocabulary; adapters map node kinds to labels.
EDGE_TYPES = frozenset({"CT_HAS_ALERT", "CT_REPORTED_ON", "CT_REPORTS_ACCOUNT", "CT_REPORTS_ADDRESS",
    "CT_REPORTS_PROCESS", "CT_REPORTS_SESSION", "CT_HAS_ASSERTION", "CT_SOURCE", "CT_TARGET", "CT_SUPPORTED_BY",
    "CT_OBSERVED_RELATIONSHIP", "CT_HYPOTHESIZED_RELATIONSHIP", "CT_HAS_REVIEW", "CT_HAS_HISTORY",
    "CT_HAS_ANALYSIS", "CT_COVERS", "CT_IN_TIME_BUCKET", "CT_NEXT_REPORTED_TIME", "CT_HAS_STAGE",
    "CT_FRAMEWORK_NEXT", "CT_HAS_STAGE_ASSESSMENT", "CT_ASSESSES_STAGE"})


def namespace_name(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
        raise GraphError("Graph namespace must be 1..64 letters, digits, underscores or hyphens.")
    return value


class CaseGraphBuilder:
    def build(self, snapshot: CaseGraphSnapshot, namespace: str) -> CaseGraph:
        namespace = namespace_name(namespace)
        case = snapshot.case
        nodes: dict[str, GraphNode] = {}
        edges: dict[str, GraphEdge] = {}

        def node(kind: str, identity: str, properties: dict) -> str:
            key = graph_key(namespace, case.case_id, kind, identity)
            value = GraphNode(key, kind, canonical_json(properties))
            if key in nodes and nodes[key] != value:
                raise GraphError("Conflicting properties for one graph identity.")
            nodes[key] = value
            if len(nodes) > MAX_GRAPH_NODES:
                raise GraphError("Graph node budget exceeded.")
            return key

        def edge(kind: str, source: str, target: str, identity: str = "", **properties):
            if kind not in EDGE_TYPES or source not in nodes or target not in nodes:
                raise GraphError("Invalid graph edge.")
            key = graph_key(namespace, case.case_id, kind, source, target, identity)
            value = GraphEdge(key, kind, source, target, canonical_json(properties))
            if key in edges and edges[key] != value:
                raise GraphError("Conflicting properties for one graph edge.")
            edges[key] = value
            if len(edges) > MAX_GRAPH_EDGES:
                raise GraphError("Graph edge budget exceeded.")

        root = node("case", case.case_id, asdict(case))
        alerts = {item.record_id: item for item in snapshot.alerts}
        alert_nodes = {}
        times: dict[str, list[str]] = {}
        for item in snapshot.alerts:
            alert = item.alert
            timestamp = alert.timestamp.astimezone(timezone.utc).isoformat()
            key = node("alert", item.record_id, {"record_id": item.record_id, "source_alert_id": alert.source_alert_id,
                "source_instance": alert.source_instance, "timestamp": timestamp, "timestamp_basis": "Wazuh alert timestamp",
                "agent_id": alert.agent_id, "agent_name": alert.agent_name, "rule_id": alert.rule_id,
                "rule_level": alert.rule_level, "description": alert.description, "active": item.active,
                "payload_sha256": item.payload_hash, "received_at": item.received_at,
                "mitre_ids": list(alert.mitre_ids), "event_json": canonical_json(asdict(alert.event)) if alert.event else "null"})
            alert_nodes[item.record_id] = key
            edge("CT_HAS_ALERT", root, key, active=item.active, first_attached_at=item.first_attached_at, changed_at=item.changed_at)
            # Labels are observations, not a machine inventory or an assertion of ownership.
            host_identity = canonical_json([alert.source_instance, alert.agent_id])
            host = node("host", host_identity, {"source_instance": alert.source_instance, "agent_id": alert.agent_id})
            edge("CT_REPORTED_ON", key, host, reported_agent_name=alert.agent_name)
            data = json.loads(alert.decoded_data_json)
            if not isinstance(data, dict):
                raise GraphError("Decoded alert data must be an object.")

            def field(path: str) -> str | None:
                value = data
                for part in path.split("."):
                    if not isinstance(value, dict):
                        return None
                    value = value.get(part)
                if not isinstance(value, str) or not value.strip() or value.strip() == "-":
                    return None
                if len(value.encode("utf-8")) > 512:
                    raise GraphError("A graph identity field exceeds 512 UTF-8 bytes.")
                return value  # Preserve exact reported identity, including case.

            for role in ("target", "subject"):
                path = f"win.eventdata.{role}UserName"
                name = field(path)
                domain = field(f"win.eventdata.{role}DomainName")
                if name:
                    scope = canonical_json([alert.source_instance, domain or "", host_identity if not domain else ""])
                    account = node("account", canonical_json([scope, name]), {"name": name, "domain": domain or "",
                        "scope": scope, "interpretation": "Reported account fields; not an authenticated person identity."})
                    edge("CT_REPORTS_ACCOUNT", key, account, path, field_path=path, role=role)
            for path in ("dstuser", "srcuser", "win.eventdata.user", "win.eventdata.sourceUser", "win.eventdata.targetUser"):
                value = field(path)
                if value:
                    account = node("account", canonical_json([host_identity, path, value]), {"name": value,
                        "scope": host_identity, "field_path": path, "interpretation": "Raw reported identity; no domain or operator inferred."})
                    edge("CT_REPORTS_ACCOUNT", key, account, path, field_path=path, role="reported")
            for path in ("srcip", "dstip", "win.eventdata.ipAddress", "win.eventdata.sourceIp", "win.eventdata.destinationIp"):
                value = field(path)
                if not value:
                    continue
                try:
                    address = ipaddress.ip_address(value)
                except ValueError:
                    continue
                scope = host_identity if address.is_loopback or address.is_link_local or address.is_unspecified else alert.source_instance
                target = node("address", canonical_json([scope, str(address)]), {"address": str(address), "scope": scope})
                edge("CT_REPORTS_ADDRESS", key, target, path, field_path=path, interpretation="Reported field, not attacker attribution.")
            for name in ("processGuid", "parentProcessGuid", "sourceProcessGUID", "targetProcessGUID",
                         "processId", "newProcessId", "parentProcessId", "sourceProcessId", "targetProcessId"):
                path = f"win.eventdata.{name}"
                value = field(path)
                if value:
                    scope = host_identity if "guid" in name.lower() else item.record_id
                    target = node("process", canonical_json([scope, "guid" if "guid" in name.lower() else "pid", value]),
                        {"value": value, "scope": scope, "identifier_type": "guid" if "guid" in name.lower() else "pid",
                         "limitation": "Reported identifier; a PID is scoped to this alert to avoid PID reuse."})
                    edge("CT_REPORTS_PROCESS", key, target, path, field_path=path)
            if alert.event and alert.event.provider == "Microsoft-Windows-Security-Auditing" and alert.event.channel == "Security" and alert.event.event_id != 4625:
                for name in ("targetLogonId", "subjectLogonId"):
                    path = f"win.eventdata.{name}"
                    value = field(path)
                    if value and re.fullmatch(r"0x[0-9a-fA-F]+", value) and int(value, 16) != 0:
                        target = node("session", canonical_json([host_identity, value.lower()]), {"value": value.lower(),
                            "scope": host_identity, "limitation": "Reported logon identifier; may be reused after reboot. Role remains on edge."})
                        edge("CT_REPORTS_SESSION", key, target, path, field_path=path,
                             role="target" if name == "targetLogonId" else "subject")
            times.setdefault(timestamp, []).append(item.record_id)

        timeline = []
        previous = None
        for timestamp, ids in sorted(times.items()):
            bucket = node("time", timestamp, {"timestamp": timestamp, "basis": "Wazuh reported alert time; not causal order"})
            for record_id in sorted(ids):
                edge("CT_IN_TIME_BUCKET", alert_nodes[record_id], bucket, active=alerts[record_id].active)
            if previous:
                edge("CT_NEXT_REPORTED_TIME", previous, bucket, interpretation="Chronology only; not an attack step or causation.")
            previous = bucket
            timeline.append({"timestamp": timestamp, "alert_record_ids": sorted(ids)})

        def support_links(assertion_key, ids):
            if not isinstance(ids, list) or not ids or any(value not in alerts for value in ids):
                raise GraphError("Assertion references evidence outside this case snapshot.")
            for record_id in ids:
                edge("CT_SUPPORTED_BY", assertion_key, alert_nodes[record_id], active=alerts[record_id].active)
            return all(alerts[value].active for value in ids)

        def reviews(values, id_name):
            grouped = {}
            for row in values:
                grouped.setdefault(row[id_name], []).append(row)
            return grouped

        def review_nodes(assertion_key, values, family):
            for row in values:
                review = node("review", f"{family}:{row['seq']}", row)
                edge("CT_HAS_REVIEW", assertion_key, review)

        relationship_reviews = reviews(json.loads(snapshot.relationship_reviews_json), "relationship_id")
        for row in json.loads(snapshot.relationships_json):
            row = dict(row)
            ids = json.loads(row.pop("supporting_ids_json"))
            source, target = row["source_alert_id"], row["target_alert_id"]
            if source not in alerts or target not in alerts:
                raise GraphError("Relationship endpoints are not in the case snapshot.")
            history = relationship_reviews.get(row["relationship_id"], [])
            status = history[-1]["decision"] if history else ("recorded" if row["kind"] == "observed" else "proposed")
            proof = json.loads(row["proof_json"])
            if row["kind"] == "observed" and (proof.get("source_payload_sha256") != alerts[source].payload_hash
                    or proof.get("target_payload_sha256") != alerts[target].payload_hash):
                raise GraphError("Observed relationship proof does not match stored evidence hashes.")
            assertion = node("relationship", row["relationship_id"], {**row, "review_status": status})
            edge("CT_HAS_ASSERTION", root, assertion)
            edge("CT_SOURCE", assertion, alert_nodes[source])
            edge("CT_TARGET", assertion, alert_nodes[target])
            active_support = support_links(assertion, ids)
            review_nodes(assertion, history, "relationship")
            if status not in {"rejected", "retracted", "superseded"} and active_support and alerts[source].active and alerts[target].active:
                edge("CT_OBSERVED_RELATIONSHIP" if row["kind"] == "observed" else "CT_HYPOTHESIZED_RELATIONSHIP",
                     alert_nodes[source], alert_nodes[target], row["relationship_id"], assertion_key=assertion,
                     predicate=row["predicate"], review_status=status, interpretation="Case assertion; kind preserved on review.")

        stage_nodes, summaries = {}, {}
        previous = None
        for order, (stage_id, title) in enumerate(KILL_CHAIN_STAGES, 1):
            target = node("stage", stage_id, {"stage": stage_id, "title": title, "order": order,
                "framework": "Lockheed Martin Cyber Kill Chain", "interpretation": "Reference framework; not evidence that this stage occurred."})
            edge("CT_HAS_STAGE", root, target)
            if previous:
                edge("CT_FRAMEWORK_NEXT", previous, target, interpretation="Framework order, not an observed attack path.")
            previous = target
            stage_nodes[stage_id] = target
            summaries[stage_id] = {"stage": stage_id, "title": title, "status": "unassessed", "hypotheses": 0, "analyst_assessments": 0}
        stage_reviews = reviews(json.loads(snapshot.stage_reviews_json), "assertion_id")
        for row in json.loads(snapshot.stages_json):
            row = dict(row)
            ids = json.loads(row.pop("supporting_ids_json"))
            if row["stage"] not in stage_nodes or row["kind"] not in {"hypothesis", "analyst_assessed"}:
                raise GraphError("Invalid stored Kill Chain assessment.")
            history = stage_reviews.get(row["assertion_id"], [])
            status = history[-1]["decision"] if history else ("proposed" if row["kind"] == "hypothesis" else "recorded")
            assertion = node("stage_assessment", row["assertion_id"], {**row, "review_status": status})
            edge("CT_HAS_STAGE_ASSESSMENT", root, assertion)
            active_support = support_links(assertion, ids)
            active = active_support and status not in {"rejected", "retracted", "superseded"}
            edge("CT_ASSESSES_STAGE", assertion, stage_nodes[row["stage"]], active=active, assessment_kind=row["kind"], review_status=status)
            review_nodes(assertion, history, "stage")
            if active:
                summary = summaries[row["stage"]]
                summary["status"] = "assessed"
                summary["hypotheses" if row["kind"] == "hypothesis" else "analyst_assessments"] += 1
        for row in json.loads(snapshot.history_json):
            target = node("history", row["event_id"], row)
            edge("CT_HAS_HISTORY", root, target)
        for row in json.loads(snapshot.reports_json):
            row = dict(row)
            coverage = row.pop("covered_alert_ids")
            inside = [value for value in coverage if value in alerts]
            target = node("analysis", row["analysis_id"], {**row, "outside_case_coverage_count": len(coverage) - len(inside),
                "interpretation": "Stored provisional report pointer, not a confirmed finding."})
            edge("CT_HAS_ANALYSIS", root, target)
            for record_id in inside:
                edge("CT_COVERS", target, alert_nodes[record_id], active=alerts[record_id].active)
        graph = CaseGraph(namespace, case.case_id, root, case.version, snapshot.snapshot_hash,
            tuple(nodes[key] for key in sorted(nodes)), tuple(edges[key] for key in sorted(edges)),
            canonical_json(timeline), canonical_json(list(summaries.values())))
        if len(canonical_json(graph.payload()).encode("utf-8")) > MAX_GRAPH_BYTES:
            raise GraphError("Graph payload exceeds 16 MiB; no partial graph is returned.")
        return graph


class ExportCaseGraph:
    def __init__(self, reader: CaseGraphReader, builder: CaseGraphBuilder, namespace: str = "cybertriage"):
        self._reader, self._builder, self._namespace = reader, builder, namespace_name(namespace)

    def execute(self, case_id: str) -> CaseGraph:
        return self._builder.build(self._reader.snapshot(identifier(case_id)), self._namespace)


class ProjectCaseGraph:
    def __init__(self, exporter: ExportCaseGraph, reader: CaseGraphReader, sink: CaseGraphSink):
        self._exporter, self._reader, self._sink = exporter, reader, sink

    def execute(self, case_id: str) -> dict:
        return self.publish(self._exporter.execute(case_id))

    def publish(self, graph: CaseGraph) -> dict:
        """Publish a prepared immutable snapshot, then check for newer SQLite changes."""
        receipt = self._sink.publish(graph)
        current = self._reader.current_version(graph.case_id)
        return {**asdict(receipt), "current_source_version": current, "needs_resync": current != graph.source_version}
