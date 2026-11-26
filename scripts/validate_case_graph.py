"""Isolated graph checks using SQLite fixtures and a scripted Neo4j substitute.

Run from the repository root. This does not contact Neo4j, Ollama, Wazuh or the
Indexer. Scripted transactions assess orchestration, not server Cypher support.
"""

import copy
import json
import sqlite3
import traceback
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import validate_cases as fixtures
from cybertriage.adapters.configuration.neo4j_environment import validate_settings
from cybertriage.adapters.storage.case_graph_neo4j import Neo4jCaseGraphSink, OWNER
from cybertriage.adapters.storage.case_graph_sqlite import SqliteCaseGraphReader
from cybertriage.adapters.storage.case_stages_sqlite import SqliteCaseStageRepository
from cybertriage.application.services.case_graph import CaseGraphBuilder, ExportCaseGraph, ProjectCaseGraph
from cybertriage.application.services.case_stages import CaseStages
from cybertriage.domain.case import CaseConflictError, CaseError
from cybertriage.domain.graph import GraphConflictError, GraphError, GraphStorageError, Neo4jSettings

ROOT = Path.cwd() / "data" / "validation" / f"case-graph-{uuid4().hex}"
CHECKS = []
SETTINGS = Neo4jSettings("bolt://127.0.0.1:7687", "projection", namespace="validation")


def check(name):
    def register(function):
        CHECKS.append((name, function))
        return function
    return register


def fixture(name):
    fixtures.ROOT = ROOT
    database, alerts, cases = fixtures.fixture(name)
    first = alerts.save_and_schedule(replace(fixtures.alert(1, event_id=4624, session="0xabc"),
        full_log="SECRET_RAW_LOG_MARKER")).record_id
    second = alerts.save_and_schedule(fixtures.alert(2, event_id=4624, session="0xabc")).record_id
    case = cases.create("Graph validation", "analyst")
    cases.attach(case.case_id, [first, second], "analyst", "Review together without asserting a common attacker.")
    reader = SqliteCaseGraphReader(database)
    stages = CaseStages(SqliteCaseStageRepository(database))
    exporter = ExportCaseGraph(reader, CaseGraphBuilder(), "validation")
    return database, cases, stages, exporter, reader, case.case_id, first, second


def kinds(graph, kind, edges=False):
    return [value for value in (graph.edges if edges else graph.nodes) if value.kind == kind]


@check("Deterministic exports preserve evidence hashes, field roles and chronology without raw logs")
def deterministic():
    db, cases, stages, exporter, reader, case_id, a, b = fixture("deterministic")
    first, second = exporter.execute(case_id), exporter.execute(case_id)
    assert first.payload_hash == second.payload_hash and first.snapshot_hash == second.snapshot_hash
    assert "SECRET_RAW_LOG_MARKER" not in json.dumps(first.payload())
    assert len(kinds(first, "alert")) == 2 and len(kinds(first, "host")) == 1
    assert len(kinds(first, "CT_REPORTS_ACCOUNT", True)) == 2
    assert all(json.loads(edge.properties_json)["role"] == "target" for edge in kinds(first, "CT_REPORTS_ACCOUNT", True))
    assert all(json.loads(edge.properties_json)["field_path"] == "win.eventdata.targetLogonId"
               for edge in kinds(first, "CT_REPORTS_SESSION", True))
    assert len(kinds(first, "CT_NEXT_REPORTED_TIME", True)) == 1
    assert all(row["status"] == "unassessed" for row in json.loads(first.stage_summary_json))
    assert not kinds(first, "CT_OBSERVED_RELATIONSHIP", True)
    assert not kinds(first, "CT_HYPOTHESIZED_RELATIONSHIP", True)


@check("Case and namespace boundaries prevent merging identically reported entities")
def isolation():
    db, cases, stages, exporter, reader, case_id, a, b = fixture("isolation")
    other = cases.create("Second case", "analyst")
    cases.attach(other.case_id, [a], "analyst", "Independent scope.")
    first, second = exporter.execute(case_id), exporter.execute(other.case_id)
    third = ExportCaseGraph(reader, CaseGraphBuilder(), "other").execute(case_id)
    assert not {n.key for n in first.nodes}.intersection(n.key for n in second.nodes)
    assert not {n.key for n in first.nodes}.intersection(n.key for n in third.nodes)


@check("Equal reported timestamps share a bucket without inventing event order")
def equal_times():
    fixtures.ROOT = ROOT
    db, alerts, cases = fixtures.fixture("equal-times")
    a = alerts.save_and_schedule(fixtures.alert(1)).record_id
    b = alerts.save_and_schedule(replace(fixtures.alert(2), timestamp=fixtures.BASE + fixtures.timedelta(seconds=1))).record_id
    case = cases.create("Equal timestamps", "analyst")
    cases.attach(case.case_id, [a, b], "analyst", "Retain tie.")
    graph = ExportCaseGraph(SqliteCaseGraphReader(db), CaseGraphBuilder()).execute(case.case_id)
    assert len(kinds(graph, "time")) == 1 and not kinds(graph, "CT_NEXT_REPORTED_TIME", True)


@check("Accepted hypotheses remain hypotheses; retractions retain assertions and review history")
def relationships():
    db, cases, stages, exporter, reader, case_id, a, b = fixture("relationships")
    observed = cases.relate(case_id, a, b, "observed", "shares_host", "analyst", "Matching host fields.")
    hypothesis = cases.relate(case_id, a, b, "hypothesis", "possibly_related", "analyst", "Needs investigation.", [a, b])
    cases.review_relationship(case_id, hypothesis["relationship_id"], "accepted", cases.get(case_id).version,
                              "reviewer", "Working hypothesis only.")
    graph = exporter.execute(case_id)
    assert len(kinds(graph, "CT_OBSERVED_RELATIONSHIP", True)) == 1
    assert len(kinds(graph, "CT_HYPOTHESIZED_RELATIONSHIP", True)) == 1
    cases.review_relationship(case_id, observed["relationship_id"], "retracted", cases.get(case_id).version,
                              "reviewer", "Remove active assertion but preserve history.")
    graph = exporter.execute(case_id)
    assert not kinds(graph, "CT_OBSERVED_RELATIONSHIP", True)
    assert len(kinds(graph, "relationship")) == 2 and len(kinds(graph, "review")) == 2


@check("Stage commands require evidence and current versions; reviews never confirm compromise")
def stage_boundary():
    db, cases, stages, exporter, reader, case_id, a, b = fixture("stages")
    current = cases.get(case_id).version
    fixtures.expect(CaseError, lambda: stages.add(case_id, "delivery", "hypothesis", [], current, "analyst", "No support"))
    fixtures.expect(CaseError, lambda: stages.add(case_id, "delivery", "hypothesis", ["missing"], current, "analyst", "Wrong scope"))
    fixtures.expect(CaseError, lambda: stages.add(case_id, "unknown", "observed", [a], current, "analyst", "Invalid stage"))
    assertion = stages.add(case_id, "actions_on_objectives", "hypothesis", [a], current, "analyst", "Tentative classification.")
    fixtures.expect(CaseConflictError, lambda: stages.add(case_id, "delivery", "hypothesis", [a], current, "analyst", "Stale version"))
    stages.review(case_id, assertion["assertion_id"], "accepted", cases.get(case_id).version, "reviewer", "Working hypothesis.")
    graph = exporter.execute(case_id)
    summary = json.loads(graph.stage_summary_json)[-1]
    assert summary["hypotheses"] == 1 and summary["analyst_assessments"] == 0
    assert cases.get(case_id).disposition == "unconfirmed"
    assert json.loads(kinds(graph, "stage_assessment")[0].properties_json)["kind"] == "hypothesis"
    cases.detach(case_id, a, cases.get(case_id).version, "analyst", "Remove evidence from active scope.")
    graph = exporter.execute(case_id)
    assert json.loads(graph.stage_summary_json)[-1]["status"] == "unassessed"
    assert len(kinds(graph, "stage_assessment")) == 1
    cases.update(case_id, {"status": "closed"}, cases.get(case_id).version, "analyst", "Close validation case.")
    fixtures.expect(CaseError, lambda: stages.add(case_id, "delivery", "hypothesis", [b], cases.get(case_id).version,
                                                  "analyst", "Closed cases require reopening."))


@check("Report pointers use exact case coverage and append-only stage storage")
def reports_and_audit():
    db, cases, stages, exporter, reader, case_id, a, b = fixture("reports")
    fixtures.SqliteAnalysisWriter(db).save(fixtures.report(a))
    current = cases.get(case_id).version
    stages.add(case_id, "installation", "analyst_assessed", [a], current, "analyst", "Explicit interpretation.")
    graph = exporter.execute(case_id)
    assert len(kinds(graph, "analysis")) == 1 and len(kinds(graph, "CT_COVERS", True)) == 1
    assert "Synthetic report only" not in json.dumps(graph.payload())
    with closing(sqlite3.connect(db)) as connection:
        fixtures.expect(sqlite3.IntegrityError, lambda: connection.execute("DELETE FROM case_stage_assertions"))


@check("Hash corruption and snapshot budgets fail without returning partial graphs")
def integrity():
    db, cases, stages, exporter, reader, case_id, a, b = fixture("integrity")
    with closing(sqlite3.connect(db)) as connection:
        connection.execute("UPDATE alerts SET payload_hash=? WHERE record_id=?", ("0" * 64, a))
        connection.commit()
    fixtures.expect(CaseError, lambda: exporter.execute(case_id))
    import cybertriage.adapters.storage.case_graph_sqlite as storage
    original = storage.MAX_SNAPSHOT_BYTES
    try:
        storage.MAX_SNAPSHOT_BYTES = 1
        fixtures.expect(GraphError, lambda: exporter.execute(case_id))
    finally:
        storage.MAX_SNAPSHOT_BYTES = original


class Result:
    def __init__(self, rows=()):
        self.rows = list(rows)
    def __iter__(self):
        return iter(self.rows)
    def single(self):
        return self.rows[0] if self.rows else None
    def consume(self):
        return None


class Driver:
    """Fixed-query substitute with transaction rollback; never a Cypher emulator."""
    def __init__(self):
        self.nodes, self.edges = {}, {}
        self.fail_after = None
        self.calls = 0
        self.schema = True
    def session(self, **kwargs):
        return self
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def run(self, query, parameters=None):
        if query.startswith("SHOW CONSTRAINTS"):
            return Result([{"name": "cybertriage_graph_key", "type": "UNIQUENESS",
                            "labelsOrTypes": ["CTGraphNode"], "properties": ["key"]}] if self.schema else [])
        self.calls += 1
        if self.fail_after == self.calls:
            raise RuntimeError("Scripted transaction failure")
        p = parameters
        if "MERGE (c:CTGraphNode:CTCase" in query:
            row = self.nodes.setdefault(p["key"], {"key": p["key"], "owner": OWNER, "namespace": p["namespace"],
                "case_key": p["case_key"], "case_id": p["case_id"], "source_version": 0})
            row["_lock_counter"] = row.get("_lock_counter", 0) + 1
            return Result([{**row, "version": row["source_version"], "snapshot_hash": row.get("snapshot_hash"),
                            "payload_hash": row.get("payload_hash"), "projected_at": row.get("projected_at")}])
        if "UNWIND $keys" in query:
            return Result([{"key": key} for key in p["keys"] if key in self.nodes and any(
                self.nodes[key].get(field) != p[field] for field in ("owner", "namespace", "case_key"))][:1])
        if "UNWIND $rows" in query:
            mapping = self.edges if "MERGE (s)-[r:" in query else self.nodes
            for row in p["rows"]:
                previous = mapping.setdefault(row["key"], {})
                previous.update(row["properties"])
                previous.update({key: p[key] for key in ("owner", "namespace", "case_key")})
                previous.update(key=row["key"], projection_hash=p["digest"])
            return Result()
        if "DELETE r" in query or "DELETE n" in query:
            mapping = self.edges if "DELETE r" in query else self.nodes
            for key, row in list(mapping.items()):
                if all(row.get(field) == p[field] for field in ("owner", "namespace", "case_key")) and row.get("projection_hash") != p["digest"] and (mapping is self.edges or key != p["key"]):
                    del mapping[key]
            return Result()
        if "SET c.source_version=" in query:
            self.nodes[p["key"]].update(source_version=p["version"], snapshot_hash=p["snapshot"],
                payload_hash=p["digest"], policy=p["policy"], projected_at=p["now"])
            return Result()
        raise AssertionError("Unrecognized graph adapter query")
    def execute_write(self, function, *args):
        saved = copy.deepcopy((self.nodes, self.edges))
        try:
            return function(self, *args)
        except BaseException:
            self.nodes, self.edges = saved
            raise
    def close(self):
        pass


@check("Publication is logically idempotent and rejects stale or conflicting snapshots")
def versioned_publication():
    db, cases, stages, exporter, reader, case_id, a, b = fixture("publication")
    driver = Driver()
    sink = Neo4jCaseGraphSink(driver, SETTINGS)
    first = exporter.execute(case_id)
    assert sink.publish(first).status == "projected"
    counts = len(driver.nodes), len(driver.edges)
    assert sink.publish(first).status == "unchanged" and counts == (len(driver.nodes), len(driver.edges))
    fixtures.expect(GraphConflictError, lambda: sink.publish(replace(first, snapshot_hash="0" * 64)))
    cases.note(case_id, "Advance case version.", "analyst")
    second = exporter.execute(case_id)
    assert sink.publish(second).status == "projected"
    fixtures.expect(GraphConflictError, lambda: sink.publish(first))
    foreign = ExportCaseGraph(reader, CaseGraphBuilder(), "foreign").execute(case_id)
    fixtures.expect(GraphError, lambda: sink.publish(foreign))


@check("Failed publication rolls back graph writes and never mutates authoritative SQLite")
def atomicity():
    db, cases, stages, exporter, reader, case_id, a, b = fixture("atomicity")
    graph, driver = exporter.execute(case_id), Driver()
    sink = Neo4jCaseGraphSink(driver, SETTINGS)
    driver.fail_after = 4
    fixtures.expect(GraphStorageError, lambda: sink.publish(graph))
    assert driver.nodes == {} and driver.edges == {}
    assert exporter.execute(case_id).payload_hash == graph.payload_hash
    driver.fail_after = None
    sink.publish(graph)
    cases.note(case_id, "New version.", "analyst")
    second = exporter.execute(case_id)
    saved = copy.deepcopy((driver.nodes, driver.edges))
    driver.fail_after = driver.calls + 4
    fixtures.expect(GraphStorageError, lambda: sink.publish(second))
    assert (driver.nodes, driver.edges) == saved


@check("Schema and foreign ownership boundaries fail before overwriting graph data")
def ownership():
    db, cases, stages, exporter, reader, case_id, a, b = fixture("ownership")
    graph, driver = exporter.execute(case_id), Driver()
    sink = Neo4jCaseGraphSink(driver, SETTINGS)
    driver.schema = False
    fixtures.expect(GraphError, lambda: sink.publish(graph))
    assert driver.nodes == {}
    driver.schema = True
    target = next(node.key for node in graph.nodes if node.kind == "host")
    driver.nodes[target] = {"key": target, "owner": "external", "namespace": "other", "case_key": "other"}
    saved = copy.deepcopy(driver.nodes)
    fixtures.expect(GraphConflictError, lambda: sink.publish(graph))
    assert driver.nodes == saved


@check("Concurrent source updates are reported as needs_resync")
def resync():
    db, cases, stages, exporter, reader, case_id, a, b = fixture("resync")
    sink = Neo4jCaseGraphSink(Driver(), SETTINGS)
    class UpdatingSink:
        def publish(self, graph):
            receipt = sink.publish(graph)
            cases.note(case_id, "Arrived after snapshot.", "analyst")
            return receipt
    result = ProjectCaseGraph(exporter, reader, UpdatingSink()).execute(case_id)
    assert result["needs_resync"] and result["current_source_version"] > result["source_version"]


@check("Neo4j configuration rejects insecure remote URLs, embedded credentials and system database")
def configuration():
    for uri in ("bolt://remote.example:7687", "neo4j://localhost:7687", "bolt+ssc://localhost:7687",
                "bolt://user:pass@localhost:7687", "bolt://localhost:0", "bolt://localhost:7687/path", " bolt://localhost"):
        fixtures.expect(GraphError, lambda uri=uri: validate_settings(replace(SETTINGS, uri=uri)))
    fixtures.expect(GraphError, lambda: validate_settings(replace(SETTINGS, database="system")))
    fixtures.expect(GraphError, lambda: validate_settings(replace(SETTINGS, namespace="bad namespace")))
    assert validate_settings(SETTINGS) == SETTINGS
    assert validate_settings(replace(SETTINGS, uri="neo4j+s://graph.example:7687"))


def main():
    ROOT.mkdir(parents=True, exist_ok=False)
    results = []
    print("Isolated validation directory:", ROOT)
    for name, function in CHECKS:
        try:
            function()
            results.append({"name": name, "passed": True})
            print("PASS:", name)
        except Exception as error:
            results.append({"name": name, "passed": False, "error_type": type(error).__name__, "traceback": traceback.format_exc()})
            print(f"FAIL: {name} ({type(error).__name__}: {error})")
    (ROOT / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    failed = sum(not row["passed"] for row in results)
    print(f"SUMMARY: {len(results) - failed}/{len(results)} passed; {failed} failed.")
    raise SystemExit(bool(failed))


if __name__ == "__main__":
    main()
