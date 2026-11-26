"""Offline related-event boundaries. Run from the project root, without -O.

Uses in-memory Indexer/model substitutes and a fresh ignored SQLite fixture.
Never connects to Wazuh, Ollama, the internet, or the operational database.
"""

import copy
import json
import sqlite3
import time
import traceback
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast
from uuid import uuid4

from langchain_core.messages import AIMessage
from langchain_ollama import ChatOllama

from cybertriage.adapters.models.investigation import OllamaInvestigationModel
from cybertriage.adapters.storage.alerts_sqlite import SqliteAlertRepository
from cybertriage.adapters.storage.analyses_sqlite import SqliteAnalysisWriter
from cybertriage.adapters.storage.jobs_sqlite import SqliteAnalysisQueue
from cybertriage.adapters.tools.related_events import build_related_event_search_tool
from cybertriage.adapters.wazuh.indexer_http import WazuhIndexerHttpClient
from cybertriage.adapters.wazuh.related_event_mapping import parse_related_event_response
from cybertriage.adapters.wazuh.related_event_query import build_related_event_query
from cybertriage.adapters.wazuh.related_event_search import WazuhRelatedEventSearcher
from cybertriage.application.policies.related_event_summary import related_event_summary
from cybertriage.application.policies.stored_investigation import ReadOnlyStoredInvestigationPlanner
from cybertriage.application.use_cases.analyze_alert import AnalyzeAlert
from cybertriage.application.use_cases.process_analysis_job import ProcessAnalysisJob
from cybertriage.domain.alert import SecurityAlert
from cybertriage.domain.investigation import InvestigationSearchError
from cybertriage.domain.related_events import InvestigationScope, RelatedEventScope, RelatedEventSearchRequest
from cybertriage.domain.security_event import EventIdentity

ROOT = Path.cwd() / "data" / "validation" / f"related-events-{uuid4().hex}"
START = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
END = START + timedelta(minutes=10)
CHECKS = []


def check(name):
    def decorate(function):
        CHECKS.append((name, function))
        return function
    return decorate


def expect(error_type, operation):
    try:
        operation()
    except error_type:
        return
    raise AssertionError(f"Expected {error_type.__name__}")


def request(**overrides):
    return RelatedEventSearchRequest(**({"source_instance": "fixture-manager", "agent_id": "001", "start": START, "end": END, "limit": 3} | overrides))


def hit(number=1, *, event_id=4728, sysmon=False):
    return {"_index": "wazuh-alerts-4.x-fixture", "_id": f"document-{number}", "_source": {
        "id": f"fixture-alert-{number}", "timestamp": (START + timedelta(seconds=number)).isoformat(),
        "manager": {"name": "fixture-manager"}, "agent": {"id": "001", "name": "fixture-host"},
        "rule": {"id": "fixture-rule", "level": 8, "description": "Synthetic source event."},
        "data": {"win": {
            "system": {"providerName": "Microsoft-Windows-Sysmon" if sysmon else "Microsoft-Windows-Security-Auditing",
                       "channel": "Microsoft-Windows-Sysmon/Operational" if sysmon else "Security", "eventID": str(event_id), "eventRecordID": str(number)},
            "eventdata": {"targetUserName": "Domain Admins", "targetDomainName": "CORP",
                          "subjectUserName": "admin-service", "subjectDomainName": "CORP",
                          "memberName": "CN=alice,DC=corp,DC=local", "ipAddress": "10.0.2.5"}}}}}


def payload(*hits):
    return {"hits": {"hits": list(hits)}}


class FakeClient:
    def __init__(self, response=None, failure=False):
        self.response = response if response is not None else payload(hit())
        self.failure = failure
        self.calls = []

    def search_alerts(self, query, *, max_hits):
        self.calls.append((query, max_hits))
        if self.failure:
            raise InvestigationSearchError("Synthetic source failure")
        return copy.deepcopy(self.response)


def searcher(client):
    return WazuhRelatedEventSearcher(cast(WazuhIndexerHttpClient, client))


def scope(**overrides):
    return RelatedEventScope(**({"hosts": (("fixture-manager", "001"),), "start": START, "end": END} | overrides))


def args(**overrides):
    return {"source_instance": "fixture-manager", "agent_id": "001", "start": START.isoformat(), "end": END.isoformat()} | overrides


def call(tool, arguments):
    return tool.invoke({"name": "search_related_events", "args": arguments, "id": uuid4().hex, "type": "tool_call"})


@check("Invalid identities, intervals, limits and incomplete filters fail before search")
def invalid_requests():
    for values in ({"limit": True}, {"limit": 101}, {"family": "invented"}, {"source_instance": "-"},
                   {"agent_id": " bad "}, {"start": START.replace(tzinfo=None)}, {"end": START},
                   {"end": START + timedelta(hours=25)}, {"account_name": "alice"}, {"source_ip": "bad-ip"}, {"source_ip": "fe80::1%eth0"},
                   {"process_guid": "not-a-guid"}, {"logon_id": "0x0"}):
        options = dict(source_instance="fixture-manager", agent_id="001", start=START, end=END)
        options.update(values)
        expect(ValueError, lambda: RelatedEventSearchRequest(**options))


@check("Queries always retain manager, agent and exclusive-end interval; values cannot add query operators")
def query_authority():
    value = request(account_name='alice" OR *', account_domain="CORP")
    query = build_related_event_query(value)
    filters = query["query"]["bool"]["filter"]
    assert {"term": {"manager.name": "fixture-manager"}} in filters
    assert {"term": {"agent.id": "001"}} in filters
    assert {"range": {"timestamp": {"gte": START.isoformat(), "lt": END.isoformat()}}} in filters
    assert query["size"] == 4 and query["track_total_hits"] is False
    assert "query_string" not in json.dumps(query)


@check("Process profiles match provider/channel/event together rather than numeric ID alone")
def process_identity():
    value = request(family="process_activity")
    expect(InvestigationSearchError, lambda: parse_related_event_response(payload(hit(event_id=1)), value))
    result = parse_related_event_response(payload(hit(event_id=1, sysmon=True)), value)
    assert result.events[0].event.provider == "Microsoft-Windows-Sysmon"


@check("Host, manager, time and family mismatches are errors, including the lookahead hit")
def returned_scope():
    variants = []
    item = hit(); item["_source"]["agent"]["id"] = "002"; variants.append(item)
    item = hit(); item["_source"]["manager"]["name"] = "another-manager"; variants.append(item)
    item = hit(); item["_source"]["timestamp"] = END.isoformat(); variants.append(item)
    item = hit(); item["_index"] = "wazuh-archives-fixture"; variants.append(item)
    item = hit(); item["_source"]["data"] = "malformed"; variants.append(item)
    for item in variants:
        expect(InvestigationSearchError, lambda: parse_related_event_response(payload(item), request()))
    expect(InvestigationSearchError, lambda: parse_related_event_response(payload(hit(), variants[0]), replace(request(), limit=1)))
    expect(InvestigationSearchError, lambda: parse_related_event_response(payload(hit()), request(family="process_activity")))


@check("Account filters preserve target and initiating roles without crossing domain/name pairs")
def account_roles():
    value = request(account_name="alice", account_domain="CORP")
    item = hit()
    item["_source"]["data"]["win"]["eventdata"].update(targetUserName="alice", targetDomainName="OTHER", subjectUserName="bob")
    expect(InvestigationSearchError, lambda: parse_related_event_response(payload(item), value))
    item["_source"]["data"]["win"]["eventdata"].update(subjectUserName="alice")
    result = parse_related_event_response(payload(item), value)
    fields = {row.path: row.value for row in result.events[0].fields}
    assert fields["data.win.eventdata.subjectUserName"] == "alice"
    assert fields["data.win.eventdata.targetDomainName"] == "OTHER"
    item["_source"]["data"]["win"]["eventdata"] = {"user": "CORP\\alice"}
    assert parse_related_event_response(payload(item), value).events


@check("IP, exact process GUID and nonzero logon filters are independently checked")
def pivots():
    guid = "{00000000-0000-0000-0000-000000000001}"
    item = hit()
    item["_source"]["data"]["win"]["eventdata"].update(processGuid=guid, subjectLogonId="0x123", ipAddress="::ffff:10.0.2.5")
    value = request(source_ip="10.0.2.5", process_guid=guid, logon_id="0x123")
    assert parse_related_event_response(payload(item), value).events
    expect(InvestigationSearchError, lambda: parse_related_event_response(payload(item), replace(value, logon_id="0x124")))
    expect(InvestigationSearchError, lambda: parse_related_event_response(payload(item), replace(value, source_ip="10.0.2.6")))


@check("Provenance, bounded field projections, omissions and truncation remain explicit")
def projection():
    item = hit(event_id=1, sysmon=True)
    item["_source"]["data"]["win"]["eventdata"].update(commandLine="x" * 5000, parentCommandLine="y" * 5000, user="CORP\\alice", image="a" * 5000)
    result = parse_related_event_response(payload(item), request())
    event = result.events[0]
    assert len(event.selected_source_sha256) == 64 and event.document_id == "document-1"
    assert any(row.truncated for row in event.fields)
    assert related_event_summary(result)["projection_truncated"] is True
    assert sum(len(row.value.encode("utf-8")) for row in event.fields) <= 3000


@check("Duplicate source identities collapse; conflicting content is not hidden by truncation")
def duplicates():
    first = hit(); duplicate = copy.deepcopy(first); duplicate["_id"] = "duplicate-index-document"
    result = parse_related_event_response(payload(first, duplicate), request())
    assert len(result.events) == 1
    duplicate["_source"]["data"]["win"]["eventdata"]["commandLine"] = "changed"
    expect(InvestigationSearchError, lambda: parse_related_event_response(payload(first, duplicate), request()))
    result = parse_related_event_response(payload(hit(1), hit(2)), replace(request(), limit=1))
    assert result.has_more and len(result.events) == 1


@check("General host alerts support non-Windows evidence without inventing an event identity")
def generic_alerts():
    item = hit()
    item["_source"]["data"] = {"srcip": "10.0.2.5", "dstuser": "alice"}
    item["_source"]["decoder"] = {"name": "sshd"}
    assert parse_related_event_response(payload(item), request()).events[0].event is None
    expect(InvestigationSearchError, lambda: parse_related_event_response(payload(item), request(family="account_changes")))


@check("Missing authority and identity/window/family/limit expansion never reach the source")
def tool_scope():
    client = FakeClient()
    tool = build_related_event_search_tool(searcher(client), scope=scope(families=("all",), max_results=3))
    for values in ({"agent_id": "002"}, {"source_instance": "another-manager"}, {"start": (START - timedelta(seconds=1)).isoformat()},
                   {"family": "process_activity"}, {"limit": 4}):
        arguments = args(); arguments.update(values)
        result = call(tool, arguments)
        assert result.status == "error" and json.loads(result.content)["code"] == "outside_scope"
    result = call(build_related_event_search_tool(searcher(client), scope=None), args())
    assert json.loads(result.content)["code"] == "scope_required" and not client.calls


@check("Invalid model arguments are errors without querying; source failures are not empty successes")
def tool_errors():
    client = FakeClient()
    tool = build_related_event_search_tool(searcher(client), scope=scope())
    for values in ({"limit": True}, {"limit": 11}, {"unexpected": "ignored?"}, {"start": "2026-01-01T12:00:00"}, {"account_name": "alice"}):
        arguments = args(); arguments.update(values)
        result = call(tool, arguments)
        assert result.status == "error" and json.loads(result.content)["code"] == "invalid_arguments"
    assert not client.calls
    result = call(build_related_event_search_tool(searcher(FakeClient(failure=True)), scope=scope()), args())
    assert result.status == "error" and json.loads(result.content)["code"] == "search_failed"
    assert "events" not in json.loads(result.content)


@check("Tool summaries compute actual filters, duration, counts and truncation; adapter preserves bounded query size")
def tool_summary():
    client = FakeClient()
    result = call(build_related_event_search_tool(searcher(client), scope=scope()), args(family="group_changes", limit=1))
    content = json.loads(result.content)
    assert result.status == "success"
    assert content["search_summary"]["duration_seconds"] == 600
    assert content["search_summary"]["filters"]["family"] == "group_changes"
    assert content["search_summary"]["returned_event_count"] == 1
    assert client.calls[0][1] == client.calls[0][0]["size"] == 2


@check("Oversized tool results become explicit errors rather than an accepted partial result")
def tool_budget():
    hits = [hit(i) for i in range(1, 11)]
    for item in hits:
        item["_source"]["data"]["win"]["eventdata"]["commandLine"] = "x" * 2000
    result = call(build_related_event_search_tool(searcher(FakeClient(payload(*hits))), scope=scope()), args(limit=10))
    assert result.status == "error" and json.loads(result.content)["code"] == "result_too_large"


def stored_alert(event_id=4728, sysmon=False):
    identity = EventIdentity("Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", event_id) if sysmon else EventIdentity("Microsoft-Windows-Security-Auditing", "Security", event_id)
    return SecurityAlert("stored-fixture", "fixture-manager", START + timedelta(seconds=1), "001", "fixture-host",
        "fixture-rule", 8, "UNTRUSTED_DESCRIPTION_DO_NOT_USE_AS_TASK", identity,
        full_log="UNTRUSTED_RAW_LOG_INSTRUCTION", decoded_data_json=json.dumps(hit(event_id=event_id, sysmon=sysmon)["_source"]["data"]))


@check("Stored planning adds host authority, selects the event family and rejects mixed-host snapshots")
def planning():
    planner = ReadOnlyStoredInvestigationPlanner()
    for event, sysmon, family in ((4720, False, "account_changes"), (4728, False, "group_changes"), (1, True, "process_activity")):
        value = stored_alert(event, sysmon)
        plan = planner.plan(value)
        assert isinstance(plan.scope, InvestigationScope)
        assert plan.scope.related_events.hosts == (("fixture-manager", "001"),)
        assert family in plan.task and "search_related_events" in plan.task
        assert "UNTRUSTED_DESCRIPTION" not in plan.task and "UNTRUSTED_RAW_LOG" not in plan.task
        assert json.loads(plan.scope.snapshot_json())["version"] == 2
    invalid = json.dumps({"alerts": [{"timestamp": START.isoformat(), "source_instance": "fixture-manager", "agent_id": "002"}]})
    expect(ValueError, lambda: planner.plan(stored_alert(), invalid))


@check("Invocation-local tool scopes do not authorize another job's host")
def isolation():
    client = FakeClient()
    first = build_related_event_search_tool(searcher(client), scope=scope())
    second = build_related_event_search_tool(searcher(client), scope=scope(hosts=(("fixture-manager", "002"),)))
    assert call(first, args()).status == "success"
    assert call(second, args()).status == "error"
    assert len(client.calls) == 1


@check("A scoped worker completes a native related-event call and persists scope and tool provenance atomically")
def worker_integration():
    database = ROOT / "worker.sqlite3"
    reader = SqliteAlertRepository(database)
    value = stored_alert(1, True)
    receipt = reader.save_and_schedule(value)
    SqliteAnalysisWriter(database)
    queue = SqliteAnalysisQueue(database)
    planner = ReadOnlyStoredInvestigationPlanner()
    plan = planner.plan(value)
    arguments = dict(source_instance="fixture-manager", agent_id="001", family="process_activity", limit=1,
                     start=plan.scope.start.isoformat(), end=plan.scope.end.isoformat())
    answers = [AIMessage(content="", tool_calls=[{"name": "search_related_events", "args": arguments, "id": "fixture-call", "type": "tool_call"}], response_metadata={"done_reason": "stop"}),
               AIMessage(content="Synthetic completion only; no semantic certification.", response_metadata={"done_reason": "stop"})]
    class Model:
        def bind_tools(self, tools):
            return self
        def invoke(self, messages):
            if not answers:
                raise AssertionError("Unexpected additional model request")
            return answers.pop(0)
    class Retriever:
        def retrieve(self, query, k):
            return []
    class Catalog:
        def lookup(self, provider, channel, event_id):
            return None
    class Baseline:
        def analyze(self, evidence, references):
            raise AssertionError("Unexpected baseline analysis")
    client = FakeClient(payload(hit(event_id=1, sysmon=True)))
    def tools_for_scope(authority):
        return [build_related_event_search_tool(searcher(client),
            scope=authority.related_events if isinstance(authority, InvestigationScope) else None)]
    investigator = OllamaInvestigationModel(cast(ChatOllama, Model()), tools_for_scope(None), scoped_tool_factory=tools_for_scope)
    analyzer = AnalyzeAlert(Retriever(), Baseline(), catalog=Catalog(), investigator=investigator)
    claim = queue.claim_next(job_id=receipt.job_id)
    assert claim is not None
    record = ProcessAnalysisJob(reader, analyzer, queue, investigation_planner=planner).execute(claim)
    assert record.result.tool_executions[0].tool_name == "search_related_events"
    assert record.result.tool_executions[0].status == "success"
    assert record.result.investigation_scope_json == plan.scope.snapshot_json()
    with closing(sqlite3.connect(database)) as connection:
        saved = json.loads(connection.execute("SELECT result_json FROM analyses WHERE analysis_id=?", (record.analysis_id,)).fetchone()[0])
        assert saved["tool_executions"][0]["arguments_json"] == record.result.tool_executions[0].arguments_json
        assert connection.execute("SELECT status FROM analysis_jobs WHERE job_id=?", (receipt.job_id,)).fetchone()[0] == "completed"


def main():
    if not __debug__ or not Path("pyproject.toml").is_file():
        raise SystemExit("Run from the project root without -O.")
    ROOT.mkdir(parents=True, exist_ok=False)
    print("Isolated validation directory:", ROOT, flush=True)
    results = []
    for name, function in CHECKS:
        started = time.perf_counter()
        try:
            function()
        except Exception as error:
            results.append({"name": name, "status": "failed", "error_type": type(error).__name__, "details": str(error), "traceback": traceback.format_exc()})
            print(f"FAIL: {name} ({type(error).__name__}: {error})", flush=True)
        else:
            results.append({"name": name, "status": "passed"})
            print(f"PASS: {name}", flush=True)
        results[-1]["seconds"] = round(time.perf_counter() - started, 3)
    failed = sum(row["status"] == "failed" for row in results)
    path = ROOT / "results.json"
    path.write_text(json.dumps({"passed": len(results) - failed, "failed": failed,
        "limitations": "In-memory source/model substitutes; not live field-mapping validation or model-quality certification.", "checks": results}, indent=2), encoding="utf-8")
    print(f"\nSUMMARY: {len(results) - failed}/{len(results)} passed; {failed} failed.")
    print("Full results:", path)
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
