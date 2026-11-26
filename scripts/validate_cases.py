"""Offline case lifecycle and storage boundary checks; run from the project root.

Uses fresh ignored databases and synthetic reports. No models, VM, Indexer,
operational databases, or external services are used.
"""

import json
import sqlite3
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cybertriage.adapters.storage.alerts_sqlite import SqliteAlertRepository
from cybertriage.adapters.storage.analyses_sqlite import SqliteAnalysisWriter
from cybertriage.adapters.storage.cases_sqlite import SqliteCaseRepository
from cybertriage.adapters.storage.jobs_sqlite import SqliteAnalysisQueue
from cybertriage.adapters.storage.triage_sqlite import SqliteTriageReviewRepository
from cybertriage.application.policies.alert_triage import AlertTriagePolicy
from cybertriage.application.policies.case_relationships import ObservedRelationshipPolicy
from cybertriage.application.services.case_management import CaseManagement
from cybertriage.domain.alert import SecurityAlert
from cybertriage.domain.case import CaseConflictError, CaseError, CaseStorageError
from cybertriage.domain.jobs import JobStorageError
from cybertriage.domain.security_event import EventIdentity
from cybertriage.domain.triage import AnalysisRecord, TriageResult
from cybertriage.domain.triage_policy import GroupingRule, TriageSettings

ROOT = Path.cwd() / "data" / "validation" / f"cases-{uuid4().hex}"
BASE = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
CHECKS = []


def check(name):
    def decorate(function):
        CHECKS.append((name, function))
        return function
    return decorate


def expect(error_type, function):
    try:
        function()
    except error_type:
        return
    raise AssertionError(f"Expected {error_type.__name__}")


def fixture(name, grouped=False):
    folder = ROOT / name
    folder.mkdir(parents=True, exist_ok=False)
    database = folder / "alerts.sqlite3"
    rules = (GroupingRule("case-fixture", (), "Microsoft-Windows-Security-Auditing", "Security", (4625,),
                          ("win.eventdata.targetUserName", "win.eventdata.targetDomainName"), 300, 0, 5),) if grouped else ()
    alerts = SqliteAlertRepository(database, AlertTriagePolicy(TriageSettings(grouping_rules=rules)))
    service = CaseManagement(SqliteCaseRepository(database), ObservedRelationshipPolicy())
    return database, alerts, service


def alert(number, *, host="host-1", account="alice", ip="10.0.2.5", event_id=4625, manager="fixture-manager", session=None):
    fields = {"targetUserName": account, "targetDomainName": "CORP", "ipAddress": ip, "logonType": "2"}
    if session:
        fields["targetLogonId" if event_id == 4624 else "subjectLogonId"] = session
    data = {"win": {"eventdata": fields}}
    return SecurityAlert(f"case-fixture.{number}", manager, BASE + timedelta(seconds=number), host, host,
                         "fixture-rule", 5, "Synthetic case evidence.",
                         EventIdentity("Microsoft-Windows-Security-Auditing", "Security", event_id),
                         decoded_data_json=json.dumps(data))


def report(anchor, evidence="Synthetic evidence without a group snapshot."):
    return AnalysisRecord(uuid4().hex, anchor, datetime.now(timezone.utc), "fixture query", evidence,
                          TriageResult("Synthetic report only; not a finding of compromise.", ()))


def scalar(database, statement, parameters=()):
    with closing(sqlite3.connect(database)) as connection:
        return connection.execute(statement, parameters).fetchone()[0]


@check("Case creation, idempotent attachment, notes, and all-or-nothing attachment")
def lifecycle():
    db, alerts, service = fixture("lifecycle")
    a = alerts.save_and_schedule(alert(1)).record_id
    case = service.create("Authentication investigation", "analyst")
    service.attach(case.case_id, [a], "analyst", "Review this activity")
    before = service.get(case.case_id)
    result = service.attach(case.case_id, [a], "analyst", "Duplicate attachment")
    assert result["attached_alert_ids"] == []
    assert service.get(case.case_id).version == before.version
    service.note(case.case_id, "Requested account owner confirmation.", "analyst")
    b = alerts.save_and_schedule(alert(2)).record_id
    expect(CaseError, lambda: service.attach(case.case_id, [b, "missing"], "analyst", "Atomic batch"))
    assert scalar(db, "SELECT COUNT(*) FROM case_alerts WHERE case_id=?", (case.case_id,)) == 1
    assert scalar(db, "SELECT COUNT(*) FROM alerts") == 2


@check("Concurrent attachments preserve one membership and one attachment event")
def concurrent_attach():
    db, alerts, service = fixture("concurrent")
    a = alerts.save_and_schedule(alert(1)).record_id
    case = service.create("Concurrent attachment", "analyst")
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: service.attach(case.case_id, [a], "analyst", "Same evidence"), range(4)))
    assert sum(len(result["attached_alert_ids"]) for result in results) == 1
    assert scalar(db, "SELECT COUNT(*) FROM case_events WHERE kind='alert_attached'") == 1


@check("Version conflicts, explicit disposition evidence, closure, and reopening")
def versions():
    db, alerts, service = fixture("versions")
    a = alerts.save_and_schedule(alert(1)).record_id
    case = service.create("Review findings", "analyst")
    service.attach(case.case_id, [a], "analyst", "Initial scope")
    expect(CaseConflictError, lambda: service.update(case.case_id, {"priority": "high"}, case.version, "analyst", "Stale view"))
    current = service.get(case.case_id)
    expect(CaseError, lambda: service.update(case.case_id, {"disposition": "confirmed_compromise"}, current.version, "analyst", "No supporting IDs"))
    updated = service.update(case.case_id, {"status": "closed", "disposition": "confirmed_compromise"},
                             current.version, "analyst", "Explicit fixture finding", [a])
    expect(CaseError, lambda: service.detach(case.case_id, a, updated.version, "analyst", "Closed case"))
    reopened = service.update(case.case_id, {"status": "investigating"}, updated.version, "analyst", "Reopen")
    service.detach(case.case_id, a, reopened.version, "analyst", "Separate investigation")
    item = service.read(case.case_id, "alerts")["alerts"][0]
    assert item["active"] == 0
    assert scalar(db, "SELECT COUNT(*) FROM alerts") == 1
    assert service.get(case.case_id).disposition == "confirmed_compromise"


@check("Observed relationships require stored facts and preserve field/hash provenance")
def observations():
    db, alerts, service = fixture("observed")
    a = alerts.save_and_schedule(alert(1)).record_id
    b = alerts.save_and_schedule(alert(2)).record_id
    case = service.create("Related activity", "analyst")
    service.attach(case.case_id, [a, b], "analyst", "Related observations")
    for predicate in ("shares_host", "shares_account_fields", "shares_source_ip", "precedes_by_reported_time"):
        service.relate(case.case_id, a, b, "observed", predicate, "analyst", "Validate reported fields")
    relations = service.read(case.case_id, "relationships")["relationships"]
    assert len(relations) == 4
    assert all(item["kind"] == "observed" and len(item["proof"]["source_payload_sha256"]) == 64 for item in relations)
    expect(CaseError, lambda: service.relate(case.case_id, b, a, "observed", "precedes_by_reported_time", "analyst", "Wrong ordering"))
    expect(CaseError, lambda: service.relate(case.case_id, a, b, "observed", "caused_compromise", "analyst", "Unsupported inference"))


@check("Loopback and sessions remain host-scoped; failed logons do not establish target sessions")
def correlation_scope():
    _, alerts, service = fixture("scope")
    a = alerts.save_and_schedule(alert(1, ip="127.0.0.1", session="0x123")).record_id
    b = alerts.save_and_schedule(alert(2, host="host-2", ip="127.0.0.1", session="0x123")).record_id
    c = alerts.save_and_schedule(alert(3, event_id=4624, session="0x123")).record_id
    d = alerts.save_and_schedule(alert(4, event_id=4728, session="0x123")).record_id
    e = alerts.save_and_schedule(alert(5, manager="other-manager", event_id=4728, session="0x123")).record_id
    case = service.create("Identity scope", "analyst")
    service.attach(case.case_id, [a, b, c, d, e], "analyst", "Compare fields")
    for x, y, predicate in ((a, b, "shares_source_ip"), (a, c, "shares_session"), (c, e, "shares_session"), (a, e, "shares_account_fields")):
        expect(CaseError, lambda x=x, y=y, p=predicate: service.relate(case.case_id, x, y, "observed", p, "analyst", "Must reject"))
    service.relate(case.case_id, c, d, "observed", "shares_session", "analyst", "Matching reported session fields")


@check("Accepted hypotheses remain hypotheses and reviews cannot cross case boundaries")
def hypotheses():
    _, alerts, service = fixture("hypotheses")
    a, b = (alerts.save_and_schedule(alert(i)).record_id for i in (1, 2))
    case = service.create("Hypothesis review", "analyst")
    other = service.create("Other case", "analyst")
    service.attach(case.case_id, [a, b], "analyst", "Working scope")
    relation = service.relate(case.case_id, a, b, "hypothesis", "possible_lateral_movement", "analyst", "Needs session confirmation", [a, b])
    service.review_relationship(case.case_id, relation["relationship_id"], "accepted", service.get(case.case_id).version, "reviewer", "Working hypothesis retained")
    row = service.read(case.case_id, "relationships")["relationships"][0]
    assert row["kind"] == "hypothesis" and row["review_status"] == "accepted"
    assert service.get(case.case_id).disposition == "unconfirmed"
    expect(CaseError, lambda: service.review_relationship(other.case_id, relation["relationship_id"], "accepted", other.version, "reviewer", "Wrong case"))
    expect(CaseError, lambda: service.relate(other.case_id, a, b, "hypothesis", "possible_lateral_movement", "analyst", "Missing membership", [a]))


@check("New reports link automatically; prior reports backfill on attachment")
def reports():
    db, alerts, service = fixture("reports")
    a = alerts.save_and_schedule(alert(1)).record_id
    existing = report(a)
    SqliteAnalysisWriter(db).save(existing)
    case = service.create("Report history", "analyst")
    service.attach(case.case_id, [a], "analyst", "Retrospective review")
    assert service.read(case.case_id, "investigations")["investigations"][0]["analysis_id"] == existing.analysis_id
    newer = report(a)
    SqliteAnalysisWriter(db).save(newer)
    assert len(service.read(case.case_id, "investigations")["investigations"]) == 2
    assert service.report(case.case_id, newer.analysis_id)["coverage"] == [{"alert_record_id": a, "actively_attached": 1}]
    other = service.create("Unrelated case", "analyst")
    expect(CaseError, lambda: service.report(other.case_id, newer.analysis_id))


@check("Legacy report backfill recovers exact evidence without requiring prior coverage rows")
def legacy_reports():
    db, alerts, service = fixture("legacy")
    a = alerts.save_and_schedule(alert(1)).record_id
    old = report(a)
    with closing(sqlite3.connect(db)) as connection:
        with connection:
            connection.execute("INSERT INTO analyses VALUES(?,?,?,?,?,?)", (old.analysis_id, a, old.completed_at.isoformat(), old.retrieval_query, old.evidence,
                json.dumps({"analysis": old.result.analysis, "references": []})))
    case = service.create("Legacy investigation", "analyst")
    service.attach(case.case_id, [a], "analyst", "Historic evidence")
    assert service.report(case.case_id, old.analysis_id)["coverage"][0]["alert_record_id"] == a


@check("Grouped report coverage uses the saved snapshot, not later group membership")
def group_snapshots():
    db, alerts, service = fixture("group-snapshot", grouped=True)
    first = alerts.save_and_schedule(alert(1))
    snapshot = SqliteTriageReviewRepository(db).group_context(first.record_id)
    assert snapshot is not None
    old = report(first.record_id, snapshot)
    SqliteAnalysisWriter(db).save(old)
    second = alerts.save_and_schedule(alert(2))
    assert second.group_id == first.group_id
    case = service.create("Later group member", "analyst")
    service.attach(case.case_id, [second.record_id], "analyst", "Later evidence")
    assert service.read(case.case_id, "investigations")["investigations"] == []
    updated_snapshot = SqliteTriageReviewRepository(db).group_context(first.record_id)
    newer = report(first.record_id, updated_snapshot)
    SqliteAnalysisWriter(db).save(newer)
    coverage = service.report(case.case_id, newer.analysis_id)["coverage"]
    assert {item["alert_record_id"] for item in coverage} == {first.record_id, second.record_id}
    assert sum(item["actively_attached"] for item in coverage) == 1
    service.attach(case.case_id, [], "analyst", "Explicit group snapshot", first.group_id)
    assert scalar(db, "SELECT COUNT(*) FROM case_alerts WHERE case_id=?", (case.case_id,)) == 2
    third = alerts.save_and_schedule(alert(3))
    assert third.group_id == first.group_id
    assert scalar(db, "SELECT COUNT(*) FROM case_alerts WHERE case_id=?", (case.case_id,)) == 2


@check("Worker completion, coverage, case history, and job result commit together")
def worker_transaction():
    db, alerts, service = fixture("worker")
    first = alerts.save_and_schedule(alert(1))
    case = service.create("Background report", "analyst")
    service.attach(case.case_id, [first.record_id], "analyst", "Investigate")
    queue = SqliteAnalysisQueue(db)
    claim = queue.claim_next(lease_seconds=600, max_attempts=3, job_id=first.job_id)
    assert claim is not None
    stored = report(first.record_id)
    with closing(sqlite3.connect(db)) as connection:
        connection.execute("""CREATE TRIGGER reject_case_link BEFORE INSERT ON case_events
            WHEN NEW.kind='analysis_linked' BEGIN SELECT RAISE(ABORT,'Fixture failure'); END""")
    expect(JobStorageError, lambda: queue.complete(claim, stored))
    assert scalar(db, "SELECT COUNT(*) FROM analyses") == 0
    assert scalar(db, "SELECT COUNT(*) FROM analysis_alert_coverage") == 0
    assert scalar(db, "SELECT COUNT(*) FROM case_analyses") == 0
    assert scalar(db, "SELECT status FROM analysis_jobs WHERE job_id=?", (first.job_id,)) == "running"
    with closing(sqlite3.connect(db)) as connection:
        connection.execute("DROP TRIGGER reject_case_link")
    queue.complete(claim, stored)
    assert service.read(case.case_id, "investigations")["investigations"][0]["analysis_id"] == stored.analysis_id
    assert scalar(db, "SELECT status FROM analysis_jobs WHERE job_id=?", (first.job_id,)) == "completed"


@check("Timeline and history paginate without silent loss; stale cursors are rejected")
def pagination():
    _, alerts, service = fixture("pagination")
    a, b = (alerts.save_and_schedule(alert(i)).record_id for i in (1, 2))
    case = service.create("Timeline", "analyst")
    service.attach(case.case_id, [a, b], "analyst", "Timeline evidence")
    service.note(case.case_id, "First note", "analyst")
    cursor, seen = None, []
    while True:
        result = service.timeline(case.case_id, 2, cursor)
        seen.extend((row["kind"], row["item_id"]) for row in result["timeline"])
        cursor = result["next_cursor"]
        if not cursor:
            break
    assert len(seen) == len(set(seen)) == 6
    first = service.timeline(case.case_id, 1)
    service.note(case.case_id, "Changed case", "analyst")
    expect(CaseConflictError, lambda: service.timeline(case.case_id, 1, first["next_cursor"]))
    expect(CaseError, lambda: service.timeline(case.case_id, 1, "invalid!"))
    initial = service.read(case.case_id, "history", 2)
    remainder = service.read(case.case_id, "history", 100, initial["next_after"])
    assert len(initial["history"]) + len(remainder["history"]) == 5


@check("Case evidence changes roll back with audit failures")
def audit_rollback():
    db, alerts, service = fixture("audit-rollback")
    a = alerts.save_and_schedule(alert(1)).record_id
    case = service.create("Audit transaction", "analyst")
    with closing(sqlite3.connect(db)) as connection:
        connection.execute("""CREATE TRIGGER reject_attachment BEFORE INSERT ON case_events
            WHEN NEW.kind='alert_attached' BEGIN SELECT RAISE(ABORT,'Fixture failure'); END""")
    expect(CaseStorageError, lambda: service.attach(case.case_id, [a], "analyst", "Must roll back"))
    assert scalar(db, "SELECT COUNT(*) FROM case_alerts") == 0
    assert service.get(case.case_id).version == case.version


@check("Audit, relationships, reviews, coverage and report links reject UPDATE and DELETE")
def immutable_history():
    db, alerts, service = fixture("immutable")
    a, b = (alerts.save_and_schedule(alert(i)).record_id for i in (1, 2))
    case = service.create("Immutable history", "analyst")
    service.attach(case.case_id, [a, b], "analyst", "Scope")
    relation = service.relate(case.case_id, a, b, "hypothesis", "possible_related_activity", "analyst", "Working theory", [a])
    service.review_relationship(case.case_id, relation["relationship_id"], "accepted", service.get(case.case_id).version, "reviewer", "Retain as hypothesis")
    SqliteAnalysisWriter(db).save(report(a))
    assignments = {"case_events": "reason='changed'", "case_relationships": "rationale='changed'",
                   "case_relationship_reviews": "reason='changed'", "analysis_alert_coverage": "analysis_id=analysis_id",
                   "case_analyses": "linked_at='changed'"}
    for table, assignment in assignments.items():
        with closing(sqlite3.connect(db)) as connection:
            for statement in (f"UPDATE {table} SET {assignment}", f"DELETE FROM {table}"):
                expect(sqlite3.IntegrityError, lambda: connection.execute(statement))
                connection.rollback()


@check("Invalid case inputs and unsupported fields are rejected before persistence")
def invalid_inputs():
    db, _, service = fixture("invalid")
    expect(CaseError, lambda: service.create("", "analyst"))
    expect(CaseError, lambda: service.create("Title", "analyst", priority="urgent"))
    expect(CaseError, lambda: service.list_cases(limit=101))
    expect(CaseError, lambda: service.get("x'; DELETE FROM alerts;--"))
    assert scalar(db, "SELECT COUNT(*) FROM incident_cases") == 0
    case = service.create("Valid case", "analyst")
    expect(CaseError, lambda: service.update(case.case_id, {"version": "0"}, case.version, "analyst", "Invalid field"))
    expect(CaseError, lambda: service.attach(case.case_id, [], "analyst", "Empty command"))
    assert service.get(case.case_id).version == case.version


def main():
    if not __debug__:
        raise SystemExit("Run without -O; checks use assertions.")
    if not Path("pyproject.toml").is_file():
        raise SystemExit("Run from the CyberTriage project root.")
    ROOT.mkdir(parents=True, exist_ok=False)
    print("Isolated validation directory:", ROOT, flush=True)
    results = []
    for name, function in CHECKS:
        started = time.perf_counter()
        try:
            function()
        except Exception as error:
            results.append({"name": name, "status": "failed", "error_type": type(error).__name__,
                            "details": str(error), "traceback": traceback.format_exc()})
            print(f"FAIL: {name} ({type(error).__name__}: {error})", flush=True)
        else:
            results.append({"name": name, "status": "passed"})
            print(f"PASS: {name}", flush=True)
        results[-1]["seconds"] = round(time.perf_counter() - started, 3)
    failed = sum(row["status"] == "failed" for row in results)
    output = ROOT / "results.json"
    output.write_text(json.dumps({"passed": len(results) - failed, "failed": failed,
        "limitations": "Synthetic storage/orchestration checks, not real-world attack attribution or model quality validation.",
        "checks": results}, indent=2), encoding="utf-8")
    print(f"\nSUMMARY: {len(results) - failed}/{len(results)} passed; {failed} failed.")
    print("Full results:", output)
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
