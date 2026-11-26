"""SQLite response authority; dispatch claims never automatically replay mutations."""

import json
from collections.abc import Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta
from hashlib import sha256
from uuid import uuid4

from cybertriage.adapters.storage.case_records import append_case_event
from cybertriage.adapters.storage.cases_sqlite import SqliteCaseRepository
from cybertriage.domain.case import CaseStorageError
from cybertriage.application.policies.response_actions import BlockIpParameterValidator, ResponseActionPolicy
from cybertriage.domain.response import ActionProposal, AnalystApproval, IncidentDisposition
from cybertriage.domain.response_workflow import (ExecutionOutcome, ExecutionRequest, ResponseConflictError,
    ResponseError, ResponsePolicySnapshot, ResponseStorageError, canonical, utc_now)


class SqliteResponseRepository(SqliteCaseRepository):
    @contextmanager
    def _session(self, write=False):
        try:
            with super()._session(write) as connection:
                yield connection
        except CaseStorageError as error:
            raise ResponseStorageError("Response storage failed; no partial changes were committed.") from error

    def __init__(self, database_path):
        super().__init__(database_path)
        with self._session(True) as connection:
            for statement in (
                """CREATE TABLE IF NOT EXISTS response_proposals(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, proposal_id TEXT NOT NULL UNIQUE,
                    case_id TEXT NOT NULL REFERENCES incident_cases(case_id), action TEXT NOT NULL,target TEXT NOT NULL,
                    parameters_json TEXT NOT NULL,fingerprint TEXT NOT NULL,binding_hash TEXT NOT NULL,
                    policy_revision TEXT NOT NULL,policy_json TEXT NOT NULL,case_version INTEGER NOT NULL,
                    supporting_json TEXT NOT NULL,analysis_id TEXT REFERENCES analyses(analysis_id),
                    rationale TEXT NOT NULL,proposed_by TEXT NOT NULL,origin TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,request_hash TEXT NOT NULL,created_at TEXT NOT NULL,
                    UNIQUE(case_id,idempotency_key))""",
                """CREATE TABLE IF NOT EXISTS response_reviews(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,review_id TEXT NOT NULL UNIQUE,
                    proposal_id TEXT NOT NULL REFERENCES response_proposals(proposal_id),
                    decision TEXT NOT NULL CHECK(decision IN ('approved','rejected','revoked')),
                    actor TEXT NOT NULL,reason TEXT NOT NULL,case_version INTEGER NOT NULL,
                    binding_hash TEXT NOT NULL,policy_revision TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT)""",
                "CREATE INDEX IF NOT EXISTS response_review_history ON response_reviews(proposal_id,seq)",
                """CREATE TABLE IF NOT EXISTS response_executions(
                    execution_id TEXT PRIMARY KEY,proposal_id TEXT NOT NULL UNIQUE REFERENCES response_proposals(proposal_id),
                    claim_token TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('dispatching','succeeded','failed','unknown')),
                    actor TEXT NOT NULL,case_version INTEGER NOT NULL,claimed_at TEXT NOT NULL,
                    finished_at TEXT,outcome_json TEXT)""",
                """CREATE TABLE IF NOT EXISTS response_execution_events(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,execution_id TEXT NOT NULL REFERENCES response_executions(execution_id),
                    kind TEXT NOT NULL,actor TEXT NOT NULL,reason TEXT NOT NULL,details_json TEXT NOT NULL,recorded_at TEXT NOT NULL)""",
                """CREATE TABLE IF NOT EXISTS response_block_leases(
                    execution_id TEXT PRIMARY KEY REFERENCES response_executions(execution_id),target TEXT NOT NULL,address TEXT NOT NULL,
                    target_revision TEXT NOT NULL,expires_at TEXT NOT NULL,status TEXT NOT NULL
                    CHECK(status IN ('scheduled','releasing','released','unknown','unmanaged')),claim_token TEXT,
                    updated_at TEXT NOT NULL,last_code TEXT)""",
                "CREATE INDEX IF NOT EXISTS response_lease_address ON response_block_leases(target,address,status)",
            ):
                connection.execute(statement)
            for table in ("response_proposals", "response_reviews", "response_execution_events"):
                for operation in ("UPDATE", "DELETE"):
                    connection.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()}
                        BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'Response history is append-only'); END""")

    @staticmethod
    def _row(connection, proposal_id):
        row = connection.execute("SELECT * FROM response_proposals WHERE proposal_id=?", (proposal_id,)).fetchone()
        if row is None:
            raise ResponseError("Response proposal not found.")
        return row

    @staticmethod
    def _proposal(row):
        return ActionProposal(row["case_id"], row["action"], row["target"], json.loads(row["parameters_json"]))

    @staticmethod
    def _policy(snapshot):
        return ResponseActionPolicy(snapshot.settings, {"block_ip": BlockIpParameterValidator()})

    def _support(self, connection, row):
        support = json.loads(row["supporting_json"])
        self._attached(connection, row["case_id"], [item["record_id"] for item in support])
        for item in support:
            if self._alert(connection, item["record_id"]).payload_hash != item["payload_sha256"]:
                raise ResponseConflictError("Supporting evidence changed.")

    def propose(self, proposal: ActionProposal, supporting_ids: Sequence[str], expected_version: int,
                actor: str, reason: str, origin: str, idempotency_key: str, analysis_id: str | None,
                snapshot: ResponsePolicySnapshot):
        contract = self._policy(snapshot).validate_proposal(proposal)
        if not contract.allowed:
            raise ResponseError(" ".join(contract.reasons))
        request_hash = sha256(canonical({"fingerprint": proposal.fingerprint, "support": sorted(supporting_ids),
            "actor": actor, "reason": reason, "origin": origin, "analysis_id": analysis_id,
            "expected_version": expected_version, "policy_revision": snapshot.revision}).encode()).hexdigest()
        with self._session(True) as connection:
            existing = connection.execute("SELECT * FROM response_proposals WHERE case_id=? AND idempotency_key=?",
                (proposal.case_id, idempotency_key)).fetchone()
            if existing:
                if existing["request_hash"] != request_hash:
                    raise ResponseConflictError("The idempotency key already identifies different proposal content.")
                return {**self._get(connection, existing["proposal_id"]), "created": False}
            case = self._case(connection, proposal.case_id, expected_version, editable=True)
            self._attached(connection, case.case_id, supporting_ids)
            if analysis_id and not connection.execute("SELECT 1 FROM case_analyses WHERE case_id=? AND analysis_id=?",
                                                      (case.case_id, analysis_id)).fetchone():
                raise ResponseError("The referenced analysis is not linked to this case.")
            if connection.execute("SELECT COUNT(*) FROM response_proposals WHERE case_id=?", (case.case_id,)).fetchone()[0] >= 1000:
                raise ResponseError("Response proposal capacity reached for this case.")
            support = [{"record_id": value, "payload_sha256": self._alert(connection, value).payload_hash} for value in sorted(supporting_ids)]
            binding = sha256(canonical({"fingerprint": proposal.fingerprint, "case_version": case.version + 1,
                "policy_revision": snapshot.revision, "support": support}).encode()).hexdigest()
            proposal_id = uuid4().hex
            connection.execute("""INSERT INTO response_proposals(proposal_id,case_id,action,target,parameters_json,fingerprint,
                binding_hash,policy_revision,policy_json,case_version,supporting_json,analysis_id,rationale,proposed_by,
                origin,idempotency_key,request_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (proposal_id, case.case_id, proposal.action, proposal.target, canonical(dict(proposal.parameters)), proposal.fingerprint,
                 binding, snapshot.revision, snapshot.json, case.version + 1, canonical(support), analysis_id, reason, actor,
                 origin, idempotency_key, request_hash, utc_now().isoformat()))
            append_case_event(connection, case.case_id, "response_proposed", actor, reason,
                {"proposal_id": proposal_id, "action": proposal.action, "target": proposal.target,
                 "origin": origin, "binding_hash": binding, "policy_revision": snapshot.revision,
                 "interpretation": "Proposal only; no approval or execution authority."})
            return {**self._get(connection, proposal_id), "created": True}

    def review(self, proposal_id, decision, expected_version, actor, reason, snapshot):
        with self._session(True) as connection:
            row = self._row(connection, proposal_id)
            case = self._case(connection, row["case_id"], expected_version, editable=True)
            previous = connection.execute("SELECT * FROM response_reviews WHERE proposal_id=? ORDER BY seq DESC LIMIT 1", (proposal_id,)).fetchone()
            execution = connection.execute("SELECT 1 FROM response_executions WHERE proposal_id=?", (proposal_id,)).fetchone()
            if execution or (decision == "revoked" and (not previous or previous["decision"] != "approved")) or (decision != "revoked" and previous):
                raise ResponseConflictError("This proposal cannot receive that review; create a new proposal when needed.")
            if decision == "approved":
                if row["case_version"] != case.version or row["policy_revision"] != snapshot.revision:
                    raise ResponseConflictError("Case or target/policy configuration changed; propose the action again.")
                self._support(connection, row)
                proposal = self._proposal(row)
                now = utc_now()
                allowed = self._policy(snapshot).evaluate(proposal, IncidentDisposition(case.disposition), AnalystApproval(proposal.fingerprint, actor, now))
                if not allowed.allowed:
                    raise ResponseError(" ".join(allowed.reasons))
                expires = (now + timedelta(seconds=snapshot.settings.approval_ttl_seconds)).isoformat()
            else:
                now, expires = utc_now(), None
            connection.execute("""INSERT INTO response_reviews(review_id,proposal_id,decision,actor,reason,case_version,
                binding_hash,policy_revision,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (uuid4().hex, proposal_id, decision, actor, reason, case.version + 1, row["binding_hash"],
                 snapshot.revision, now.isoformat(), expires))
            append_case_event(connection, case.case_id, "response_" + decision, actor, reason,
                {"proposal_id": proposal_id, "binding_hash": row["binding_hash"], "expires_at": expires})
            return self._get(connection, proposal_id)

    def _get(self, connection, proposal_id):
        row = dict(self._row(connection, proposal_id))
        row["parameters"] = json.loads(row.pop("parameters_json"))
        row["supporting_alerts"] = json.loads(row.pop("supporting_json"))
        row["policy_snapshot"] = json.loads(row.pop("policy_json"))
        row.pop("request_hash")
        reviews = connection.execute("SELECT * FROM response_reviews WHERE proposal_id=? ORDER BY seq", (proposal_id,)).fetchall()
        execution = connection.execute("SELECT * FROM response_executions WHERE proposal_id=?", (proposal_id,)).fetchone()
        row["reviews"] = [dict(value) for value in reviews]
        row["status"] = reviews[-1]["decision"] if reviews else "proposed"
        row["execution"] = None
        if execution:
            entry = dict(execution)
            entry.pop("claim_token")
            outcome_json = entry.pop("outcome_json")
            entry["outcome"] = json.loads(outcome_json) if outcome_json else None
            entry["events"] = [dict(value) for value in connection.execute("SELECT * FROM response_execution_events WHERE execution_id=? ORDER BY seq", (execution["execution_id"],))]
            row["execution"], row["status"] = entry, entry["status"]
            lease = connection.execute("SELECT * FROM response_block_leases WHERE execution_id=?", (execution["execution_id"],)).fetchone()
            if lease:
                lease = dict(lease)
                lease.pop("claim_token")
                row["block_lease"] = lease
        row["current_case_version"] = self._case(connection, row["case_id"]).version
        if not execution and reviews and reviews[-1]["decision"] == "approved":
            row["approval_expired"] = reviews[-1]["expires_at"] <= utc_now().isoformat()
            row["case_changed_since_approval"] = reviews[-1]["case_version"] != row["current_case_version"]
        return self._bounded(row)

    def get(self, proposal_id):
        with self._session() as connection:
            return self._get(connection, proposal_id)

    def list(self, case_id, limit, after):
        with self._session() as connection:
            case = self._case(connection, case_id)
            rows = connection.execute("SELECT seq,proposal_id,action,target,case_version,created_at FROM response_proposals WHERE case_id=? AND seq>? ORDER BY seq LIMIT ?",
                                      (case_id, after, limit + 1)).fetchall()
            return self._bounded({"case_id": case_id, "case_version": case.version, "proposals": [dict(row) for row in rows[:limit]],
                "next_after": rows[limit - 1]["seq"] if len(rows) > limit else None})

    def claim(self, proposal_id, expected_version, actor, reason, snapshot):
        with self._session(True) as connection:
            row = self._row(connection, proposal_id)
            case = self._case(connection, row["case_id"], expected_version, editable=True)
            review = connection.execute("SELECT * FROM response_reviews WHERE proposal_id=? ORDER BY seq DESC LIMIT 1", (proposal_id,)).fetchone()
            if not review or review["decision"] != "approved" or review["case_version"] != case.version or review["binding_hash"] != row["binding_hash"]:
                raise ResponseConflictError("A current approval bound to this case version is required.")
            if row["policy_revision"] != snapshot.revision or review["policy_revision"] != snapshot.revision:
                raise ResponseConflictError("Response policy or firewall target configuration changed.")
            if review["expires_at"] <= utc_now().isoformat():
                raise ResponseConflictError("The stored approval has expired; propose and review a new action.")
            if connection.execute("SELECT 1 FROM response_executions WHERE proposal_id=?", (proposal_id,)).fetchone():
                raise ResponseConflictError("This proposal already has a dispatch claim; it cannot be executed again.")
            self._support(connection, row)
            proposal = self._proposal(row)
            allowed = self._policy(snapshot).evaluate(proposal, IncidentDisposition(case.disposition),
                AnalystApproval(proposal.fingerprint, review["actor"], datetime.fromisoformat(review["created_at"])))
            if not allowed.allowed:
                raise ResponseError(" ".join(allowed.reasons))
            execution_id, token, now = uuid4().hex, uuid4().hex, utc_now()
            if proposal.action == "block_ip":
                ip = proposal.parameters["ip_address"]
                if connection.execute("SELECT 1 FROM response_block_leases WHERE target=? AND address=? AND status NOT IN ('released','unmanaged')",
                                      (proposal.target, ip)).fetchone():
                    raise ResponseConflictError("This target/address already has an active or unresolved block lease.")
            append_case_event(connection, case.case_id, "response_dispatch_claimed", actor, reason,
                              {"proposal_id": proposal_id, "execution_id": execution_id, "approved_case_version": case.version})
            connection.execute("""INSERT INTO response_executions(execution_id,proposal_id,claim_token,status,actor,case_version,claimed_at)
                VALUES(?,?,?,'dispatching',?,?,?)""", (execution_id, proposal_id, token, actor, case.version + 1, now.isoformat()))
            if proposal.action == "block_ip":
                connection.execute("""INSERT INTO response_block_leases(execution_id,target,address,target_revision,expires_at,status,updated_at)
                    VALUES(?,?,?,?,?,'scheduled',?)""", (execution_id, proposal.target, proposal.parameters["ip_address"],
                    snapshot.target_revision, (now + timedelta(seconds=int(proposal.parameters["duration_seconds"]))).isoformat(), now.isoformat()))
            return ExecutionRequest(execution_id, token, proposal_id, proposal, case.version + 1, snapshot.revision)

    @staticmethod
    def _execution_event(connection, execution_id, kind, actor, reason, details):
        connection.execute("INSERT INTO response_execution_events(execution_id,kind,actor,reason,details_json,recorded_at) VALUES(?,?,?,?,?,?)",
                           (execution_id, kind, actor, reason, canonical(details), utc_now().isoformat()))

    def finish(self, request: ExecutionRequest, outcome: ExecutionOutcome):
        with self._session(True) as connection:
            changed = connection.execute("""UPDATE response_executions SET status=?,finished_at=?,outcome_json=?
                WHERE execution_id=? AND proposal_id=? AND claim_token=? AND status='dispatching'""",
                (outcome.status, utc_now().isoformat(), outcome.summary_json, request.execution_id, request.proposal_id, request.claim_token)).rowcount
            if changed != 1:
                raise ResponseConflictError("Execution is no longer owned by this dispatch claim.")
            details = json.loads(outcome.summary_json)
            lease_status = "scheduled" if outcome.status == "succeeded" else ("unknown" if details.get("cleanup_required", outcome.status == "unknown") else "unmanaged")
            connection.execute("UPDATE response_block_leases SET status=?,updated_at=? WHERE execution_id=?",
                               (lease_status, utc_now().isoformat(), request.execution_id))
            self._execution_event(connection, request.execution_id, "dispatch_finished", "system:response", "Executor outcome recorded.", details)
            append_case_event(connection, request.proposal.case_id, "response_" + outcome.status, "system:response", "Response dispatch outcome recorded.",
                              {"proposal_id": request.proposal_id, "execution_id": request.execution_id, "status": outcome.status})
            return self._get(connection, request.proposal_id)

    def reconcile(self, execution_id, outcome, actor, reason, evidence):
        with self._session(True) as connection:
            execution = connection.execute("SELECT * FROM response_executions WHERE execution_id=?", (execution_id,)).fetchone()
            if execution is None or execution["status"] not in {"dispatching", "unknown"}:
                raise ResponseConflictError("Only unresolved executions can be reconciled.")
            row = self._row(connection, execution["proposal_id"])
            status = "succeeded" if outcome == "applied" else "failed"
            connection.execute("UPDATE response_executions SET status=?,finished_at=?,outcome_json=? WHERE execution_id=?",
                (status, utc_now().isoformat(), canonical({"code": "operator_reconciled", "outcome": outcome, "evidence": evidence}), execution_id))
            connection.execute("UPDATE response_block_leases SET status=?,updated_at=? WHERE execution_id=?",
                               ("scheduled" if outcome == "applied" else "unmanaged", utc_now().isoformat(), execution_id))
            self._execution_event(connection, execution_id, "operator_reconciled", actor, reason, {"outcome": outcome, "evidence": evidence})
            append_case_event(connection, row["case_id"], "response_reconciled", actor, reason, {"execution_id": execution_id, "outcome": outcome, "evidence": evidence})
            return self._get(connection, row["proposal_id"])

    def claim_expired_block(self, target_revision: str):
        with self._session(True) as connection:
            row = connection.execute("""SELECT l.*,p.case_id,p.proposal_id FROM response_block_leases l
                JOIN response_executions e ON e.execution_id=l.execution_id JOIN response_proposals p ON p.proposal_id=e.proposal_id
                WHERE l.status='scheduled' AND e.status='succeeded' AND l.expires_at<=? ORDER BY l.expires_at LIMIT 1""", (utc_now().isoformat(),)).fetchone()
            if row is None:
                return None
            if row["target_revision"] != target_revision:
                raise ResponseConflictError("An expired block uses different firewall configuration; reconcile it before changing targets.")
            token = uuid4().hex
            connection.execute("UPDATE response_block_leases SET status='releasing',claim_token=?,updated_at=? WHERE execution_id=?",
                               (token, utc_now().isoformat(), row["execution_id"]))
            return {**dict(row), "claim_token": token}

    def finish_block_release(self, lease, released: bool):
        with self._session(True) as connection:
            changed = connection.execute("""UPDATE response_block_leases SET status=?,last_code=?,updated_at=?,claim_token=NULL
                WHERE execution_id=? AND status='releasing' AND claim_token=?""", ("released" if released else "unknown",
                "expiry_removed" if released else "expiry_unknown", utc_now().isoformat(), lease["execution_id"], lease["claim_token"])).rowcount
            if changed != 1:
                raise ResponseConflictError("The block release claim is no longer valid.")
            self._execution_event(connection, lease["execution_id"], "block_release", "system:response-expiry", "Block expiry removal attempted.", {"released": released})
            append_case_event(connection, lease["case_id"], "response_block_released" if released else "response_block_release_unknown",
                              "system:response-expiry", "Block expiry outcome recorded.", {"execution_id": lease["execution_id"]})
            return {"execution_id": lease["execution_id"], "status": "released" if released else "unknown"}

    def reconcile_block_release(self, execution_id, actor, reason, evidence):
        with self._session(True) as connection:
            row = connection.execute("SELECT l.*,p.case_id,e.status AS execution_status FROM response_block_leases l JOIN response_executions e ON e.execution_id=l.execution_id JOIN response_proposals p ON p.proposal_id=e.proposal_id WHERE l.execution_id=?", (execution_id,)).fetchone()
            if row is None or row["status"] not in {"unknown", "releasing"} or row["execution_status"] != "succeeded":
                raise ResponseConflictError("Only an unresolved block release can be reconciled.")
            connection.execute("UPDATE response_block_leases SET status='released',claim_token=NULL,updated_at=?,last_code='operator_verified_absent' WHERE execution_id=?", (utc_now().isoformat(), execution_id))
            self._execution_event(connection, execution_id, "release_reconciled", actor, reason, {"evidence": evidence})
            append_case_event(connection, row["case_id"], "response_block_release_reconciled", actor, reason, {"execution_id": execution_id, "evidence": evidence})
            return {"execution_id": execution_id, "status": "released"}
