"""Explicit local response operations; no action executes as a side effect of review."""

import argparse
import json
import time
from pathlib import Path

from cybertriage.domain.response_workflow import ResponseError

COMMANDS = {"response-propose", "response-review", "response-show", "response-list", "response-execute",
            "response-reconcile", "response-release-reconcile", "response-expiry-worker"}


def register_response_commands(commands):
    for name in sorted(COMMANDS):
        parser = commands.add_parser(name, help={
            "response-propose": "Persist an evidence-backed action proposal; never execute it.",
            "response-review": "Approve, reject or revoke an exact stored proposal.",
            "response-show": "Read a response proposal and its complete execution history.",
            "response-list": "List response proposals for a case.",
            "response-execute": "Dispatch one current approved action through its allowlisted adapter.",
            "response-reconcile": "Record a verified outcome after stopping an unresolved dispatcher.",
            "response-release-reconcile": "Record verified removal after stopping an unresolved expiry worker.",
            "response-expiry-worker": "Remove expired application-managed IP blocks; never create new blocks.",
        }[name])
        parser.add_argument("--alerts-database", type=Path, default=Path("data/alerts/alerts.sqlite3"))
        parser.add_argument("--config", type=Path, default=Path("config/response_actions.yaml"))
        parser.add_argument("--firewalls-config", type=Path, default=Path("config/firewalls.yaml"))
        if name in {"response-propose", "response-list"}:
            parser.add_argument("--case-id", required=True)
        if name in {"response-review", "response-show", "response-execute"}:
            parser.add_argument("--proposal-id", required=True)
        if name in {"response-propose", "response-review", "response-execute"}:
            parser.add_argument("--expected-version", type=int, required=True)
        if name in {"response-propose", "response-review", "response-execute", "response-reconcile", "response-release-reconcile"}:
            parser.add_argument("--actor", required=True)
            parser.add_argument("--reason", required=True)
        if name == "response-propose":
            parser.add_argument("--action", required=True)
            parser.add_argument("--target", required=True)
            parser.add_argument("--parameters-file", type=Path, required=True)
            parser.add_argument("--supporting-alert-id", action="append", required=True)
            parser.add_argument("--idempotency-key", required=True)
            parser.add_argument("--analysis-id")
            parser.add_argument("--origin", choices=["operator", "application", "model"], default="operator")
        if name == "response-review":
            parser.add_argument("--decision", choices=["approved", "rejected", "revoked"], required=True)
        if name in {"response-reconcile", "response-release-reconcile"}:
            parser.add_argument("--execution-id", required=True)
            parser.add_argument("--evidence", required=True, help="Verified firewall evidence; stop the unresolved process before reconciliation.")
        if name == "response-reconcile":
            parser.add_argument("--outcome", choices=["applied", "not_applied"], required=True)
        if name == "response-list":
            parser.add_argument("--limit", type=int, default=50)
            parser.add_argument("--after", type=int, default=0)
        if name == "response-expiry-worker":
            parser.add_argument("--once", action="store_true")
            parser.add_argument("--poll-seconds", type=int, default=5)


def dispatch_response_command(args: argparse.Namespace) -> bool:
    if args.command not in COMMANDS:
        return False
    from cybertriage.bootstrap import build_response_runtime
    workflow, expiry, repository = build_response_runtime(args.alerts_database.resolve(), args.config, args.firewalls_config)
    name = args.command
    if name == "response-propose":
        with args.parameters_file.open("rb") as file:
            content = file.read(4097)
        if len(content) > 4096:
            raise ResponseError("Response parameters file exceeds 4096 bytes.")
        from cybertriage.entrypoints.api.app import _unique_object, _reject_constant
        parameters = json.loads(content.decode("utf-8-sig"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        output = workflow.propose(args.case_id, args.action, args.target, parameters, args.supporting_alert_id,
            args.expected_version, args.actor, args.reason, args.idempotency_key, args.origin, args.analysis_id)
    elif name == "response-review":
        output = workflow.review(args.proposal_id, args.decision, args.expected_version, args.actor, args.reason)
    elif name == "response-execute":
        output = workflow.execute(args.proposal_id, args.expected_version, args.actor, args.reason)
    elif name == "response-show":
        output = workflow.get(args.proposal_id)
    elif name == "response-list":
        output = workflow.list(args.case_id, args.limit, args.after)
    elif name == "response-reconcile":
        output = workflow.reconcile(args.execution_id, args.outcome, args.actor, args.reason, args.evidence)
    elif name == "response-release-reconcile":
        output = workflow.reconcile_release(args.execution_id, args.actor, args.reason, args.evidence)
    else:
        if not 1 <= args.poll_seconds <= 300:
            raise ResponseError("Expiry polling interval must be 1..300 seconds.")
        while True:
            try:
                output = expiry.execute()
                print(json.dumps(output, ensure_ascii=False), flush=True)
            except Exception:
                print(json.dumps({"status": "error", "code": "expiry_worker_failed", "requires_operator_review": True}), flush=True)
                if args.once:
                    raise
                time.sleep(args.poll_seconds)
                continue
            if args.once:
                return True
            if output["status"] in {"idle", "unknown"}:
                time.sleep(args.poll_seconds)
    print(json.dumps(output, indent=2, ensure_ascii=False, allow_nan=False))
    return True
