"""Operational CLI for the authenticated backend and its independent workers."""

import argparse
import getpass
import ipaddress
import json
import logging
import os
import secrets
import sys
import time
from hashlib import sha256
from pathlib import Path
from threading import Event

COMMANDS = {"analyst-key", "serve-analyst", "request-investigation", "investigation-status", "investigation-worker", "graph-worker", "case-candidates"}


def register_backend_commands(commands):
    for name in sorted(COMMANDS):
        parser = commands.add_parser(name, help={
            "analyst-key": "Generate an analyst bearer token and its configuration hash; display the token once.",
            "serve-analyst": "Run the separately authenticated analyst API.",
            "request-investigation": "Queue an explicit case re-investigation without replacing automatic jobs.",
            "investigation-status": "Read a requested investigation's status and saved report ID.",
            "investigation-worker": "Process explicitly requested investigations with scoped read-only tools.",
            "graph-worker": "Publish changed case versions to Neo4j with durable delivery cursors.",
            "case-candidates": "Suggest related retained alerts without attaching or classifying them.",
        }[name])
        if name == "analyst-key":
            continue
        parser.add_argument("--alerts-database", type=Path, default=Path("data/alerts/alerts.sqlite3"))
        if name == "serve-analyst":
            parser.add_argument("--credentials", type=Path, default=Path("config/analysts.local.yaml"))
            parser.add_argument("--response-config", type=Path, default=Path("config/response_actions.yaml"))
            parser.add_argument("--firewalls-config", type=Path, default=Path("config/firewalls.yaml"))
            parser.add_argument("--host", default="127.0.0.1")
            parser.add_argument("--port", type=int, default=8001)
            parser.add_argument("--tls-certificate", type=Path)
            parser.add_argument("--tls-key", type=Path)
        if name in {"request-investigation", "investigation-status", "case-candidates"}:
            parser.add_argument("--case-id", required=True)
        if name == "case-candidates":
            parser.add_argument("--anchor-alert-id", required=True)
            parser.add_argument("--window-seconds", type=int, default=300)
            parser.add_argument("--limit", type=int, default=20)
        if name == "request-investigation":
            parser.add_argument("--alert-id", required=True)
            parser.add_argument("--task", required=True)
            parser.add_argument("--expected-version", type=int, required=True)
            parser.add_argument("--actor", required=True)
            parser.add_argument("--idempotency-key", required=True)
        if name == "investigation-status":
            parser.add_argument("--job-id", required=True)
        if name in {"investigation-worker", "graph-worker"}:
            parser.add_argument("--once", action="store_true")
        if name == "investigation-worker":
            parser.add_argument("--database", type=Path, default=Path("data/chroma"))
            parser.add_argument("--catalog", type=Path, default=Path("data/catalogs/windows-security.json"))
            parser.add_argument("--sources-config", type=Path, default=Path("config/sources.yaml"))
            parser.add_argument("--model")
            parser.add_argument("--offline-knowledge", action="store_true")
            parser.add_argument("--job-id")
        if name == "graph-worker":
            parser.add_argument("--poll-seconds", type=int, default=5)


def dispatch_backend_command(args: argparse.Namespace) -> bool:
    if args.command not in COMMANDS:
        return False
    name = args.command
    if name == "analyst-key":
        token = secrets.token_urlsafe(32)
        print(json.dumps({"token": token, "token_sha256": sha256(token.encode("ascii")).hexdigest()}, indent=2))
        return True
    if name == "serve-analyst":
        import uvicorn
        from cybertriage.entrypoints.api.analyst import create_analyst_app
        loopback = args.host.lower() == "localhost"
        try:
            loopback = loopback or ipaddress.ip_address(args.host).is_loopback
        except ValueError:
            pass
        tls = args.tls_certificate is not None and args.tls_key is not None
        if bool(args.tls_certificate) != bool(args.tls_key) or (not loopback and not tls):
            raise ValueError("Non-loopback analyst listeners require a TLS certificate and key; a local reverse proxy can target loopback.")
        if not 1 <= args.port <= 65535:
            raise ValueError("Analyst API port must be 1..65535.")
        app = create_analyst_app(args.alerts_database.resolve(), args.credentials, args.response_config, args.firewalls_config)
        uvicorn.run(app, host=args.host, port=args.port, access_log=False, limit_concurrency=32, timeout_keep_alive=5,
            ssl_certfile=str(args.tls_certificate) if tls else None, ssl_keyfile=str(args.tls_key) if tls else None)
        return True
    if name == "case-candidates":
        from cybertriage.adapters.storage.case_candidates import SqliteCaseCandidates
        output = SqliteCaseCandidates(args.alerts_database.resolve()).suggest(args.case_id, args.anchor_alert_id, args.window_seconds, args.limit)
        print(json.dumps(output, indent=2, ensure_ascii=False, allow_nan=False))
        return True
    if name in {"request-investigation", "investigation-status"}:
        from cybertriage.adapters.storage.investigation_requests import SqliteInvestigationRequests
        queue = SqliteInvestigationRequests(args.alerts_database.resolve())
        output = queue.request(args.case_id, args.alert_id, args.task, args.actor, args.expected_version, args.idempotency_key) if name == "request-investigation" else queue.get_request(args.case_id, args.job_id)
        print(json.dumps(output, indent=2, ensure_ascii=False, allow_nan=False))
        return True
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if name == "investigation-worker":
        from cybertriage.bootstrap import build_requested_investigation_worker
        if args.job_id is not None and not args.once:
            raise ValueError("Targeted investigation processing requires --once.")
        worker = build_requested_investigation_worker(args.alerts_database.resolve(), args.database, args.catalog,
            args.sources_config, model_name=args.model, offline_knowledge=args.offline_knowledge)
        worker.run(Event(), once=args.once, job_id=args.job_id)
        return True
    from cybertriage.adapters.configuration.neo4j_environment import EnvironmentNeo4jConfiguration
    from cybertriage.adapters.storage.case_graph_neo4j import Neo4jCaseGraphSink
    from cybertriage.adapters.storage.graph_sync_sqlite import SqliteGraphSyncState
    from cybertriage.bootstrap import build_case_graph_projection
    if not 1 <= args.poll_seconds <= 300:
        raise ValueError("Graph polling interval must be 1..300 seconds.")
    settings = EnvironmentNeo4jConfiguration().load()
    password = os.environ.get("CYBERTRIAGE_NEO4J_PASSWORD")
    if not password:
        if not sys.stdin.isatty():
            raise ValueError("Set CYBERTRIAGE_NEO4J_PASSWORD for the graph worker.")
        password = getpass.getpass("Neo4j projection password: ")
    sink = Neo4jCaseGraphSink.connect(settings, password)
    try:
        state = SqliteGraphSyncState(args.alerts_database.resolve(), settings.namespace)
        projection = build_case_graph_projection(args.alerts_database.resolve(), sink, settings.namespace)
        while True:
            case_id = state.next_case()
            if case_id is None:
                if args.once:
                    print(json.dumps({"status": "idle"}))
                    return True
                time.sleep(args.poll_seconds)
                continue
            try:
                receipt = projection.execute(case_id)
                state.record(case_id, receipt["source_version"])
                print(json.dumps(receipt, ensure_ascii=False), flush=True)
            except Exception:
                state.record(case_id, 0, "graph_sync_failed")
                logging.error("Graph synchronization failed case=%s; retry delayed", case_id)
                if args.once:
                    raise
            if args.once:
                return True
    finally:
        sink.close()
