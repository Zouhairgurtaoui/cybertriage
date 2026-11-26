import argparse
import sys
from importlib.metadata import version
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

from cybertriage.domain.security_event import EventIdentity


MAX_EVIDENCE_BYTES = 4000


def read_evidence(path: Path) -> str:
    with path.open("rb") as file:
        content = file.read(MAX_EVIDENCE_BYTES + 1)

    if len(content) > MAX_EVIDENCE_BYTES:
        raise ValueError(
            f"Evidence file exceeds {MAX_EVIDENCE_BYTES} bytes."
        )

    evidence = content.decode("utf-8-sig").strip()

    if not evidence:
        raise ValueError("Evidence file is empty.")

    return evidence


def _read_indexer_password() -> str:
    import getpass

    if not sys.stdin.isatty():
        raise ValueError("Set CYBERTRIAGE_INDEXER_PASSWORD for non-interactive investigation.")
    return getpass.getpass("Read-only Indexer password: ")


def _run() -> None:
    parser = argparse.ArgumentParser(
        prog="cybertriage",
        description="Investigate security alerts using reference knowledge.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"CyberTriage {version('cybertriage')}",
    )

    commands = parser.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser(
        "analyze",
        help="Analyse incident evidence using the local knowledge index.",
    )
    analyze.add_argument("--evidence", type=Path, required=True)
    analyze.add_argument(
        "--query",
        help="Focused knowledge search query; defaults to the evidence.",
    )
    analyze.add_argument(
        "--database",
        type=Path,
        default=Path("data/chroma"),
    )
    analyze.add_argument("--event-id", type=int)
    analyze.add_argument("--model", help="Override the configured local Ollama model.")
    analyze.add_argument("--output", type=Path, help="Save the text report and references in a JSON file.")
    analyze.add_argument("--provider")
    analyze.add_argument("--channel")
    analyze.add_argument("--sources-config", type=Path, default=Path("config/sources.yaml"))
    analyze.add_argument(
        "--catalog",
        type=Path,
        default=Path("data/catalogs/windows-security.json"),
    )
    analyze.add_argument(
        "--investigate",
        action="store_true",
        help="Enable bounded read-only investigation tool calls.",
    )
    analyze.add_argument(
        "--task",
        help="Analyst investigation instruction; requires --investigate.",
    )
    ingest = commands.add_parser(
        "ingest",
        help="Fetch, chunk, and store reference knowledge.",
    )
    ingest.add_argument(
        "--source",
        choices=["mitre", "microsoft"],
        required=True,
    )
    ingest.add_argument(
        "--database",
        type=Path,
        default=Path("data/chroma"),
    )
    ingest.add_argument("--sources-config", type=Path, default=Path("config/sources.yaml"))
    catalog_update = commands.add_parser(
        "catalog-update",
        help="Update the local Windows Security event catalogue.",
    )
    catalog_update.add_argument(
        "--output",
        type=Path,
        default=Path("data/catalogs/windows-security.json"),
    )
    catalog_update.add_argument("--sources-config", type=Path, default=Path("config/sources.yaml"))

    response_policy = commands.add_parser(
        "response-policy",
        help="Preview configured action eligibility; never approve or execute an action.",
    )
    response_policy.add_argument("--case-id", required=True)
    response_policy.add_argument("--action", required=True)
    response_policy.add_argument("--target", required=True)
    response_policy.add_argument("--parameters-file", type=Path, required=True)
    response_policy.add_argument(
        "--disposition",
        choices=["unconfirmed", "confirmed_compromise", "benign"],
        default="unconfirmed",
        help="What-if case status for this preview; this does not create a case-review record.",
    )
    response_policy.add_argument("--config", type=Path, default=Path("config/response_actions.yaml"))

    event_lookup = commands.add_parser(
        "event-lookup",
        help="Look up a locally stored event definition.",
    )
    event_lookup.add_argument("--event-id", type=int, required=True)
    event_lookup.add_argument(
        "--provider",
        default="Microsoft-Windows-Security-Auditing",
    )
    event_lookup.add_argument(
        "--channel",
        default="Security",
    )
    event_lookup.add_argument(
        "--catalog",
        type=Path,
        default=Path("data/catalogs/windows-security.json"),
    )

    serve = commands.add_parser(
        "serve",
        help="Run the authenticated Wazuh ingestion API.",
    )
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--triage-config", type=Path, default=Path("config/triage.yaml"))
    serve.add_argument(
        "--database",
        type=Path,
        default=Path("data/alerts/alerts.sqlite3"),
    )
    serve.add_argument(
        "--max-connections",
        type=int,
        default=16,
    )

    stored = commands.add_parser(
        "analyze-stored",
        help="Investigate a received alert stored in SQLite.",
    )
    stored.add_argument("--record-id", required=True)
    stored.add_argument("--investigate", action="store_true", help="Enable application-scoped read-only tool calls.")
    stored.add_argument("--query")
    stored.add_argument("--model")
    stored.add_argument("--output", type=Path)
    stored.add_argument(
        "--alerts-database",
        type=Path,
        default=Path("data/alerts/alerts.sqlite3"),
    )
    stored.add_argument(
        "--database",
        type=Path,
        default=Path("data/chroma"),
    )
    stored.add_argument(
        "--catalog",
        type=Path,
        default=Path("data/catalogs/windows-security.json"),
    )
    stored.add_argument(
        "--sources-config",
        type=Path,
        default=Path("config/sources.yaml"),
    )

    worker = commands.add_parser(
        "worker",
        help="Process queued alert investigations.",
    )
    worker.add_argument(
        "--alerts-database",
        type=Path,
        default=Path("data/alerts/alerts.sqlite3"),
    )
    worker.add_argument(
        "--database",
        type=Path,
        default=Path("data/chroma"),
    )
    worker.add_argument(
        "--catalog",
        type=Path,
        default=Path("data/catalogs/windows-security.json"),
    )
    worker.add_argument(
        "--sources-config",
        type=Path,
        default=Path("config/sources.yaml"),
    )
    worker.add_argument("--model")
    worker.add_argument("--investigate", action="store_true", help="Enable application-scoped read-only tool calls for queued alerts.")
    worker.add_argument("--once", action="store_true")
    worker.add_argument(
        "--job-id",
        help="Process one specific eligible job; requires --once.",
    )
    worker.add_argument("--lease-seconds", type=int, default=600)
    worker.add_argument("--max-attempts", type=int, default=3)
    worker.add_argument("--retry-delay-seconds", type=int, default=30)
    worker.add_argument("--poll-seconds", type=float, default=2.0)

    authentication = commands.add_parser(
        "search-authentication",
        help="Search related Windows logon events in Wazuh.",
    )
    authentication.add_argument("--account", required=True)
    authentication.add_argument("--domain", required=True)
    authentication.add_argument(
        "--start",
        required=True,
        type=datetime.fromisoformat,
        help="ISO timestamp with timezone.",
    )
    authentication.add_argument(
        "--end",
        required=True,
        type=datetime.fromisoformat,
        help="ISO timestamp with timezone.",
    )
    authentication.add_argument("--limit", type=int, default=50)
    authentication.add_argument("--output", type=Path)

    for name, help_text in (
        ("triage-inspect", "Inspect triage history, group members, and analyst feedback."),
        ("triage-feedback", "Append an analyst label; malicious or uncertain labels release unscheduled alerts."),
        ("triage-release", "Request individual analysis without changing an analyst label."),
        ("triage-evaluate", "Evaluate original scheduling decisions against latest analyst labels."),
    ):
        review = commands.add_parser(name, help=help_text)
        review.add_argument("--alerts-database", type=Path, default=Path("data/alerts/alerts.sqlite3"))
        if name != "triage-evaluate":
            review.add_argument("--record-id", required=True)
        if name in ("triage-feedback", "triage-release"):
            review.add_argument("--analyst", required=True)
            review.add_argument("--reason", required=True)
        if name == "triage-feedback":
            review.add_argument("--label", required=True, choices=["benign", "malicious", "uncertain"])
        if name == "triage-evaluate":
            review.add_argument("--output", type=Path)

    triage_policy = commands.add_parser("triage-policy", help="Validate triage configuration and show its revision.")
    triage_policy.add_argument("--config", type=Path, default=Path("config/triage.yaml"))

    from cybertriage.entrypoints.cases import register_case_commands, dispatch_case_command
    register_case_commands(commands)
    args = parser.parse_args()

    if dispatch_case_command(args):
        return

    if args.command == "triage-policy":
        import json
        from cybertriage.adapters.configuration.triage_yaml import YamlTriageConfiguration
        from cybertriage.application.policies.alert_triage import AlertTriagePolicy
        settings = YamlTriageConfiguration(args.config).load()
        policy = AlertTriagePolicy(settings)
        print(json.dumps({"policy_revision": policy.revision, "enabled": settings.enabled,
                          "suppression_rule_count": len(settings.suppression_rules),
                          "grouping_rule_count": len(settings.grouping_rules)}, indent=2))
        return

    if args.command in ("triage-inspect", "triage-feedback", "triage-release", "triage-evaluate"):
        import json
        from cybertriage.bootstrap import build_triage_evaluation, build_triage_review
        from cybertriage.domain.triage_policy import AnalystFeedback

        if args.command == "triage-evaluate":
            output = build_triage_evaluation(args.alerts_database.resolve()).execute()
            if args.output is not None:
                from cybertriage.adapters.storage.json_files import atomic_write_json
                atomic_write_json(args.output, output)
        else:
            review_service = build_triage_review(args.alerts_database.resolve())
            if args.command == "triage-inspect":
                output = dict(review_service.inspect(args.record_id))
            elif args.command == "triage-feedback":
                output = dict(review_service.feedback(AnalystFeedback(
                    args.record_id, args.analyst, args.label, args.reason,
                )))
            else:
                output = dict(review_service.release(args.record_id, args.analyst, args.reason))
        print(json.dumps(output, indent=2, ensure_ascii=True, allow_nan=False))
        return

    if args.command == "analyze":
        if args.investigate:
            from cybertriage.domain.agent import validate_investigation_task

            try:
                args.task = validate_investigation_task(args.task)
            except ValueError as error:
                parser.error(f"--investigate requires a valid --task: {error}")
        elif args.task is not None:
            parser.error("--task requires --investigate.")

    if args.command == "serve":
        import os

        if not 1 <= args.port <= 65535:
            parser.error("--port must be between 1 and 65535.")

        if args.max_connections <= 0:
            parser.error("--max-connections must be positive.")

        token = os.environ.get("CYBERTRIAGE_INGEST_TOKEN")

        if not token:

            parser.error(
                "Set the CYBERTRIAGE_INGEST_TOKEN environment variable "
                "before starting the ingestion API."
            )

        import uvicorn

        from cybertriage.bootstrap import build_ingestion_api

        app = build_ingestion_api(
            database_path=args.database.resolve(),
            token=token,
            triage_config_path=args.triage_config,
        )

        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            workers=1,
            limit_concurrency=args.max_connections,
            proxy_headers=False,
        )
        return

    if args.command == "response-policy":
        import json

        from cybertriage.bootstrap import build_response_preview
        from cybertriage.domain.response import ActionProposal, IncidentDisposition

        def unique_parameters(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate keys in action parameters.")
                result[key] = value
            return result

        with args.parameters_file.open("rb") as file:
            raw = file.read(4097)
        if len(raw) > 4096:
            raise ValueError("Action parameters exceed the size limit.")
        parameters = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_parameters)
        if not isinstance(parameters, dict):
            raise ValueError("Action parameters must be a JSON object.")
        proposal = ActionProposal(args.case_id, args.action, args.target, parameters)
        decision = build_response_preview(args.config).execute(
            proposal, IncidentDisposition(args.disposition),
        )
        print("Policy preview only; no approval was created and no action was executed.")
        print(f"Proposal fingerprint: {proposal.fingerprint}")
        print(f"Eligible for execution: {decision.allowed}")
        for reason in decision.reasons:
            print(f"- {reason}")
        return

    if args.command == "event-lookup":
        from cybertriage.bootstrap import load_event_catalog

        catalog = load_event_catalog(args.catalog.resolve())

        definition = catalog.lookup(
            provider=args.provider,
            channel=args.channel,
            event_id=args.event_id,
        )

        if definition is None:
            parser.exit(
                status=2,
                message=(
                    "No definition available for "
                    f"{args.provider}/{args.channel}/{args.event_id}.\n"
                ),
            )

        print(f"Event ID: {definition.event_id}")
        print(f"Provider: {definition.provider}")
        print(f"Channel: {definition.channel}")
        print(f"Definition: {definition.description}")
        print(f"Source: {definition.source_url}")
        print(f"Revision: {definition.source_revision}")
        return

    if args.command == "catalog-update":
        from cybertriage.bootstrap import build_catalog_update

        snapshot_path = args.output.resolve()

        print("Updating event catalogue...", file=sys.stderr)
        count = build_catalog_update(snapshot_path, args.sources_config).execute()

        print(f"Definitions saved: {count}")
        print(f"Snapshot: {snapshot_path}")
        return

    if args.command == "ingest":
        import logging

        from cybertriage.bootstrap import build_knowledge_ingestion

        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
        )

        use_case = build_knowledge_ingestion(
            args.source, args.database.resolve(), args.sources_config,
        )
        result = use_case.execute()

        print(f"Documents: {result.documents}")
        print(f"Chunks: {result.chunks}")
        print(f"New chunks stored: {result.added}")
        return

    if args.command == "analyze-stored":
        from dataclasses import asdict

        from cybertriage.adapters.storage.json_files import (
            atomic_write_json,
        )
        from cybertriage.bootstrap import build_analyze_stored_alert

        use_case = build_analyze_stored_alert(
            alerts_database_path=args.alerts_database.resolve(),
            database_directory=args.database.resolve(),
            catalog_path=args.catalog.resolve(),
            model_name=args.model,
            sources_config_path=args.sources_config,
            investigate=args.investigate,
            password_supplier=_read_indexer_password if args.investigate else None,
        )

        print(
            "Retrieving references and analysing the stored alert...",
            file=sys.stderr,
        )

        record = use_case.execute(
            record_id=args.record_id,
            retrieval_query=args.query,
        )
        result = record.result

        print(f"Analysis ID: {record.analysis_id}")
        print(f"Alert ID: {record.alert_record_id}")
        print(f"Completed at: {record.completed_at.isoformat()}")

        if args.output is not None:
            payload = asdict(record)
            payload["completed_at"] = record.completed_at.isoformat()

            atomic_write_json(args.output, payload)

        print("Model analysis (provisional; analyst review required):")
        print(result.analysis)
        if args.investigate:
            print("\nInvestigation tool activity:")
            if not result.tool_executions:
                print("No tools were requested by the model.")
            for execution in result.tool_executions:
                print(f"- {execution.tool_name}: {execution.status} (call ID: {execution.call_id})")
        print("\nRetrieved references:")

        if not result.references:
            print("None.")

        for number, reference in enumerate(result.references, start=1):
            print(f"[R{number}] {reference.title}")
            print(f"  Source: {reference.source_url}")
            print(f"  Chunk: {reference.chunk_id}")

        return
    if args.command == "worker":
        import logging
        import signal
        from threading import Event

        from cybertriage.bootstrap import build_analysis_worker

        if args.job_id is not None and not args.once:
            parser.error("--job-id requires --once.")

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )

        service = build_analysis_worker(
            alerts_database_path=args.alerts_database.resolve(),
            database_directory=args.database.resolve(),
            catalog_path=args.catalog.resolve(),
            model_name=args.model,
            sources_config_path=args.sources_config,
            lease_seconds=args.lease_seconds,
            max_attempts=args.max_attempts,
            retry_delay_seconds=args.retry_delay_seconds,
            poll_seconds=args.poll_seconds,
            investigate=args.investigate,
            password_supplier=_read_indexer_password if args.investigate else None,
        )

        stop = Event()

        def request_stop(signum, frame):
            stop.set()
            logging.getLogger(__name__).info(
                "Shutdown requested; finishing the current job"
            )

        previous_handlers = {}

        try:
            for signum in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[signum] = signal.signal(
                    signum,
                    request_stop,
                )

            service.run(
                stop,
                once=args.once,
                job_id=args.job_id,
            )

        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)

        return

    if args.command == "search-authentication":
        import getpass
        import json
        from dataclasses import asdict

        from cybertriage.adapters.storage.json_files import atomic_write_json
        from cybertriage.bootstrap import build_authentication_search
        from cybertriage.domain.investigation import AuthenticationSearchRequest

        request = AuthenticationSearchRequest(
            account_name=args.account,
            account_domain=args.domain,
            start=args.start,
            end=args.end,
            limit=args.limit,
        )

        def read_password() -> str:
            if not sys.stdin.isatty():
                parser.error(
                    "Set CYBERTRIAGE_INDEXER_PASSWORD "
                    "for non-interactive searches."
                )

            return getpass.getpass("Read-only Indexer password: ")

        searcher = build_authentication_search(
            password_supplier=read_password,
        )
        result = searcher.search(request)

        payload = {
            "request": {
                "account_name": result.request.account_name,
                "account_domain": result.request.account_domain,
                "start": result.request.start.isoformat(),
                "end": result.request.end.isoformat(),
                "limit": result.request.limit,
            },
            "searched_at": result.searched_at.isoformat(),
            "has_more": result.has_more,
            "coverage": result.coverage,
            "events": [
                {
                    **asdict(event),
                    "timestamp": event.timestamp.isoformat(),
                }
                for event in result.events
            ],
        }

        if args.output is not None:
            atomic_write_json(args.output, payload)

        print(json.dumps(
            payload,
            indent=2,
            ensure_ascii=True,
            allow_nan=False,
        ))
        return

    evidence = read_evidence(args.evidence)


    event_fields = (args.event_id, args.provider, args.channel)
    event = None

    if any(value is not None for value in event_fields):
        if not all(value is not None for value in event_fields):
            parser.error(
                "--event-id, --provider and --channel must be supplied together."
            )

        event = EventIdentity(
            provider=args.provider,
            channel=args.channel,
            event_id=args.event_id,
        )

    from cybertriage.bootstrap import build_analyze_alert

    def read_investigation_password() -> str:
        import getpass

        if not sys.stdin.isatty():
            parser.error(
                "Set CYBERTRIAGE_INDEXER_PASSWORD "
                "for non-interactive investigation."
            )

        return getpass.getpass("Read-only Indexer password: ")

    use_case = build_analyze_alert(
        database_directory=args.database.resolve(),
        catalog_path=args.catalog.resolve() if event is not None else None,
        model_name=args.model,
        sources_config_path=args.sources_config,
        investigate=args.investigate,
        password_supplier=(
            read_investigation_password
            if args.investigate
            else None
        ),
    )

    print("Retrieving references and analysing evidence...", file=sys.stderr)

    result = use_case.execute(
        evidence=evidence,
        retrieval_query=args.query,
        event=event,
        investigation_task=args.task,
    )
    if args.output is not None:
        from dataclasses import asdict
        from cybertriage.adapters.storage.json_files import atomic_write_json

        atomic_write_json(args.output, asdict(result))
    if event is not None:
        print("Catalogue event definition:")

        if result.event_definition is None:
            print("No definition available in the local catalogue.")
        else:
            print(
                f"{result.event_definition.event_id}: "
                f"{result.event_definition.description}"
            )
            print(f"Source: {result.event_definition.source_url}")

        print()
    print("Model analysis (provisional; analyst review required):")
    print(result.analysis)

    if args.investigate:
        print("\nInvestigation tool activity:")

        if not result.tool_executions:
            print("No tools were requested by the model.")

        for execution in result.tool_executions:
            print(
                f"- {execution.tool_name}: {execution.status} "
                f"(call ID: {execution.call_id})"
            )

    print("\nRetrieved references:")

    if not result.references:
        print("None.")

    for number, reference in enumerate(result.references, start=1):
        print(f"[R{number}] {reference.title}")
        print(f"  Source: {reference.source_url}")
        print(f"  Chunk: {reference.chunk_id}")

       


def main() -> None:
    try:
        load_dotenv(
            dotenv_path=Path.cwd() / ".env.local",
            override=False,
            interpolate=False,
            encoding="utf-8",
        )
        _run()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as error:
        print(
            f"CyberTriage failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
