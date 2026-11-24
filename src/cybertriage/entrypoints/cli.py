import argparse
import sys
from importlib.metadata import version
from pathlib import Path

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

    args = parser.parse_args()

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

    use_case = build_analyze_alert(
        database_directory=args.database.resolve(),
        catalog_path=args.catalog.resolve() if event is not None else None,
        model_name=args.model,
        sources_config_path=args.sources_config,
    )

    print("Retrieving references and analysing evidence...", file=sys.stderr)

    result = use_case.execute(
        evidence=evidence,
        retrieval_query=args.query,
        event=event,
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
    print("\nRetrieved references:")

    if not result.references:
        print("None.")

    for number, reference in enumerate(result.references, start=1):
        print(f"[R{number}] {reference.title}")
        print(f"  Source: {reference.source_url}")
        print(f"  Chunk: {reference.chunk_id}")

       


def main() -> None:
    try:
        _run()
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as error:
        # Surface transport, input, and generation failures without a partial report.
        print(f"CyberTriage failed: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
