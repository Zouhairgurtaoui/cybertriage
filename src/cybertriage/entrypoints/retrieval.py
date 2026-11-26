"""Inspect retrieval and provenance without generating an LLM report."""

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from cybertriage.domain.retrieval import RetrievalContext
from cybertriage.domain.security_event import EventIdentity


def register_retrieval_command(commands: argparse._SubParsersAction) -> None:
    parser = commands.add_parser("retrieve", help="Inspect hybrid knowledge references and ranking provenance without a chat-model call.")
    parser.add_argument("--query", required=True)
    parser.add_argument("--k", type=int, default=3)
    parser.add_argument("--database", type=Path, default=Path("data/chroma"))
    parser.add_argument("--sources-config", type=Path, default=Path("config/sources.yaml"))
    parser.add_argument("--event-id", type=int)
    parser.add_argument("--provider")
    parser.add_argument("--channel")
    parser.add_argument("--platform", choices=["windows", "linux", "macos"])
    parser.add_argument("--catalog", type=Path, default=Path("data/catalogs/windows-security.json"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--offline-knowledge", action="store_true", help="Inspect only the local knowledge corpus.")


def dispatch_retrieval_command(args: argparse.Namespace) -> bool:
    if args.command != "retrieve":
        return False
    from cybertriage.bootstrap import build_knowledge_retriever, load_event_catalog
    fields = args.provider, args.channel, args.event_id
    if any(value is not None for value in fields) and not all(value is not None for value in fields):
        raise ValueError("--provider, --channel and --event-id must be supplied together.")
    event = EventIdentity(args.provider, args.channel, args.event_id) if args.event_id is not None else None
    definition = load_event_catalog(args.catalog.resolve()).lookup(event.provider, event.channel, event.event_id) if event else None
    context = RetrievalContext(event, definition.description if definition else None, args.platform)
    outcome = build_knowledge_retriever(args.database.resolve(), args.sources_config,
        offline_knowledge=args.offline_knowledge).retrieve_for(args.query, context, args.k)
    payload = {"query": args.query, "references": [asdict(reference) for reference in outcome.references], "trace": json.loads(outcome.trace_json)}
    if args.output is not None:
        from cybertriage.adapters.storage.json_files import atomic_write_json
        atomic_write_json(args.output, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False))
    return True
