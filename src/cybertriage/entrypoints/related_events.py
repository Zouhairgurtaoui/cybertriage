"""Explicit operator searches and host authority for file-based analysis."""

import argparse
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Callable

from cybertriage.domain.related_events import EVENT_FAMILIES, InvestigationScope, RelatedEventScope, RelatedEventSearchRequest


def register_related_event_command(commands: argparse._SubParsersAction) -> None:
    parser = commands.add_parser("search-events", help="Read related indexed alerts on an exact manager/agent within a bounded interval.")
    parser.add_argument("--source-instance", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--start", type=datetime.fromisoformat, required=True)
    parser.add_argument("--end", type=datetime.fromisoformat, required=True)
    parser.add_argument("--family", choices=EVENT_FAMILIES, default="all")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--account")
    parser.add_argument("--domain")
    parser.add_argument("--source-ip")
    parser.add_argument("--process-guid")
    parser.add_argument("--logon-id")
    parser.add_argument("--catalog", type=Path, default=Path("data/catalogs/windows-security.json"))
    parser.add_argument("--output", type=Path)


def add_investigation_scope_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source-instance", help="Authorize related-event searches on this exact manager; requires --agent-id, --start and --end.")
    parser.add_argument("--agent-id")
    parser.add_argument("--start", type=datetime.fromisoformat)
    parser.add_argument("--end", type=datetime.fromisoformat)
    parser.add_argument("--account", help="Optional authentication scope account; requires --domain and a host/time scope.")
    parser.add_argument("--domain")


def manual_investigation_scope(args: argparse.Namespace) -> InvestigationScope | None:
    values = (args.source_instance, args.agent_id, args.start, args.end, args.account, args.domain)
    if not any(value is not None for value in values):
        return None
    if not args.investigate or any(value is None for value in values[:4]):
        raise ValueError("A host/time scope requires --investigate, --source-instance, --agent-id, --start and --end.")
    if (args.account is None) != (args.domain is None):
        raise ValueError("Supply --account and --domain together.")
    accounts = ((args.account, args.domain),) if args.account is not None else ()
    return InvestigationScope(accounts, args.start, args.end,
        related_events=RelatedEventScope(((args.source_instance, args.agent_id),), args.start, args.end))


def _default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError("Unsupported search result value.")


def dispatch_related_event_command(args: argparse.Namespace, password_supplier: Callable[[], str]) -> bool:
    if args.command != "search-events":
        return False
    from cybertriage.bootstrap import build_related_event_search, load_event_catalog
    from cybertriage.application.policies.related_event_summary import related_event_summary

    request = RelatedEventSearchRequest(args.source_instance, args.agent_id, args.start, args.end,
        args.family, args.limit, args.account, args.domain, args.source_ip, args.process_guid, args.logon_id)
    catalog = load_event_catalog(args.catalog.resolve()) if args.catalog.is_file() else None
    result = build_related_event_search(password_supplier=password_supplier).search(request)
    payload = json.loads(json.dumps({**asdict(result), "search_summary": related_event_summary(result, catalog)},
                                   default=_default, ensure_ascii=True, allow_nan=False))
    if args.output is not None:
        from cybertriage.adapters.storage.json_files import atomic_write_json
        atomic_write_json(args.output, payload)
    print(json.dumps(payload, indent=2, ensure_ascii=True, allow_nan=False))
    return True
