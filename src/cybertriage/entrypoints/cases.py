"""Local operator interface; no case writes are exposed by the ingestion API."""

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from cybertriage.application.services.case_management import DISPOSITIONS, PRIORITIES, STATUSES


def register_case_commands(commands: argparse._SubParsersAction) -> None:
    descriptions = {
        "case-create": "Open a persistent incident case.",
        "case-list": "List cases with bounded pagination.",
        "case-show": "Show case metadata and current version.",
        "case-update": "Update case metadata or explicit analyst disposition.",
        "case-attach": "Attach retained alerts or a snapshot of a triage group.",
        "case-detach": "Detach evidence while preserving its history.",
        "case-note": "Append an investigation note.",
        "case-relate": "Assert a validated observed relationship or an analyst hypothesis.",
        "case-review-relationship": "Append a relationship review without changing its kind.",
        "case-alerts": "List current and historical case evidence.",
        "case-relationships": "List relationships and latest review status.",
        "case-history": "Read the append-only investigation history.",
        "case-investigations": "List stored reports linked to case evidence.",
        "case-timeline": "Read a chronological evidence and investigation timeline.",
        "case-report": "Read a case-linked report and its exact alert coverage.",
    }
    writes = {"case-create", "case-update", "case-attach", "case-detach", "case-note", "case-relate", "case-review-relationship"}
    reasons = writes - {"case-create", "case-note"}
    for name, description in descriptions.items():
        parser = commands.add_parser(name, help=description)
        parser.add_argument("--alerts-database", type=Path, default=Path("data/alerts/alerts.sqlite3"))
        if name not in {"case-create", "case-list"}:
            parser.add_argument("--case-id", required=True)
        if name in writes:
            parser.add_argument("--actor", required=True, help="Asserted local operator identity; not an authenticated session.")
        if name in reasons:
            parser.add_argument("--reason", required=True)
        if name in {"case-update", "case-detach", "case-review-relationship"}:
            parser.add_argument("--expected-version", type=int, required=True)
        if name in {"case-create", "case-update"}:
            parser.add_argument("--title", required=name == "case-create")
            parser.add_argument("--description", default="" if name == "case-create" else None)
            parser.add_argument("--priority", choices=sorted(PRIORITIES), default="medium" if name == "case-create" else None)
        if name in {"case-list", "case-update"}:
            parser.add_argument("--status", choices=sorted(STATUSES))
        if name == "case-update":
            parser.add_argument("--disposition", choices=sorted(DISPOSITIONS))
        if name in {"case-update", "case-relate"}:
            parser.add_argument("--supporting-alert-id", action="append", default=[])
        if name == "case-attach":
            attachments = parser.add_mutually_exclusive_group(required=True)
            attachments.add_argument("--alert-id", action="append", default=[])
            attachments.add_argument("--group-id")
        if name == "case-detach":
            parser.add_argument("--alert-id", required=True)
        if name == "case-note":
            parser.add_argument("--text", required=True)
        if name == "case-relate":
            parser.add_argument("--source-alert-id", required=True)
            parser.add_argument("--target-alert-id", required=True)
            parser.add_argument("--kind", required=True, choices=["observed", "hypothesis"])
            parser.add_argument("--predicate", required=True)
            parser.add_argument("--analysis-id")
        if name == "case-review-relationship":
            parser.add_argument("--relationship-id", required=True)
            parser.add_argument("--decision", required=True, choices=["accepted", "rejected", "retracted", "superseded"])
        if name == "case-report":
            parser.add_argument("--analysis-id", required=True)
        if name in {"case-list", "case-alerts", "case-relationships", "case-history", "case-investigations", "case-timeline"}:
            parser.add_argument("--limit", type=int, default=50)
            if name == "case-timeline":
                parser.add_argument("--cursor")
            else:
                parser.add_argument("--after", type=str if name == "case-list" else int,
                                    default=None if name == "case-list" else 0)


def dispatch_case_command(args: argparse.Namespace) -> bool:
    if not args.command.startswith("case-"):
        return False
    from cybertriage.bootstrap import build_case_management

    service = build_case_management(args.alerts_database.resolve())
    name = args.command
    if name == "case-create":
        output = asdict(service.create(args.title, args.actor, args.priority, args.description))
    elif name == "case-list":
        output = service.list_cases(args.status, args.limit, args.after)
    elif name == "case-show":
        output = asdict(service.get(args.case_id))
    elif name == "case-update":
        changes = {key: getattr(args, key) for key in ("title", "description", "priority", "status", "disposition") if getattr(args, key) is not None}
        output = asdict(service.update(args.case_id, changes, args.expected_version, args.actor, args.reason, args.supporting_alert_id))
    elif name == "case-attach":
        output = service.attach(args.case_id, args.alert_id, args.actor, args.reason, args.group_id)
    elif name == "case-detach":
        output = asdict(service.detach(args.case_id, args.alert_id, args.expected_version, args.actor, args.reason))
    elif name == "case-note":
        output = asdict(service.note(args.case_id, args.text, args.actor))
    elif name == "case-relate":
        output = service.relate(args.case_id, args.source_alert_id, args.target_alert_id, args.kind,
                                args.predicate, args.actor, args.reason, args.supporting_alert_id, args.analysis_id)
    elif name == "case-review-relationship":
        output = asdict(service.review_relationship(args.case_id, args.relationship_id, args.decision,
                                                    args.expected_version, args.actor, args.reason))
    elif name == "case-timeline":
        output = service.timeline(args.case_id, args.limit, args.cursor)
    elif name == "case-report":
        output = service.report(args.case_id, args.analysis_id)
    else:
        output = service.read(args.case_id, name.removeprefix("case-"), args.limit, args.after)
    print(json.dumps(output, indent=2, ensure_ascii=False, allow_nan=False))
    return True
