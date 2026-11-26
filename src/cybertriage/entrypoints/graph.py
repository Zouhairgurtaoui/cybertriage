"""Local operator commands; no graph mutation capability is exposed to the model."""

import argparse
import getpass
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from cybertriage.domain.graph import GraphError, KILL_CHAIN_STAGES

COMMANDS = frozenset({"graph-export", "graph-schema", "graph-sync", "case-stage-add", "case-stage-review", "case-stages"})


def register_graph_commands(commands) -> None:
    for name in sorted(COMMANDS):
        parser = commands.add_parser(name, help={
            "graph-export": "Export a bounded evidence-backed case graph without Neo4j.",
            "graph-schema": "Initialize the optional Neo4j projection uniqueness constraint.",
            "graph-sync": "Atomically publish the current case graph to Neo4j.",
            "case-stage-add": "Record an evidence-backed Kill Chain hypothesis or analyst assessment.",
            "case-stage-review": "Append a review without changing the assessment kind.",
            "case-stages": "List stored Kill Chain assessments and their latest review status.",
        }[name])
        if name != "graph-schema":
            parser.add_argument("--case-id", required=True)
            parser.add_argument("--alerts-database", type=Path, default=Path("data/alerts/alerts.sqlite3"))
        if name == "graph-export":
            parser.add_argument("--namespace", default=None)
            parser.add_argument("--output", type=Path, help="Create a new JSON file; existing files are not overwritten.")
        if name in {"case-stage-add", "case-stage-review"}:
            parser.add_argument("--expected-version", type=int, required=True)
            parser.add_argument("--actor", required=True)
            parser.add_argument("--reason", required=True)
        if name == "case-stage-add":
            parser.add_argument("--stage", choices=list(dict(KILL_CHAIN_STAGES)), required=True)
            parser.add_argument("--kind", choices=["hypothesis", "analyst_assessed"], required=True)
            parser.add_argument("--supporting-alert-id", action="append", required=True)
        if name == "case-stage-review":
            parser.add_argument("--assertion-id", required=True)
            parser.add_argument("--decision", choices=["accepted", "rejected", "retracted", "superseded"], required=True)
        if name == "case-stages":
            parser.add_argument("--limit", type=int, default=50)
            parser.add_argument("--after", type=int, default=0)


def dispatch_graph_command(args: argparse.Namespace) -> bool:
    if args.command not in COMMANDS:
        return False
    from cybertriage.bootstrap import build_case_graph_export, build_case_stages

    name = args.command
    if name in {"case-stage-add", "case-stage-review", "case-stages"}:
        stages = build_case_stages(args.alerts_database.resolve())
        if name == "case-stage-add":
            output = stages.add(args.case_id, args.stage, args.kind, args.supporting_alert_id, args.expected_version, args.actor, args.reason)
        elif name == "case-stage-review":
            output = asdict(stages.review(args.case_id, args.assertion_id, args.decision, args.expected_version, args.actor, args.reason))
        else:
            output = stages.list(args.case_id, args.limit, args.after)
    elif name == "graph-export":
        namespace = args.namespace if args.namespace is not None else os.environ.get("CYBERTRIAGE_GRAPH_NAMESPACE", "cybertriage")
        graph = build_case_graph_export(args.alerts_database.resolve(), namespace).execute(args.case_id)
        output = {**graph.payload(), "payload_hash": graph.payload_hash}
        if args.output is not None:
            # No silent overwrite of source evidence or an existing graph export.
            with args.output.open("x", encoding="utf-8") as file:
                json.dump(output, file, ensure_ascii=False, allow_nan=False, indent=2)
                file.write("\n")
            output = {"case_id": graph.case_id, "source_version": graph.source_version, "payload_hash": graph.payload_hash,
                      "node_count": len(graph.nodes), "edge_count": len(graph.edges), "output": str(args.output.resolve())}
    else:
        from cybertriage.adapters.configuration.neo4j_environment import EnvironmentNeo4jConfiguration
        from cybertriage.adapters.storage.case_graph_neo4j import Neo4jCaseGraphSink

        settings = EnvironmentNeo4jConfiguration().load()
        # Assemble before opening a driver; invalid cases never cause network publication.
        exporter = build_case_graph_export(args.alerts_database.resolve(), settings.namespace) if name == "graph-sync" else None
        graph = exporter.execute(args.case_id) if exporter is not None else None
        password = os.environ.get("CYBERTRIAGE_NEO4J_PASSWORD")
        if not password:
            if not sys.stdin.isatty():
                raise GraphError("Set CYBERTRIAGE_NEO4J_PASSWORD for non-interactive graph publication.")
            password = getpass.getpass("Neo4j projection password: ")
        sink = Neo4jCaseGraphSink.connect(settings, password)
        try:
            if name == "graph-schema":
                sink.initialize_schema()
                output = {"status": "ready", "database": settings.database, "constraint": "cybertriage_graph_key"}
            else:
                from cybertriage.adapters.storage.case_graph_sqlite import SqliteCaseGraphReader
                from cybertriage.application.services.case_graph import ProjectCaseGraph
                if graph is None or exporter is None:
                    raise GraphError("No case graph snapshot was prepared.")
                output = ProjectCaseGraph(exporter, SqliteCaseGraphReader(args.alerts_database.resolve()), sink).publish(graph)
        finally:
            sink.close()
    print(json.dumps(output, indent=2, ensure_ascii=False, allow_nan=False))
    return True
