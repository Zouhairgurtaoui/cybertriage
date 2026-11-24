"""Record live reports for review. Successful generation is not an accuracy score."""

import argparse
import json
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from cybertriage.adapters.storage.json_files import atomic_write_json
from cybertriage.bootstrap import build_analyze_alert
from cybertriage.domain.security_event import EventIdentity


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=Path("config/evaluation-cases.json"))
    parser.add_argument("--output", type=Path, default=Path("data/evaluations/latest.json"))
    parser.add_argument("--database", type=Path, default=Path("data/chroma"))
    parser.add_argument("--catalog", type=Path, default=Path("data/catalogs/windows-security.json"))
    parser.add_argument("--case", help="Run just this case ID.")
    parser.add_argument("--model", help="Local model to evaluate; defaults to the application setting.")
    parser.add_argument("--sources-config", type=Path, default=Path("config/sources.yaml"))
    args = parser.parse_args()
    with args.cases.open("rb") as file:
        raw = file.read(65537)
    if len(raw) > 65536:
        parser.error("Evaluation fixture exceeds its size limit.")
    document = json.loads(raw)
    cases = document.get("cases")
    if document.get("schema_version") != 1 or not isinstance(cases, list) or not 1 <= len(cases) <= 20:
        parser.error("Expected a version-1 fixture containing 1-20 cases.")
    if args.case:
        cases = [case for case in cases if case.get("id") == args.case]
        if not cases:
            parser.error("Unknown evaluation case ID.")

    results = []
    for case in cases:
        started = time.monotonic()
        print(f"Evaluating {case['id']}...", flush=True)
        record = {
            "case_id": case["id"],
            "review_criteria": case["review_criteria"],
            "semantic_review": "pending",
            "model": args.model or "application default",
        }
        try:
            event = (EventIdentity("Microsoft-Windows-Security-Auditing", "Security", case["event_id"])
                     if "event_id" in case else None)
            use_case = build_analyze_alert(
                args.database.resolve(), args.catalog.resolve() if event else None,
                model_name=args.model,
                sources_config_path=args.sources_config,
            )
            result = use_case.execute(case["evidence"], retrieval_query=case["query"], event=event)
            record.update(execution_status="completed", result=asdict(result))
        except Exception as error:
            # The failure remains a failed case, not a substitute passing report.
            record.update(execution_status="failed", error=f"{type(error).__name__}: {error}")
        record["duration_seconds"] = round(time.monotonic() - started, 3)
        results.append(record)
        atomic_write_json(args.output, {
            "schema_version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "scope": "text-report generation; semantic review is separate and pending",
            "cases": results,
        })
        print(f"{case['id']}: {record['execution_status']} ({record['duration_seconds']}s)", flush=True)
    print(f"Results: {args.output.resolve()}", flush=True)
    if any(record["execution_status"] != "completed" for record in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
