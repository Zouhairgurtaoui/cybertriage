import json
import sqlite3
from dataclasses import asdict
from datetime import timezone

from cybertriage.domain.triage import AnalysisRecord
from cybertriage.adapters.storage.case_records import record_analysis_case_links


def insert_analysis(
    connection: sqlite3.Connection,
    record: AnalysisRecord,
) -> None:
    """Insert a report using the caller's transaction."""
    if record.completed_at.utcoffset() is None:
        raise ValueError(
            "The completion timestamp must include a timezone."
        )

    result_json = json.dumps(
        asdict(record.result),
        ensure_ascii=False,
        allow_nan=False,
    )

    connection.execute(
        """
        INSERT INTO analyses (
            analysis_id,
            alert_record_id,
            completed_at,
            retrieval_query,
            evidence,
            result_json
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            record.analysis_id,
            record.alert_record_id,
            record.completed_at.astimezone(timezone.utc).isoformat(),
            record.retrieval_query,
            record.evidence,
            result_json,
        ),
    )
    record_analysis_case_links(connection, record)
