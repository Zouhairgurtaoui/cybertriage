import json
from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime, timezone
from uuid import uuid4

from cybertriage.application.ports.alerts import AlertReader
from cybertriage.application.ports.triage_policy import AlertEvidenceGrounder, GroupEvidenceReader
from cybertriage.application.ports.triage import (
    AlertAnalyzer,
    AnalysisWriter,
)
from cybertriage.domain.alert import AlertNotFoundError, SecurityAlert
from cybertriage.domain.triage import AnalysisRecord


def _format_evidence(alert: SecurityAlert, grounding: Mapping[str, object] | None = None) -> str:
    payload = asdict(alert)

    # JSON cannot directly represent a Python datetime.
    payload["timestamp"] = alert.timestamp.isoformat()

    # Include decoded fields as an object rather than an escaped JSON string.
    payload["decoded_data"] = json.loads(
        payload.pop("decoded_data_json")
    )
    if grounding is not None:
        payload["grounding"] = dict(grounding)

    serialized = json.dumps(
        payload,
        indent=2,
        ensure_ascii=True,
        allow_nan=False,
    )

    return (
        "The following is one normalized alert received from Wazuh.\n"
        "This operation does not search for additional incident events.\n"
        "Wazuh rule metadata, including MITRE IDs, provides classification "
        "context and does not independently confirm an attack.\n\n"
        f"{serialized}"
    )


class AnalyzeStoredAlert:
    def __init__(
        self,
        reader: AlertReader,
        analyzer: AlertAnalyzer,
        writer: AnalysisWriter,
        *,
        group_reader: GroupEvidenceReader | None = None,
        grounder: AlertEvidenceGrounder | None = None,
    ):
        self._reader = reader
        self._analyzer = analyzer
        self._writer = writer
        self._group_reader = group_reader
        self._grounder = grounder

    def execute(
        self,
        record_id: str,
        retrieval_query: str | None = None,
    ) -> AnalysisRecord:
        alert = self._reader.get(record_id)

        if alert is None:
            raise AlertNotFoundError(
                "No stored alert matches this record ID."
            )

        query = (
            retrieval_query
            if retrieval_query is not None
            else alert.description
        )
        group_context = (
            self._group_reader.group_context(record_id)
            if self._group_reader is not None else None
        )
        evidence = group_context if group_context is not None else _format_evidence(
            alert, self._grounder.ground_alert(alert) if self._grounder else None,
        )

        result = self._analyzer.execute(
            evidence=evidence,
            retrieval_query=query,
            event=alert.event,
        )

        record = AnalysisRecord(
            analysis_id=uuid4().hex,
            alert_record_id=record_id,
            completed_at=datetime.now(timezone.utc),
            retrieval_query=query,
            evidence=evidence,
            result=result,
        )

        self._writer.save(record)

        return record
