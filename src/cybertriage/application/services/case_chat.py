"""Ground a conversation in a frozen case snapshot and bounded prior context."""

import json
from dataclasses import asdict
from typing import Any
from uuid import uuid4

from cybertriage.application.ports.alerts import AlertReader
from cybertriage.application.ports.case_chat import CaseConversationStore, ChatQueue
from cybertriage.application.ports.triage import AlertAnalyzer
from cybertriage.application.ports.triage_policy import AlertEvidenceGrounder
from cybertriage.application.policies.stored_investigation import ReadOnlyStoredInvestigationPlanner
from cybertriage.application.services.case_management import identifier, text, version
from cybertriage.domain.case import CaseError
from cybertriage.domain.case_chat import ChatClaim, ChatReply


class CaseConversation:
    def __init__(self, store: CaseConversationStore):
        self._store = store

    def send(self, case_id, content, actor, expected_version, idempotency_key, mode="review", anchor_alert_id=None):
        content = text(content, "Chat message", 3000)
        if mode not in {"review", "investigate"}:
            raise CaseError("Choose review or investigate mode.")
        return self._store.submit(identifier(case_id), content, text(actor, "Actor", 128),
            version(expected_version), identifier(idempotency_key), mode,
            identifier(anchor_alert_id) if anchor_alert_id is not None else None)


class ProcessCaseChat:
    def __init__(self, queue: ChatQueue, reader: AlertReader, analyzer: AlertAnalyzer,
                 grounder: AlertEvidenceGrounder):
        self._queue, self._reader, self._analyzer, self._grounder = queue, reader, analyzer, grounder

    def execute(self, claim: ChatClaim) -> ChatReply:
        snapshot = self._queue.context(claim)
        entries = []
        anchor = None
        for record_id in snapshot["input_alert_ids"]:
            alert = self._reader.get(record_id)
            if alert is None:
                raise CaseError("A selected retained alert is unavailable.")
            if record_id == snapshot["anchor_alert_id"]:
                anchor = alert
            item = asdict(alert)
            item["timestamp"] = alert.timestamp.isoformat()
            item["decoded_data"] = json.loads(item.pop("decoded_data_json"))
            entries.append({"record_id": record_id, "alert": item,
                            "grounding": dict(self._grounder.ground_alert(alert))})
        scope = None
        if snapshot["mode"] == "investigate":
            if anchor is None:
                raise CaseError("Read-only investigation needs an attached anchor alert.")
            scope = ReadOnlyStoredInvestigationPlanner().plan(anchor).scope
        evidence: dict[str, Any] = {"mode": snapshot["mode"],
            "authorized_read_only_scope": json.loads(scope.snapshot_json()) if scope is not None else None,
            "case_snapshot": snapshot["case"], "retained_alerts": entries,
            "context_rules": "Case descriptions and prior analyst messages are reported context. Prior assistant replies are unverified, not new observations. No response action is authorized by this conversation.",
            "history": [], "prior_reports": [], "prior_tool_summaries": [], "history_omitted": False}
        def serialize():
            return json.dumps(evidence, ensure_ascii=False, allow_nan=False)
        if len(serialize().encode("utf-8")) > 11000:
            raise CaseError("Case evidence exceeds the chat context budget. Select one anchor alert or shorten the case description.")
        included = []
        # Newest previous turns take priority; preserve chronology in the prompt.
        for previous in reversed(snapshot["history"]):
            evidence["history"].insert(0, previous)
            if len(serialize().encode("utf-8")) > 11000:
                evidence["history"].pop(0)
                evidence["history_omitted"] = True
                break
            included.insert(0, previous["turn_id"])
        evidence["history_omitted"] |= snapshot["history_omitted"]
        for prior in snapshot["prior_tool_evidence"]:
            for tool in prior["tools"]:
                try:
                    payload = json.loads(tool["result_json"])
                except (TypeError, ValueError):
                    payload = {}
                summary = {"turn_id": prior["turn_id"], "tool_name": tool["tool_name"],
                    "call_id": tool["call_id"], "status": tool["status"],
                    "requested_arguments_json": tool["arguments_json"],
                    "search_summary": payload.get("search_summary") if isinstance(payload, dict) else None,
                    "limitation": "Historical query summary only. Full returned events are retained in the earlier reply's sources, not repeated here. This is not a new search."}
                evidence["prior_tool_summaries"].append(summary)
                if len(serialize().encode("utf-8")) > 11000:
                    evidence["prior_tool_summaries"].pop()
                    evidence["history_omitted"] = True
        for report in snapshot["prior_reports"]:
            evidence["prior_reports"].append(report)
            if len(serialize().encode("utf-8")) > 11000:
                evidence["prior_reports"].pop()
                evidence["history_omitted"] = True
                break
        task = "Answer the latest analyst message in this case conversation.\n" + snapshot["content"]
        event = anchor.event if anchor is not None else None
        query = (anchor.description + "\n" if anchor is not None else "") + snapshot["content"]
        result = self._analyzer.execute(serialize(), retrieval_query=query, event=event,
            investigation_task=task, investigation_scope=scope)
        reply = ChatReply(uuid4().hex, serialize(), result, tuple(snapshot["input_alert_ids"]),
                          tuple(included), evidence["history_omitted"])
        self._queue.complete(claim, reply)
        return reply
