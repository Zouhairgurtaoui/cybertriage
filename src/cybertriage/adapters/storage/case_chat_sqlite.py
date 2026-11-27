"""Atomic chat submission, frozen context, leased jobs and append-only replies."""

import json
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import uuid4

from cybertriage.adapters.storage.analysis_records import insert_analysis
from cybertriage.adapters.storage.case_records import append_case_event, link_report_to_cases, utc_now
from cybertriage.adapters.storage.cases_sqlite import SqliteCaseRepository
from cybertriage.application.services.case_management import identifier, page
from cybertriage.domain.case import CaseConflictError, CaseError
from cybertriage.domain.case_chat import ChatClaim, ChatLeaseLostError, ChatReply
from cybertriage.domain.response_workflow import canonical
from cybertriage.domain.triage import AnalysisRecord


class SqliteCaseChat(SqliteCaseRepository):
    def __init__(self, database_path):
        super().__init__(database_path)
        with self._session(True) as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS case_chat_turns(
                seq INTEGER PRIMARY KEY AUTOINCREMENT,turn_id TEXT NOT NULL UNIQUE,
                case_id TEXT NOT NULL REFERENCES incident_cases(case_id),actor TEXT NOT NULL,
                content TEXT NOT NULL,mode TEXT NOT NULL CHECK(mode IN ('review','investigate')),
                anchor_alert_id TEXT REFERENCES alerts(record_id),case_version INTEGER NOT NULL,
                context_json TEXT NOT NULL,idempotency_key TEXT NOT NULL,request_hash TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending','running','completed','failed')),
                attempt_count INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,available_at TEXT NOT NULL,
                claim_token TEXT,lease_expires_at TEXT,last_error_code TEXT,finished_at TEXT,
                UNIQUE(case_id,idempotency_key),CHECK(attempt_count>=0),
                CHECK((status='running' AND claim_token IS NOT NULL AND lease_expires_at IS NOT NULL)
                OR (status<>'running' AND claim_token IS NULL AND lease_expires_at IS NULL)))""")
            connection.execute("CREATE INDEX IF NOT EXISTS case_chat_history ON case_chat_turns(case_id,seq)")
            connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS case_chat_one_active ON case_chat_turns(case_id) WHERE status IN ('pending','running')")
            connection.execute("""CREATE TABLE IF NOT EXISTS case_chat_replies(
                turn_id TEXT PRIMARY KEY REFERENCES case_chat_turns(turn_id),reply_id TEXT NOT NULL UNIQUE,
                result_json TEXT NOT NULL,evidence TEXT NOT NULL,coverage_json TEXT NOT NULL,
                history_json TEXT NOT NULL,history_omitted INTEGER NOT NULL,completed_at TEXT NOT NULL,
                analysis_id TEXT REFERENCES analyses(analysis_id))""")
            for operation in ("UPDATE", "DELETE"):
                connection.execute(f"""CREATE TRIGGER IF NOT EXISTS case_chat_replies_no_{operation.lower()}
                    BEFORE {operation} ON case_chat_replies BEGIN SELECT RAISE(ABORT,'Chat replies are append-only'); END""")
            connection.execute("""CREATE TRIGGER IF NOT EXISTS case_chat_turns_identity BEFORE UPDATE ON case_chat_turns
                WHEN NEW.turn_id<>OLD.turn_id OR NEW.case_id<>OLD.case_id OR NEW.actor<>OLD.actor
                OR NEW.content<>OLD.content OR NEW.mode<>OLD.mode OR NEW.anchor_alert_id IS NOT OLD.anchor_alert_id
                OR NEW.case_version<>OLD.case_version OR NEW.context_json<>OLD.context_json
                OR NEW.idempotency_key<>OLD.idempotency_key OR NEW.request_hash<>OLD.request_hash
                OR NEW.created_at<>OLD.created_at
                BEGIN SELECT RAISE(ABORT,'Chat turn identity is immutable'); END""")
            connection.execute("""CREATE TRIGGER IF NOT EXISTS case_chat_turns_no_delete BEFORE DELETE ON case_chat_turns
                BEGIN SELECT RAISE(ABORT,'Chat history is retained'); END""")

    def submit(self, case_id, content, actor, expected_version, idempotency_key, mode, anchor_alert_id):
        digest = sha256(canonical([content, actor, expected_version, mode, anchor_alert_id]).encode()).hexdigest()
        with self._session(True) as connection:
            existing = connection.execute("SELECT turn_id,request_hash FROM case_chat_turns WHERE case_id=? AND idempotency_key=?",
                                          (case_id, idempotency_key)).fetchone()
            if existing:
                if existing["request_hash"] != digest:
                    raise CaseConflictError("Chat idempotency key belongs to different content.")
                return self._turn(connection, case_id, existing["turn_id"])
            case = self._case(connection, case_id, expected_version, editable=True)
            if connection.execute("SELECT 1 FROM case_chat_turns WHERE case_id=? AND status IN ('pending','running')", (case_id,)).fetchone():
                raise CaseConflictError("Wait for this case's pending reply before sending another message.")
            if connection.execute("SELECT COUNT(*) FROM case_chat_turns WHERE case_id=?", (case_id,)).fetchone()[0] >= 1000:
                raise CaseError("The case conversation has reached its history capacity.")
            if anchor_alert_id is not None:
                self._attached(connection, case_id, [anchor_alert_id])
                selected = [anchor_alert_id]
                total = connection.execute("SELECT COUNT(*) FROM case_alerts WHERE case_id=? AND active=1", (case_id,)).fetchone()[0]
            else:
                rows = connection.execute("SELECT alert_record_id FROM case_alerts WHERE case_id=? AND active=1 ORDER BY seq LIMIT 6", (case_id,)).fetchall()
                if len(rows) > 5:
                    raise CaseError("More than five alerts are attached. Select an anchor alert to focus this conversation turn.")
                selected = [row[0] for row in rows]
                total = len(selected)
                anchor_alert_id = selected[0] if selected else None
            if mode == "investigate" and anchor_alert_id is None:
                raise CaseError("Attach a retained alert before requesting read-only investigation.")
            for record_id in selected:
                self._alert(connection, record_id)  # Verify evidence integrity before scheduling.
            previous = connection.execute("""SELECT t.turn_id,t.actor,t.content,t.status,
                substr(json_extract(r.result_json,'$.analysis'),1,2000) AS answer,
                length(json_extract(r.result_json,'$.analysis'))>2000 AS answer_excerpt
                FROM case_chat_turns t LEFT JOIN case_chat_replies r ON r.turn_id=t.turn_id
                WHERE t.case_id=? ORDER BY t.seq DESC LIMIT 9""", (case_id,)).fetchall()
            prior = connection.execute("""SELECT a.analysis_id,substr(json_extract(a.result_json,'$.analysis'),1,1800) AS excerpt
                FROM case_analyses c JOIN analyses a ON a.analysis_id=c.analysis_id
                WHERE c.case_id=? ORDER BY c.seq DESC LIMIT 2""", (case_id,)).fetchall()
            tools = connection.execute("""SELECT t.turn_id,json_extract(r.result_json,'$.tool_executions') AS tools
                FROM case_chat_turns t JOIN case_chat_replies r ON r.turn_id=t.turn_id
                WHERE t.case_id=? ORDER BY t.seq DESC LIMIT 2""", (case_id,)).fetchall()
            snapshot = {"case": {"case_id": case_id, "title": case.title, "reported_description": case.description,
                "version": case.version, "disposition": case.disposition,
                "active_alert_count": total, "selected_alert_count": len(selected)},
                "input_alert_ids": selected, "anchor_alert_id": anchor_alert_id,
                "history": [dict(row) for row in reversed(previous[:8])], "history_omitted": len(previous)>8,
                "prior_reports": [dict(row) for row in prior],
                "prior_tool_evidence": [{"turn_id": row["turn_id"], "tools": json.loads(row["tools"] or "[]")} for row in tools]}
            turn_id, now = uuid4().hex, utc_now()
            connection.execute("""INSERT INTO case_chat_turns(turn_id,case_id,actor,content,mode,anchor_alert_id,
                case_version,context_json,idempotency_key,request_hash,status,created_at,available_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,'pending',?,?)""", (turn_id,case_id,actor,content,mode,anchor_alert_id,
                case.version,canonical(snapshot),idempotency_key,digest,now,now))
            append_case_event(connection, case_id, "chat_message_submitted", actor, "Analyst requested an agent reply.",
                              {"turn_id": turn_id, "mode": mode, "input_alert_ids": selected})
            return self._turn(connection, case_id, turn_id)

    @staticmethod
    def _turn(connection, case_id, turn_id):
        row = connection.execute("""SELECT t.seq,t.turn_id,t.case_id,t.actor,t.content,t.mode,t.anchor_alert_id,
            t.case_version,t.status,t.attempt_count,t.created_at,t.finished_at,t.last_error_code,
            r.reply_id,r.completed_at,r.analysis_id,r.history_omitted,
            json_extract(r.result_json,'$.analysis') AS answer,r.coverage_json
            FROM case_chat_turns t LEFT JOIN case_chat_replies r ON r.turn_id=t.turn_id
            WHERE t.case_id=? AND t.turn_id=?""", (case_id,turn_id)).fetchone()
        if row is None:
            raise CaseError("Conversation turn not found in this case.")
        value = dict(row)
        value["input_alert_ids"] = json.loads(value.pop("coverage_json") or "[]")
        return value

    def list_turns(self, case_id, limit=20, before=None):
        case_id = identifier(case_id)
        page(limit)
        if limit > 20 or (before is not None and (type(before) is not int or not 1 <= before <= 9223372036854775807)):
            raise CaseError("Chat pages allow 1-20 turns and a positive sequence cursor.")
        with self._session() as connection:
            case = self._case(connection,case_id)
            rows = connection.execute("SELECT seq,turn_id FROM case_chat_turns WHERE case_id=? AND (? IS NULL OR seq<?) ORDER BY seq DESC LIMIT ?",
                                      (case_id,before,before,limit+1)).fetchall()
            return self._bounded({"case_id": case_id, "case_version": case.version,
                "turns": [self._turn(connection,case_id,row["turn_id"]) for row in rows[:limit]],
                "next_before": rows[limit-1]["seq"] if len(rows)>limit else None}, 2*1024*1024)

    def turn_detail(self, case_id, turn_id):
        case_id, turn_id = identifier(case_id), identifier(turn_id)
        with self._session() as connection:
            self._case(connection,case_id)
            turn = self._turn(connection,case_id,turn_id)
            row = connection.execute("SELECT * FROM case_chat_replies WHERE turn_id=?",(turn_id,)).fetchone()
            report = None if row is None else {"completed_at": row["completed_at"], "evidence": row["evidence"],
                "result": json.loads(row["result_json"]), "analysis_id": row["analysis_id"]}
            return self._bounded({"turn": turn, "report": report,
                "coverage": [{"alert_record_id": key} for key in turn["input_alert_ids"]]}, 2*1024*1024)

    @staticmethod
    def _owned(connection, claim):
        row = connection.execute("""SELECT * FROM case_chat_turns WHERE turn_id=? AND case_id=?
            AND claim_token=? AND status='running' AND lease_expires_at>?""",
            (claim.turn_id,claim.case_id,claim.claim_token,utc_now())).fetchone()
        if row is None:
            raise ChatLeaseLostError("Chat turn lease is no longer owned.")
        return row

    def claim(self, lease_seconds=600):
        if type(lease_seconds) is not int or not 30 <= lease_seconds <= 86400:
            raise ValueError("Chat lease must be 30-86400 seconds.")
        now = utc_now()
        with self._session(True) as connection:
            connection.execute("""UPDATE case_chat_turns SET status='failed',claim_token=NULL,lease_expires_at=NULL,
                last_error_code='attempt_limit',finished_at=? WHERE attempt_count>=3 AND
                ((status='running' AND lease_expires_at<=?) OR status='pending')""", (now,now))
            row = connection.execute("""SELECT turn_id,case_id,attempt_count FROM case_chat_turns
                WHERE attempt_count<3 AND ((status='pending' AND available_at<=?) OR
                (status='running' AND lease_expires_at<=?)) ORDER BY seq LIMIT 1""",(now,now)).fetchone()
            if row is None:
                return None
            token = uuid4().hex
            expiry = (datetime.now(timezone.utc)+timedelta(seconds=lease_seconds)).isoformat()
            connection.execute("""UPDATE case_chat_turns SET status='running',attempt_count=attempt_count+1,
                claim_token=?,lease_expires_at=? WHERE turn_id=?""",(token,expiry,row["turn_id"]))
            return ChatClaim(row["turn_id"],row["case_id"],token,row["attempt_count"]+1)

    def context(self, claim):
        with self._session() as connection:
            row = self._owned(connection,claim)
            self._case(connection,claim.case_id,editable=True)
            snapshot = json.loads(row["context_json"])
            self._attached(connection,claim.case_id,snapshot["input_alert_ids"])
            snapshot.update(content=row["content"],mode=row["mode"])
            return snapshot

    def renew(self, claim, lease_seconds=600):
        if type(lease_seconds) is not int or not 30 <= lease_seconds <= 86400:
            raise ValueError("Chat lease must be 30-86400 seconds.")
        with self._session(True) as connection:
            self._owned(connection,claim)
            connection.execute("UPDATE case_chat_turns SET lease_expires_at=? WHERE turn_id=?",
                ((datetime.now(timezone.utc)+timedelta(seconds=lease_seconds)).isoformat(),claim.turn_id))

    def complete(self, claim: ChatClaim, reply: ChatReply):
        result_json = canonical(asdict(reply.result))
        if len(result_json.encode("utf-8")) > 256000 or len(reply.result.analysis.encode("utf-8"))>64000:
            raise CaseError("Chat reply exceeds the storage budget.")
        with self._session(True) as connection:
            row = self._owned(connection,claim)
            snapshot = json.loads(row["context_json"])
            if tuple(snapshot["input_alert_ids"]) != reply.input_alert_ids:
                raise CaseError("Reply coverage does not match the requested case snapshot.")
            now, analysis_id = utc_now(), None
            if row["anchor_alert_id"]:
                analysis_id = reply.reply_id
                insert_analysis(connection, AnalysisRecord(analysis_id,row["anchor_alert_id"],datetime.now(timezone.utc),
                    row["content"],reply.evidence,reply.result))
                for alert_id in reply.input_alert_ids:
                    connection.execute("INSERT OR IGNORE INTO analysis_alert_coverage VALUES(?,?)",(analysis_id,alert_id))
                link_report_to_cases(connection,analysis_id)
            connection.execute("""INSERT INTO case_chat_replies(turn_id,reply_id,result_json,evidence,coverage_json,
                history_json,history_omitted,completed_at,analysis_id) VALUES(?,?,?,?,?,?,?,?,?)""",
                (claim.turn_id,reply.reply_id,result_json,reply.evidence,canonical(reply.input_alert_ids),
                 canonical(reply.included_history_ids),int(reply.history_omitted),now,analysis_id))
            connection.execute("""UPDATE case_chat_turns SET status='completed',claim_token=NULL,lease_expires_at=NULL,
                finished_at=?,last_error_code=NULL WHERE turn_id=?""",(now,claim.turn_id))
            append_case_event(connection,claim.case_id,"chat_reply_saved","system:case-chat",
                "Provisional agent reply saved; no response authorized.",{"turn_id": claim.turn_id,"reply_id": reply.reply_id})

    def fail(self, claim, code, retryable):
        if code not in {"invalid_context","generation_failed","generation_timeout","output_incomplete","model_context_limit","model_response_invalid"} or type(retryable) is not bool:
            raise ValueError("Invalid chat failure classification.")
        with self._session(True) as connection:
            row = self._owned(connection,claim)
            retry = retryable and row["attempt_count"]<3
            now = datetime.now(timezone.utc)
            connection.execute("""UPDATE case_chat_turns SET status=?,claim_token=NULL,lease_expires_at=NULL,
                last_error_code=?,available_at=?,finished_at=? WHERE turn_id=?""",
                ("pending" if retry else "failed",code,(now+timedelta(seconds=30*2**(row["attempt_count"]-1))).isoformat(),
                 None if retry else now.isoformat(),claim.turn_id))
