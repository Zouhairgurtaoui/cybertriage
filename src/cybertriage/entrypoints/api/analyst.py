"""Authenticated case/response backend for an analyst application."""

from dataclasses import asdict
import os
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.concurrency import run_in_threadpool

from cybertriage.adapters.configuration.analyst_keys import AnalystKeyStore
from cybertriage.adapters.storage.investigation_requests import SqliteInvestigationRequests
from cybertriage.adapters.storage.case_candidates import SqliteCaseCandidates
from cybertriage.adapters.storage.analyst_read_sqlite import SqliteAnalystAlertReader
from cybertriage.application.ports.analyst_read import AnalystAlertReader
from cybertriage.bootstrap import build_case_graph_export, build_case_management, build_case_stages, build_response_runtime
from cybertriage.domain.analyst import AnalystPrincipal
from cybertriage.domain.authentication import AuthenticationStorageError, LoginRateLimitedError
from cybertriage.domain.case import CaseConflictError, CaseError, CaseStorageError
from cybertriage.domain.graph import GraphError, GraphStorageError
from cybertriage.domain.response_workflow import ResponseConflictError, ResponseError, ResponseStorageError
from cybertriage.domain.triage import AnalysisStorageError
from cybertriage.domain.jobs import JobStorageError
from cybertriage.domain.triage_policy import TriageReviewError
from cybertriage.entrypoints.api.app import _read_payload


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Login(Body):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128, repr=False)


class CreateCase(Body):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=8000)
    priority: Literal["low", "medium", "high", "critical"] = "medium"


class Reasoned(Body):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=4000)


class UpdateCase(Reasoned):
    changes: dict[str, str]
    supporting_alert_ids: list[str] = Field(default_factory=list, max_length=100)


class AttachAlerts(Body):
    alert_ids: list[str] = Field(default_factory=list, max_length=100)
    group_id: str | None = None
    reason: str = Field(min_length=1, max_length=4000)


class Note(Body):
    text: str = Field(min_length=1, max_length=8000)


class Relation(Body):
    source_alert_id: str
    target_alert_id: str
    kind: Literal["observed", "hypothesis"]
    predicate: str
    reason: str
    supporting_alert_ids: list[str] = Field(default_factory=list, max_length=100)
    analysis_id: str | None = None


class ReviewRelation(Reasoned):
    decision: Literal["accepted", "rejected", "retracted", "superseded"]


class Stage(Reasoned):
    stage: str
    kind: Literal["hypothesis", "analyst_assessed"]
    supporting_alert_ids: list[str] = Field(min_length=1, max_length=100)


class Proposal(Reasoned):
    action: str
    target: str
    parameters: dict[str, str | int]
    supporting_alert_ids: list[str] = Field(min_length=1, max_length=100)
    idempotency_key: str
    origin: Literal["operator", "application", "model"] = "operator"
    analysis_id: str | None = None


class ReviewProposal(Reasoned):
    decision: Literal["approved", "rejected", "revoked"]


class Reconcile(Body):
    outcome: Literal["applied", "not_applied"]
    reason: str
    evidence: str


class ReleaseReconcile(Body):
    reason: str
    evidence: str


class Investigation(Body):
    alert_record_id: str
    task: str = Field(min_length=1, max_length=1500)
    expected_version: int = Field(ge=1)
    idempotency_key: str


class ChatMessage(Body):
    content: str = Field(min_length=1, max_length=2000)
    expected_version: int = Field(ge=1)
    idempotency_key: str
    mode: Literal["review", "investigate"] = "review"
    anchor_alert_id: str | None = None


class Feedback(Body):
    label: Literal["benign", "malicious", "uncertain"]
    reason: str


def create_analyst_app(database: Path, credentials: Path, response_config: Path, firewalls_config: Path) -> FastAPI:
    keys = AnalystKeyStore(credentials)
    keys.load()  # Fail closed on absent/invalid credentials before opening a listener.
    from cybertriage.bootstrap import build_analyst_sessions
    sessions = build_analyst_sessions(database,keys)
    cases, stages = build_case_management(database), build_case_stages(database)
    requests = SqliteInvestigationRequests(database)
    from cybertriage.bootstrap import build_case_conversation
    conversation, conversation_reader = build_case_conversation(database)
    candidate_reader = SqliteCaseCandidates(database)
    alert_reader: AnalystAlertReader = SqliteAnalystAlertReader(database)
    build_response_runtime(database, response_config, firewalls_config)
    app = FastAPI(title="CyberTriage analyst API", debug=False, docs_url=None, redoc_url=None, openapi_url=None)
    bearer = HTTPBearer(auto_error=False)

    async def principal(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if len(request.headers.getlist("authorization")) != 1 or credentials is None:
            raise HTTPException(401, "Analyst authentication required.", headers={"WWW-Authenticate": "Bearer"})
        try:
            identity = await run_in_threadpool(sessions.authenticate, credentials.credentials)
            if identity is None:
                identity = await run_in_threadpool(keys.authenticate, credentials.credentials)
        except (ValueError, OSError):
            raise HTTPException(503, "Analyst authentication configuration is unavailable.") from None
        if identity is None:
            raise HTTPException(401, "Invalid or expired analyst credential.", headers={"WWW-Authenticate": "Bearer"})
        return identity

    def permission(name: str):
        async def authorize(request: Request, identity: AnalystPrincipal = Depends(principal)):
            case_id = request.path_params.get("case_id")
            if not identity.permits(name, case_id):
                raise HTTPException(403, "This analyst is not authorized for this operation and case.")
            return identity
        return authorize

    def global_scope(identity):
        if identity.case_ids != ("*",):
            raise HTTPException(403, "This operation requires explicit access to all investigation evidence.")

    async def body(request, model):
        payload = await _read_payload(request, 16384)
        try:
            return model.model_validate(payload)
        except ValidationError:
            raise HTTPException(400, "Invalid request fields; inspect the authenticated API schema.") from None

    def runtime():
        # Each response operation reloads policy and target bindings, invalidating obsolete approvals.
        return build_response_runtime(database, response_config, firewalls_config)[0]

    async def checked_response(case_id, proposal_id):
        service = await run_in_threadpool(runtime)
        value = await run_in_threadpool(service.get, proposal_id)
        if value["case_id"] != case_id:
            raise HTTPException(404, "Response proposal not found in this case.")
        return service

    @app.middleware("http")
    async def response_headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        return response

    @app.get("/", include_in_schema=False)
    async def service_info():
        return {"service": "cybertriage-analyst-api", "health": "/healthz"}

    def register_error(error_type, code, detail=None):
        async def handle(request, error):
            return JSONResponse(status_code=code, content={"detail": detail or str(error)})
        app.add_exception_handler(error_type, handle)
    for error in (CaseConflictError, ResponseConflictError):
        register_error(error, 409)
    for error in (CaseError, ResponseError, GraphError, ValueError):
        register_error(error, 400)
    for error in (CaseStorageError, ResponseStorageError, GraphStorageError, AnalysisStorageError, JobStorageError, TriageReviewError, AuthenticationStorageError):
        register_error(error, 503, "Application storage is unavailable.")

    @app.get("/healthz")
    async def health():
        return {"status": "up"}

    @app.get("/api/v1/schema")
    async def schema(identity=Depends(permission("cases:read"))):
        return app.openapi()

    @app.post("/api/v1/auth/login")
    async def password_login(request: Request):
        data = await body(request,Login)
        client = request.client.host if request.client else "unknown"
        try:
            result = await run_in_threadpool(sessions.login,data.username,data.password,client)
        except LoginRateLimitedError:
            raise HTTPException(429,"Too many login attempts. Try again later.",headers={"Retry-After":"300"}) from None
        except (ValueError,OSError):
            raise HTTPException(503,"Analyst login configuration is unavailable.") from None
        if result is None:
            raise HTTPException(401,"Invalid username or password.")
        return result

    @app.post("/api/v1/auth/logout")
    async def password_logout(request: Request, credential: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if len(request.headers.getlist("authorization")) != 1 or credential is None:
            raise HTTPException(401,"Analyst session credential required.")
        await run_in_threadpool(sessions.logout,credential.credentials)
        return {"status":"signed_out"}

    @app.get("/api/v1/me")
    async def me(identity=Depends(principal)):
        return {"analyst_id": identity.analyst_id, "permissions": sorted(identity.permissions), "case_ids": identity.case_ids}

    @app.get("/api/v1/alerts")
    async def alert_inbox(limit: int = 50, before: int | None = None, identity=Depends(permission("cases:read"))):
        global_scope(identity)
        return await run_in_threadpool(alert_reader.list_alerts, limit, before)

    @app.get("/api/v1/alerts/{record_id}")
    async def alert_detail(record_id: str, identity=Depends(permission("cases:read"))):
        global_scope(identity)
        return await run_in_threadpool(alert_reader.alert_detail, record_id)

    @app.get("/api/v1/analyses")
    async def agent_reports(limit: int = 50, before: int | None = None, alert_id: str | None = None,
                            identity=Depends(permission("reports:read_all"))):
        global_scope(identity)
        return await run_in_threadpool(alert_reader.list_analyses, limit, before, alert_id)

    @app.get("/api/v1/analyses/{analysis_id}")
    async def agent_report(analysis_id: str, identity=Depends(permission("reports:read_all"))):
        global_scope(identity)
        return await run_in_threadpool(alert_reader.analysis_detail, analysis_id)

    @app.get("/api/v1/cases")
    async def list_cases(limit: int = 50, after: str | None = None, status: str | None = None, identity=Depends(permission("cases:read"))):
        from cybertriage.application.services.case_management import STATUSES, identifier, page
        page(limit)
        if status is not None and status not in STATUSES:
            raise CaseError("Invalid case status.")
        if after is not None:
            identifier(after)
        if identity.case_ids == ("*",):
            return await run_in_threadpool(cases.list_cases, status, limit, after)
        selected = []
        for case_id in sorted(identity.case_ids):
            if after and case_id <= after:
                continue
            try:
                case = await run_in_threadpool(cases.get, case_id)
            except CaseError:
                continue
            if status is None or case.status == status:
                selected.append(asdict(case))
            if len(selected) > limit:
                break
        return {"cases": selected[:limit], "next_after": selected[limit - 1]["case_id"] if len(selected) > limit else None}

    @app.post("/api/v1/cases", status_code=201)
    async def create_case(request: Request, identity=Depends(permission("cases:write"))):
        global_scope(identity)
        data = await body(request, CreateCase)
        return asdict(await run_in_threadpool(cases.create, data.title, identity.analyst_id, data.priority, data.description))

    @app.get("/api/v1/cases/{case_id}")
    async def get_case(case_id: str, identity=Depends(permission("cases:read"))):
        return asdict(await run_in_threadpool(cases.get, case_id))

    @app.patch("/api/v1/cases/{case_id}")
    async def update_case(case_id: str, request: Request, identity=Depends(permission("cases:review"))):
        data = await body(request, UpdateCase)
        return asdict(await run_in_threadpool(cases.update, case_id, data.changes, data.expected_version,
            identity.analyst_id, data.reason, data.supporting_alert_ids))

    @app.post("/api/v1/cases/{case_id}/alerts")
    async def attach(case_id: str, request: Request, identity=Depends(permission("cases:write"))):
        global_scope(identity)
        data = await body(request, AttachAlerts)
        return await run_in_threadpool(cases.attach, case_id, data.alert_ids, identity.analyst_id, data.reason, data.group_id)

    @app.delete("/api/v1/cases/{case_id}/alerts/{alert_id}")
    async def detach(case_id: str, alert_id: str, request: Request, identity=Depends(permission("cases:write"))):
        data = await body(request, Reasoned)
        return asdict(await run_in_threadpool(cases.detach, case_id, alert_id, data.expected_version, identity.analyst_id, data.reason))

    @app.post("/api/v1/cases/{case_id}/notes")
    async def note(case_id: str, request: Request, identity=Depends(permission("cases:write"))):
        data = await body(request, Note)
        return asdict(await run_in_threadpool(cases.note, case_id, data.text, identity.analyst_id))

    @app.get("/api/v1/cases/{case_id}/timeline")
    async def timeline(case_id: str, limit: int = 50, cursor: str | None = None, identity=Depends(permission("cases:read"))):
        return await run_in_threadpool(cases.timeline, case_id, limit, cursor)

    @app.get("/api/v1/cases/{case_id}/graph")
    async def graph(case_id: str, identity=Depends(permission("cases:read"))):
        def export():
            value = build_case_graph_export(database, os.environ.get("CYBERTRIAGE_GRAPH_NAMESPACE", "cybertriage")).execute(case_id)
            return {**value.payload(), "payload_hash": value.payload_hash}
        return await run_in_threadpool(export)

    @app.get("/api/v1/cases/{case_id}/candidates")
    async def candidates(case_id: str, anchor_alert_id: str, window_seconds: int = 300, limit: int = 20,
                         identity=Depends(permission("cases:read"))):
        global_scope(identity)
        return await run_in_threadpool(candidate_reader.suggest, case_id, anchor_alert_id, window_seconds, limit)

    @app.get("/api/v1/cases/{case_id}/sections/{section}")
    async def section(case_id: str, section: str, limit: int = 50, after: int = 0, identity=Depends(permission("cases:read"))):
        if section == "investigations":
            global_scope(identity)
        return await run_in_threadpool(cases.read, case_id, section, limit, after)

    @app.get("/api/v1/cases/{case_id}/reports/{analysis_id}")
    async def report(case_id: str, analysis_id: str, identity=Depends(permission("reports:read_all"))):
        # Tool results and group inputs can include evidence outside a case's original attachments.
        global_scope(identity)
        return await run_in_threadpool(cases.report, case_id, analysis_id)

    @app.post("/api/v1/cases/{case_id}/relationships")
    async def relate(case_id: str, request: Request, identity=Depends(permission("cases:write"))):
        global_scope(identity)
        data = await body(request, Relation)
        return await run_in_threadpool(cases.relate, case_id, data.source_alert_id, data.target_alert_id, data.kind,
            data.predicate, identity.analyst_id, data.reason, data.supporting_alert_ids, data.analysis_id)

    @app.post("/api/v1/cases/{case_id}/relationships/{relationship_id}/reviews")
    async def review_relationship(case_id: str, relationship_id: str, request: Request, identity=Depends(permission("cases:review"))):
        data = await body(request, ReviewRelation)
        return asdict(await run_in_threadpool(cases.review_relationship, case_id, relationship_id, data.decision,
            data.expected_version, identity.analyst_id, data.reason))

    @app.get("/api/v1/cases/{case_id}/stages")
    async def list_stages(case_id: str, limit: int = 50, after: int = 0, identity=Depends(permission("cases:read"))):
        return await run_in_threadpool(stages.list, case_id, limit, after)

    @app.post("/api/v1/cases/{case_id}/stages")
    async def add_stage(case_id: str, request: Request, identity=Depends(permission("cases:review"))):
        data = await body(request, Stage)
        return await run_in_threadpool(stages.add, case_id, data.stage, data.kind, data.supporting_alert_ids,
            data.expected_version, identity.analyst_id, data.reason)

    @app.post("/api/v1/cases/{case_id}/stages/{assertion_id}/reviews")
    async def review_stage(case_id: str, assertion_id: str, request: Request, identity=Depends(permission("cases:review"))):
        data = await body(request, ReviewRelation)
        return asdict(await run_in_threadpool(stages.review, case_id, assertion_id, data.decision,
            data.expected_version, identity.analyst_id, data.reason))

    @app.get("/api/v1/cases/{case_id}/conversation")
    async def case_conversation(case_id: str, limit: int = 20, before: int | None = None,
                                identity=Depends(permission("reports:read_all"))):
        global_scope(identity)
        return await run_in_threadpool(conversation_reader.list_turns, case_id, limit, before)

    @app.get("/api/v1/cases/{case_id}/conversation/{turn_id}")
    async def conversation_turn(case_id: str, turn_id: str, identity=Depends(permission("reports:read_all"))):
        global_scope(identity)
        return await run_in_threadpool(conversation_reader.turn_detail, case_id, turn_id)

    @app.post("/api/v1/cases/{case_id}/conversation", status_code=202)
    async def send_case_message(case_id: str, request: Request, identity=Depends(permission("investigations:request"))):
        global_scope(identity)
        if not identity.permits("reports:read_all", case_id) or not identity.permits("cases:read", case_id):
            raise HTTPException(403, "Case conversation requires case and full-report read permissions.")
        data = await body(request, ChatMessage)
        return await run_in_threadpool(conversation.send, case_id, data.content, identity.analyst_id,
            data.expected_version, data.idempotency_key, data.mode, data.anchor_alert_id)

    @app.post("/api/v1/cases/{case_id}/investigation-requests", status_code=202)
    async def investigate(case_id: str, request: Request, identity=Depends(permission("investigations:request"))):
        global_scope(identity)
        data = await body(request, Investigation)
        return await run_in_threadpool(requests.request, case_id, data.alert_record_id, data.task, identity.analyst_id,
            data.expected_version, data.idempotency_key)

    @app.get("/api/v1/cases/{case_id}/investigation-requests/{job_id}")
    async def investigation_status(case_id: str, job_id: str, identity=Depends(permission("cases:read"))):
        return await run_in_threadpool(requests.get_request, case_id, job_id)

    @app.get("/api/v1/cases/{case_id}/investigation-requests")
    async def investigation_requests(case_id: str, limit: int = 50, before: int | None = None, identity=Depends(permission("cases:read"))):
        return await run_in_threadpool(requests.list_requests, case_id, limit, before)

    @app.post("/api/v1/cases/{case_id}/alerts/{alert_id}/feedback")
    async def feedback(case_id: str, alert_id: str, request: Request, identity=Depends(permission("triage:review"))):
        global_scope(identity)
        data = await body(request, Feedback)
        from cybertriage.bootstrap import build_triage_review
        from cybertriage.domain.triage_policy import AnalystFeedback
        def record():
            cases.require_active_alert(case_id, alert_id)
            return build_triage_review(database).feedback(AnalystFeedback(alert_id, identity.analyst_id, data.label, data.reason))
        return await run_in_threadpool(record)

    @app.get("/api/v1/triage/evaluation")
    async def triage_evaluation(identity=Depends(permission("triage:review"))):
        global_scope(identity)
        from cybertriage.bootstrap import build_triage_evaluation
        return await run_in_threadpool(lambda: build_triage_evaluation(database).execute())

    @app.get("/api/v1/cases/{case_id}/responses")
    async def list_responses(case_id: str, limit: int = 50, after: int = 0, identity=Depends(permission("cases:read"))):
        service = await run_in_threadpool(runtime)
        return await run_in_threadpool(service.list, case_id, limit, after)

    @app.get("/api/v1/cases/{case_id}/response-capabilities")
    async def response_capabilities(case_id: str, identity=Depends(permission("cases:read"))):
        await run_in_threadpool(cases.get, case_id)
        service = await run_in_threadpool(runtime)
        return service.capabilities()

    @app.post("/api/v1/cases/{case_id}/responses", status_code=201)
    async def propose(case_id: str, request: Request, identity=Depends(permission("responses:propose"))):
        data = await body(request, Proposal)
        service = await run_in_threadpool(runtime)
        return await run_in_threadpool(service.propose, case_id, data.action, data.target, data.parameters,
            data.supporting_alert_ids, data.expected_version, identity.analyst_id, data.reason,
            data.idempotency_key, data.origin, data.analysis_id)

    @app.get("/api/v1/cases/{case_id}/responses/{proposal_id}")
    async def show_response(case_id: str, proposal_id: str, identity=Depends(permission("cases:read"))):
        service = await checked_response(case_id, proposal_id)
        return await run_in_threadpool(service.get, proposal_id)

    @app.post("/api/v1/cases/{case_id}/responses/{proposal_id}/reviews")
    async def review_response(case_id: str, proposal_id: str, request: Request, identity=Depends(permission("responses:approve"))):
        data = await body(request, ReviewProposal)
        service = await checked_response(case_id, proposal_id)
        return await run_in_threadpool(service.review, proposal_id, data.decision, data.expected_version, identity.analyst_id, data.reason)

    @app.post("/api/v1/cases/{case_id}/responses/{proposal_id}/execute")
    async def execute_response(case_id: str, proposal_id: str, request: Request, identity=Depends(permission("responses:execute"))):
        data = await body(request, Reasoned)
        service = await checked_response(case_id, proposal_id)
        return await run_in_threadpool(service.execute, proposal_id, data.expected_version, identity.analyst_id, data.reason)

    @app.post("/api/v1/cases/{case_id}/responses/{proposal_id}/reconcile")
    async def reconcile_response(case_id: str, proposal_id: str, request: Request, identity=Depends(permission("responses:reconcile"))):
        data = await body(request, Reconcile)
        service = await checked_response(case_id, proposal_id)
        value = await run_in_threadpool(service.get, proposal_id)
        if not value["execution"]:
            raise ResponseError("This proposal has no execution to reconcile.")
        return await run_in_threadpool(service.reconcile, value["execution"]["execution_id"], data.outcome,
            identity.analyst_id, data.reason, data.evidence)

    @app.post("/api/v1/cases/{case_id}/responses/{proposal_id}/release-reconcile")
    async def reconcile_release(case_id: str, proposal_id: str, request: Request, identity=Depends(permission("responses:reconcile"))):
        data = await body(request, ReleaseReconcile)
        service = await checked_response(case_id, proposal_id)
        value = await run_in_threadpool(service.get, proposal_id)
        if not value["execution"]:
            raise ResponseError("This proposal has no execution to reconcile.")
        return await run_in_threadpool(service.reconcile_release, value["execution"]["execution_id"],
            identity.analyst_id, data.reason, data.evidence)

    contracts = {
        ("post", "/api/v1/auth/login"): Login,
        ("post", "/api/v1/cases"): CreateCase,
        ("patch", "/api/v1/cases/{case_id}"): UpdateCase,
        ("post", "/api/v1/cases/{case_id}/alerts"): AttachAlerts,
        ("delete", "/api/v1/cases/{case_id}/alerts/{alert_id}"): Reasoned,
        ("post", "/api/v1/cases/{case_id}/notes"): Note,
        ("post", "/api/v1/cases/{case_id}/relationships"): Relation,
        ("post", "/api/v1/cases/{case_id}/relationships/{relationship_id}/reviews"): ReviewRelation,
        ("post", "/api/v1/cases/{case_id}/stages"): Stage,
        ("post", "/api/v1/cases/{case_id}/stages/{assertion_id}/reviews"): ReviewRelation,
        ("post", "/api/v1/cases/{case_id}/investigation-requests"): Investigation,
        ("post", "/api/v1/cases/{case_id}/conversation"): ChatMessage,
        ("post", "/api/v1/cases/{case_id}/alerts/{alert_id}/feedback"): Feedback,
        ("post", "/api/v1/cases/{case_id}/responses"): Proposal,
        ("post", "/api/v1/cases/{case_id}/responses/{proposal_id}/reviews"): ReviewProposal,
        ("post", "/api/v1/cases/{case_id}/responses/{proposal_id}/execute"): Reasoned,
        ("post", "/api/v1/cases/{case_id}/responses/{proposal_id}/reconcile"): Reconcile,
        ("post", "/api/v1/cases/{case_id}/responses/{proposal_id}/release-reconcile"): ReleaseReconcile,
    }
    def documented_schema():
        if app.openapi_schema is None:
            from fastapi.openapi.utils import get_openapi
            document = get_openapi(title=app.title, version="1.0.0", routes=app.routes)
            schemas = document.setdefault("components", {}).setdefault("schemas", {})
            for (method, path), model in contracts.items():
                contract = model.model_json_schema(ref_template="#/components/schemas/{model}")
                schemas.update(contract.pop("$defs", {}))
                schemas[model.__name__] = contract
                document["paths"][path][method]["requestBody"] = {"required": True,
                    "content": {"application/json": {"schema": {"$ref": f"#/components/schemas/{model.__name__}"}}}}
            app.openapi_schema = document
        return app.openapi_schema
    app.openapi = documented_schema

    return app
