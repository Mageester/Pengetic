from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable
import json
import queue
import threading

import anyio
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from scopeguard.evidence.redaction import redact_sensitive_value
from scopeguard.findings.models import Finding
from scopeguard.findings.normalize import normalize_findings
from scopeguard.policy.approvals import ApprovalRecord
from scopeguard.policy.gate import GateDecision
from scopeguard.policy.plan import AssessmentAction, AssessmentPlan
from scopeguard.policy.risk import RiskLevel
from scopeguard.reporting.markdown import render_report
from scopeguard.scope.loader import load_scope_package
from scopeguard.scope.models import ScopePackage

from .agent import AssessmentOrchestratorService
from .execution import persist_action_outcome, render_and_store_report
from .llm import OllamaPlannerService, PlannerContext
from .orchestrator import (
    ActionOutcome,
    ApprovalLookup,
    AssessmentRunCoordinator,
    RunExecutionResult,
)
from .schemas import (
    ApprovalCreateRequest,
    ApprovalView,
    ArtifactView,
    DashboardView,
    EventView,
    FindingView,
    LLMPlannerRequest,
    LLMPlannerResponse,
    OrchestratorDecisionView,
    OrchestratorRunRequest,
    OrchestratorRunResponse,
    PlanActionView,
    PlanView,
    RunActionView,
    RunCreateRequest,
    RunResumeRequest,
    RunView,
    ScopeSummary,
    ScopeUploadResponse,
)
from .settings import AppSettings, load_settings
from .state import AssessmentState
from .storage import PengeticStore


class RunEventHub:
    def __init__(self) -> None:
        self._subscribers: dict[str, list[queue.Queue[dict[str, Any]]]] = {}
        self._lock = threading.Lock()

    def subscribe(self, run_id: str) -> queue.Queue[dict[str, Any]]:
        subscriber: queue.Queue[dict[str, Any]] = queue.Queue()
        with self._lock:
            self._subscribers.setdefault(run_id, []).append(subscriber)
        return subscriber

    def unsubscribe(self, run_id: str, subscriber: queue.Queue[dict[str, Any]]) -> None:
        with self._lock:
            subscribers = self._subscribers.get(run_id)
            if not subscribers:
                return
            if subscriber in subscribers:
                subscribers.remove(subscriber)
            if not subscribers:
                self._subscribers.pop(run_id, None)

    def publish(self, run_id: str, event: dict[str, Any]) -> None:
        with self._lock:
            subscribers = list(self._subscribers.get(run_id, []))
        for subscriber in subscribers:
            subscriber.put(event)


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _scope_view(scope: dict[str, Any] | None) -> ScopeSummary | None:
    if scope is None:
        return None
    return ScopeSummary.model_validate(
        {
            "id": scope["id"],
            "name": scope["name"],
            "primary_domain": scope["primary_domain"],
            "base_url": scope["base_url"],
            "authorized_hosts": scope["authorized_hosts"],
            "allowed_subdomains": scope["allowed_subdomains"],
            "allowed_urls": scope["allowed_urls"],
            "login_areas_allowed": scope["login_areas_allowed"],
            "apis_allowed": scope["apis_allowed"],
            "tool_allowlist": scope["tool_allowlist"],
            "authorization_note": scope["authorization_note"],
            "notes": scope.get("notes"),
            "created_at": scope["created_at"],
            "updated_at": scope["updated_at"],
        }
    )


def _plan_view(plan: dict[str, Any] | None) -> PlanView | None:
    if plan is None:
        return None
    return PlanView.model_validate(
        {
            "id": plan["id"],
            "scope_id": plan["scope_id"],
            "scope_name": plan["scope_name"],
            "scope_fingerprint": plan["scope_fingerprint"],
            "profile": plan["profile"],
            "generated_at": plan["generated_at"],
            "actions": [
                PlanActionView.model_validate(action)
                for action in plan["actions"]
            ],
        }
    )


def _finding_view(finding: dict[str, Any]) -> FindingView:
    return FindingView.model_validate(finding)


def _artifact_view(artifact: dict[str, Any]) -> ArtifactView:
    return ArtifactView.model_validate(artifact)


def _approval_view(approval: dict[str, Any]) -> ApprovalView:
    return ApprovalView.model_validate(approval)


def _event_view(event: dict[str, Any]) -> EventView:
    return EventView.model_validate(event)


def _run_action_view(action: dict[str, Any]) -> RunActionView:
    return RunActionView.model_validate(action)


def _outcome_from_action(action: dict[str, Any]) -> ActionOutcome:
    assessment_action = AssessmentAction.model_validate(
        {
            "action_id": action["action_id"],
            "title": action["title"],
            "objective": action["objective"],
            "target": action["target"],
            "tool_id": action["tool_id"],
            "classification": action["classification"],
            "expected_evidence": action["expected_evidence"],
            "approval_required": action["approval_required"],
            "allowed_by_scope": action["allowed_by_scope"],
            "notes": action["notes"],
        }
    )
    decision = GateDecision(
        approved=action["status"] in {"executed", "approved", "skipped", "blocked"},
        auto_approved=action["classification"] == RiskLevel.passive_safe.value,
        reason=action["decision_reason"] or action["status"],
    )
    started_at = (
        datetime.fromisoformat(action["started_at"].replace("Z", "+00:00"))
        if action.get("started_at")
        else None
    )
    finished_at = (
        datetime.fromisoformat(action["finished_at"].replace("Z", "+00:00"))
        if action.get("finished_at")
        else None
    )
    return ActionOutcome(
        action=assessment_action,
        decision=decision,
        status=action["status"],
        summary=action["decision_reason"] or action["status"],
        evidence_paths=action["evidence_paths"],
        result=None,
        started_at=started_at,
        finished_at=finished_at,
        details=action["result"] or {},
    )


def _run_summary_from_db(store: PengeticStore, run_id: str) -> SimpleNamespace:
    run = store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found.")
    plan = _plan_view(run["plan"])
    outcomes = [_outcome_from_action(action) for action in run["actions"]]
    findings = [Finding.model_validate(item) for item in run["findings"]]
    evidence_paths = sorted({artifact["path"] for artifact in run["artifacts"] if artifact["kind"] in {"evidence", "report"}})
    started_at = (
        datetime.fromisoformat(run["started_at"].replace("Z", "+00:00"))
        if run.get("started_at")
        else datetime.now(UTC)
    )
    finished_at = (
        datetime.fromisoformat(run["finished_at"].replace("Z", "+00:00"))
        if run.get("finished_at")
        else datetime.now(UTC)
    )
    return SimpleNamespace(
        run_id=run["id"],
        started_at=started_at,
        finished_at=finished_at,
        profile=run["profile"],
        report_generated_at=datetime.now(UTC),
        outcomes=outcomes,
        findings=findings,
        evidence_paths=evidence_paths,
    )


def _render_dashboard(store: PengeticStore) -> DashboardView:
    current_scope = _scope_view(store.get_current_scope())
    current_plan = _plan_view(store.get_current_plan())
    latest_run = store.get_latest_run()
    latest_run_view = _run_view(latest_run) if latest_run else None
    recent_runs = [_run_view(run) for run in store.list_runs(limit=5)]
    pending = [_run_action_view(action) for action in store.list_pending_approvals(latest_run["id"])] if latest_run else []
    recent_findings = [_finding_view(item) for item in (latest_run["findings"] if latest_run else [])[:5]]
    state = store.current_state() or (latest_run["state"] if latest_run else AssessmentState.idle.value)
    return DashboardView(
        current_scope=current_scope,
        current_plan=current_plan,
        latest_run=latest_run_view,
        counts=store.get_dashboard_counts(),
        pending_approvals=pending,
        recent_findings=recent_findings,
        recent_runs=recent_runs,
        state=state,
    )


def _run_view(run: dict[str, Any] | None) -> RunView:
    if run is None:
        raise ValueError("Run data is required.")
    return RunView.model_validate(
        {
            "id": run["id"],
            "scope_id": run["scope_id"],
            "scope_name": run["scope_name"],
            "scope_fingerprint": run["scope_fingerprint"],
            "profile": run["profile"],
            "state": run["state"],
            "status": run["status"],
            "started_at": run["started_at"],
            "finished_at": run["finished_at"],
            "created_at": run["created_at"],
            "updated_at": run["updated_at"],
            "report_path": run["report_path"],
            "report_text": run["report_text"],
            "manual_notes": run["manual_notes"],
            "plan_id": run["plan_id"],
            "plan": _plan_view(run["plan"]),
            "actions": [_run_action_view(item) for item in run["actions"]],
            "findings": [_finding_view(item) for item in run["findings"]],
            "artifacts": [_artifact_view(item) for item in run["artifacts"]],
            "approvals": [_approval_view(item) for item in run["approvals"]],
            "events": [_event_view(item) for item in run["events"]],
        }
    )


def create_app(settings: AppSettings | None = None) -> FastAPI:
    app_settings = settings or load_settings()
    store = PengeticStore(app_settings.paths.db_path)
    store.initialize()
    hub = RunEventHub()
    app = FastAPI(
        title="Pengetic",
        version="0.2.0",
        description="Local-first defensive web assessment platform.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(app_settings.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.settings = app_settings
    app.state.store = store
    app.state.hub = hub

    def emit_event(run_id: str, event: dict[str, Any]) -> None:
        store.add_run_event(
            run_id,
            event_type=event["type"],
            message=event["message"],
            level=event.get("level", "info"),
            action_id=event.get("action_id"),
            tool_id=event.get("tool_id"),
            payload=event.get("payload") or {},
        )
        hub.publish(run_id, event)

    def approval_lookup_factory(run_id: str) -> ApprovalLookup:
        def lookup(action_id: str, scope_fp: str) -> ApprovalRecord | None:
            for approval in reversed(store.list_approvals(run_id)):
                if approval["action_id"] != action_id or approval["scope_fingerprint"] != scope_fp:
                    continue
                return ApprovalRecord(
                    action_id=approval["action_id"],
                    scope_fingerprint=approval["scope_fingerprint"],
                    approved_by=approval["approved_by"] or "user",
                    approved_at=approval["approved_at"] or _now(),
                    note=approval["note"] or "",
                    risk=RiskLevel(approval["risk"]),
                )
            return None

        return ApprovalLookup(lookup)

    def run_worker(*, run_id: str, action_ids: set[str] | None = None, include_approved_active: bool = False, resume: bool = False) -> None:
        run = store.get_run(run_id)
        if run is None:
            return
        scope_row = store.get_scope(run["scope_id"])
        if scope_row is None:
            return
        scope = ScopePackage.model_validate(scope_row["scope_json"])
        plan = AssessmentPlan.model_validate_json(run["plan_json"])
        coordinator = AssessmentRunCoordinator(
            scope,
            profile=run["profile"],
            artifacts_root=app_settings.paths.artifacts_dir,
            manual_notes=run["manual_notes"],
        )
        run_dir = coordinator.build_run_dir(run_id)
        approvals = approval_lookup_factory(run_id)

        try:
            result = coordinator.execute(
                plan,
                run_id=run_id,
                run_dir=run_dir,
                approvals=approvals,
                include_approved_active=include_approved_active,
                action_ids=action_ids,
                stop_on_pending_active=(not resume and action_ids is None),
                event_sink=lambda event: emit_event(run_id, event),
                resume=resume,
            )

            for outcome in result.outcomes:
                normalized_findings = normalize_findings(
                    outcome.result.findings if outcome.result is not None else [],
                    source_action_id=outcome.action.action_id,
                )
                persist_action_outcome(
                    store,
                    run_id,
                    outcome,
                    normalized_findings=normalized_findings,
                )

            remaining_blockers = [
                action["action_id"]
                for action in store.list_run_actions(run_id)
                if action["classification"] != RiskLevel.passive_safe.value
                and action["status"] in {"queued", "pending-approval", "approved"}
            ]
            final_state = AssessmentState.awaiting_approval.value if remaining_blockers else AssessmentState.completed.value
            store.update_run(
                run_id,
                state=final_state,
                status=final_state,
                summary_json={
                    "state": final_state,
                    "pending_action_ids": remaining_blockers,
                    "findings": len(result.findings),
                    "executed_actions": len([item for item in result.outcomes if item.status == "executed"]),
                },
                finished_at=result.finished_at.isoformat().replace("+00:00", "Z"),
            )
            store.set_assessment_state(final_state)

            report_path, report_text = render_and_store_report(
                store,
                scope,
                plan,
                run_id,
                run_dir,
                state=final_state,
                summary_json={
                    "state": final_state,
                    "pending_action_ids": remaining_blockers,
                    "findings": len(store.list_findings(run_id)),
                    "executed_actions": len([item for item in result.outcomes if item.status == "executed"]),
                },
                record_artifact=True,
            )
            emit_event(
                run_id,
                {
                    "type": "run_state",
                    "message": f"Run state updated to {final_state}.",
                    "level": "info",
                    "payload": {"state": final_state, "pending_action_ids": remaining_blockers},
                },
            )
        except Exception as exc:
            store.update_run(
                run_id,
                state=AssessmentState.failed.value,
                status=AssessmentState.failed.value,
                summary_json={"error": str(exc)},
                finished_at=_now(),
            )
            store.set_assessment_state(AssessmentState.failed.value)
            emit_event(
                run_id,
                {
                    "type": "run_failed",
                    "message": str(exc),
                    "level": "error",
                    "payload": {"error": str(exc)},
                },
            )

    def launch_worker(**kwargs: Any) -> None:
        thread = threading.Thread(target=run_worker, kwargs=kwargs, daemon=True)
        thread.start()

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "pengetic"}

    @app.get("/api/dashboard", response_model=DashboardView)
    def dashboard() -> DashboardView:
        return _render_dashboard(store)

    @app.get("/api/scopes/current", response_model=ScopeSummary | None)
    def current_scope() -> ScopeSummary | None:
        return _scope_view(store.get_current_scope())

    @app.get("/api/scopes", response_model=list[ScopeSummary])
    def list_scopes() -> list[ScopeSummary]:
        return [view for scope in store.list_scopes() if (view := _scope_view(scope)) is not None]

    @app.post("/api/scopes/upload", response_model=ScopeUploadResponse)
    async def upload_scope(
        file: UploadFile = File(...),
        profile: str = Form("passive-only"),
        activate: bool = Form(True),
    ) -> ScopeUploadResponse:
        raw = await file.read()
        text = raw.decode("utf-8")
        saved_path = app_settings.paths.scopes_dir / f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{file.filename or 'scope.yaml'}"
        saved_path.parent.mkdir(parents=True, exist_ok=True)
        saved_path.write_text(text, encoding="utf-8")
        store.set_assessment_state(AssessmentState.scope_uploaded.value)
        try:
            scope = load_scope_package(saved_path)
        except Exception as exc:
            store.set_assessment_state(AssessmentState.failed.value)
            try:
                saved_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        store.set_assessment_state(AssessmentState.scope_validated.value)
        stored_scope = store.upsert_scope(scope, raw_yaml=text, source_path=str(saved_path))
        coordinator = AssessmentRunCoordinator(
            scope,
            profile=profile,
            artifacts_root=app_settings.paths.artifacts_dir,
        )
        plan = coordinator.build_plan()
        stored_plan = store.save_plan(scope, profile, plan, activate=activate)
        store.set_assessment_state(AssessmentState.plan_ready.value)
        return ScopeUploadResponse(
            scope=_scope_view(stored_scope),
            plan=_plan_view(stored_plan),
            validation_message=f"Scope {scope.name} validated and plan generated.",
        )

    @app.get("/api/plans/current", response_model=PlanView | None)
    def current_plan() -> PlanView | None:
        return _plan_view(store.get_current_plan())

    @app.get("/api/runs", response_model=list[RunView])
    def list_runs(limit: int = 20) -> list[RunView]:
        return [_run_view(run) for run in store.list_runs(limit=limit)]

    @app.get("/api/runs/{run_id}", response_model=RunView)
    def get_run(run_id: str) -> RunView:
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return _run_view(run)

    @app.get("/api/runs/{run_id}/actions", response_model=list[RunActionView])
    def get_run_actions(run_id: str) -> list[RunActionView]:
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return [_run_action_view(action) for action in run["actions"]]

    @app.get("/api/runs/{run_id}/approvals", response_model=list[ApprovalView])
    def get_run_approvals(run_id: str) -> list[ApprovalView]:
        if store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return [_approval_view(approval) for approval in store.list_approvals(run_id)]

    @app.get("/api/runs/{run_id}/findings", response_model=list[FindingView])
    def get_run_findings(run_id: str) -> list[FindingView]:
        if store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return [_finding_view(finding) for finding in store.list_findings(run_id)]

    @app.get("/api/runs/{run_id}/artifacts", response_model=list[ArtifactView])
    def get_run_artifacts(run_id: str) -> list[ArtifactView]:
        if store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return [_artifact_view(artifact) for artifact in store.list_artifacts(run_id)]

    @app.get("/api/runs/{run_id}/events", response_model=list[EventView])
    def get_run_events(run_id: str, after_id: int | None = None) -> list[EventView]:
        if store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return [_event_view(event) for event in store.list_events(run_id, after_id=after_id)]

    @app.get("/api/runs/{run_id}/stream")
    async def stream_run_events(run_id: str, after_id: int | None = None) -> Response:
        if store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        subscriber = hub.subscribe(run_id)

        async def generator() -> Any:
            try:
                existing = store.list_events(run_id, after_id=after_id)
                for event in existing:
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                while True:
                    event = await anyio.to_thread.run_sync(subscriber.get)
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                    if event.get("type") in {"run_complete", "run_failed"}:
                        break
            finally:
                hub.unsubscribe(run_id, subscriber)

        return StreamingResponse(generator(), media_type="text/event-stream")

    @app.post("/api/runs", response_model=RunView, status_code=202)
    def start_run(request: RunCreateRequest) -> RunView:
        scope_row = store.get_current_scope()
        if scope_row is None:
            raise HTTPException(status_code=400, detail="No validated scope is loaded.")
        scope = ScopePackage.model_validate(scope_row["scope_json"])
        coordinator = AssessmentRunCoordinator(
            scope,
            profile=request.profile,
            artifacts_root=app_settings.paths.artifacts_dir,
            manual_notes=request.manual_notes,
        )
        current_plan = store.get_current_plan()
        if current_plan is None or current_plan["scope_id"] != scope_row["id"] or current_plan["profile"] != request.profile:
            plan = coordinator.build_plan()
            store.save_plan(scope, request.profile, plan, activate=True)
        else:
            plan = AssessmentPlan.model_validate_json(current_plan["plan_json"])
        run_record = store.create_run(scope, plan, profile=request.profile, manual_notes=request.manual_notes)
        store.set_assessment_state(AssessmentState.running.value)
        launch_worker(run_id=run_record["id"], include_approved_active=request.include_approved_active, resume=False)
        return _run_view(run_record)

    @app.post("/api/runs/{run_id}/resume", response_model=RunView, status_code=202)
    def resume_run(run_id: str, request: RunResumeRequest) -> RunView:
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        pending_actions = [action for action in run["actions"] if action["status"] == "approved" and action["result"] is None]
        if not pending_actions:
            raise HTTPException(status_code=400, detail="No approved actions are waiting to be resumed.")
        launch_worker(
            run_id=run_id,
            action_ids={action["action_id"] for action in pending_actions},
            include_approved_active=request.include_approved_active,
            resume=True,
        )
        store.set_assessment_state(AssessmentState.running.value)
        refreshed = store.get_run(run_id)
        if refreshed is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return _run_view(refreshed)

    @app.post("/api/approvals", response_model=ApprovalView)
    def approve_action(request: ApprovalCreateRequest) -> ApprovalView:
        run = store.get_run(request.run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        action = next((item for item in run["actions"] if item["action_id"] == request.action_id), None)
        if action is None:
            raise HTTPException(status_code=404, detail="Action not found in run.")
        if action["classification"] == RiskLevel.passive_safe.value:
            raise HTTPException(status_code=400, detail="Passive-safe actions do not require approval.")
        approval = store.record_approval(
            run_id=request.run_id,
            action_id=request.action_id,
            scope_fingerprint_value=run["scope_fingerprint"],
            risk=action["classification"],
            approved_by=request.approved_by,
            note=request.note,
            decision_reason="Explicit approval recorded in the Pengetic queue.",
        )
        emit_event(
            request.run_id,
            {
                "type": "approval_recorded",
                "message": f"Approval recorded for {request.action_id}.",
                "level": "info",
                "action_id": request.action_id,
                "payload": approval,
            },
        )
        if store.get_setting("assessment_state") is None:
            store.set_assessment_state(AssessmentState.awaiting_approval.value)
        return _approval_view(approval)

    @app.get("/api/reports/{run_id}", response_model=dict[str, Any])
    def get_report(run_id: str) -> dict[str, Any]:
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return {
            "run_id": run_id,
            "report_path": run["report_path"],
            "report_text": run["report_text"],
        }

    @app.get("/api/reports/{run_id}/export")
    def export_report(run_id: str) -> Response:
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        if not run["report_path"]:
            raise HTTPException(status_code=404, detail="Report not available.")
        report_path = Path(run["report_path"])
        if not report_path.exists():
            raise HTTPException(status_code=404, detail="Report file not found.")
        return FileResponse(report_path, media_type="text/markdown", filename=f"pengetic-{run_id}.md")

    @app.post("/api/llm/planner", response_model=LLMPlannerResponse)
    async def llm_planner(request: LLMPlannerRequest) -> LLMPlannerResponse:
        run = store.get_run(request.run_id) if request.run_id else store.get_latest_run()
        scope = store.get_current_scope() if request.scope_id is None else store.get_scope(request.scope_id)
        if scope is None:
            raise HTTPException(status_code=404, detail="No scope is available.")
        if run is None and request.run_id is not None:
            raise HTTPException(status_code=404, detail="Run not found.")
        plan = _plan_view(run["plan"]) if run and run.get("plan") else _plan_view(store.get_current_plan())
        if plan is None:
            raise HTTPException(status_code=404, detail="No plan is available.")
        findings = run["findings"] if run else []
        pending_actions = [action for action in (run["actions"] if run else []) if action["status"] == "pending-approval"]
        approved_actions = [action for action in (run["actions"] if run else []) if action["status"] == "approved"]
        latest_summary = json.dumps(run["summary_json"], ensure_ascii=False, default=str) if run else None
        context = PlannerContext(
            scope_name=scope["name"],
            scope_id=scope["id"],
            run_id=run["id"] if run else None,
            state=run["state"] if run else AssessmentState.idle.value,
            profile=run["profile"] if run else plan.profile,
            findings=findings,
            pending_actions=pending_actions,
            approved_actions=approved_actions,
            plan_actions=[action.model_dump(mode="json") for action in plan.actions],
            latest_run_summary=latest_summary,
        )
        service = OllamaPlannerService(base_url=app_settings.ollama_base_url, model=request.model or app_settings.ollama_model)
        suggestion = await service.suggest(context, model=request.model)
        store.store_llm_recommendation(
            run_id=run["id"] if run else None,
            scope_id=scope["id"],
            model=suggestion.model,
            source=suggestion.source,
            summary=suggestion.summary,
            next_allowed_step=suggestion.next_allowed_step,
            recommended_action_id=suggestion.recommended_action_id,
            rationale=suggestion.rationale,
            confidence=suggestion.confidence,
            raw_json=suggestion.raw,
        )
        return LLMPlannerResponse.model_validate(suggestion.model_dump())

    @app.post("/api/runs/{run_id}/orchestrate", response_model=OrchestratorRunResponse)
    async def orchestrate_run(run_id: str, request: OrchestratorRunRequest) -> OrchestratorRunResponse:
        if store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        orchestrator = AssessmentOrchestratorService(store=store, settings=app_settings)
        try:
            return await orchestrator.run_assessment(
                run_id,
                max_steps=request.max_steps,
                model=request.model or app_settings.ollama_model,
                event_sink=emit_event,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/runs/{run_id}/orchestrator/steps", response_model=list[OrchestratorDecisionView])
    def list_orchestrator_steps(run_id: str) -> list[OrchestratorDecisionView]:
        if store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return [OrchestratorDecisionView.model_validate(step["decision_json"]) for step in store.list_orchestrator_steps(run_id)]

    @app.get("/")
    def serve_root() -> Response:
        index_path = app_settings.paths.frontend_dist_dir / "index.html"
        if index_path.exists():
            return FileResponse(index_path)
        return PlainTextResponse(
            "Pengetic backend is running. Build the frontend with `npm install` and `npm run build` in /frontend.",
            status_code=200,
        )

    @app.get("/{path:path}")
    def serve_frontend(path: str) -> Response:
        if path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not found.")
        index_path = app_settings.paths.frontend_dist_dir / "index.html"
        if index_path.exists():
            return FileResponse(index_path)
        raise HTTPException(status_code=404, detail="Frontend build not found.")

    if app_settings.paths.frontend_dist_dir.exists():
        assets_dir = app_settings.paths.frontend_dist_dir / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    return app
