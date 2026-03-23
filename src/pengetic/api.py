from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse
from typing import Any, Callable
import json
import queue
import threading

import anyio
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response, StreamingResponse
import yaml

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
from .llm import OllamaPlannerService, OllamaPulseService, PlannerContext
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
    EvidenceCorrelationView,
    EnginePulseView,
    DashboardView,
    EventView,
    FindingView,
    FindingCandidateView,
    LLMPlannerRequest,
    LLMPlannerResponse,
    OllamaModelView,
    OllamaModelUpdateRequest,
    OrchestratorDecisionView,
    OrchestratorRunRequest,
    OrchestratorRunResponse,
    PlanActionView,
    PlanView,
    RunActionView,
    RunCreateRequest,
    RunResumeRequest,
    RunView,
    ToolArtifactView,
    ToolResultView,
    ScopeSummary,
    ScopeTemplateRequest,
    ScopeTemplateResponse,
    ScopeUploadResponse,
    WorkspacePurgeRequest,
    WorkspacePurgeResponse,
)
from .settings import AppSettings, load_settings
from .state import AssessmentState
from .workspace import WorkspaceReset
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


def _root_url(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = parsed.hostname or value
    scheme = parsed.scheme or "https"
    return f"{scheme}://{host.rstrip('/')}/"


def _template_tool_allowlist(template_id: str) -> list[str]:
    passive = [
        "http-probe",
        "header-review",
        "tls-review",
        "dns-visibility",
        "robots-fetch",
        "sitemap-fetch",
        "route-inventory",
        "tech-fingerprint",
        "manual-review",
    ]
    if template_id == "internal-audit":
        return [*passive, "nmap-service-discovery", "approved-login-surface-probe", "approved-api-surface-probe"]
    if template_id == "api-surface-mapping":
        return [*passive, "nmap-service-discovery", "approved-api-surface-probe"]
    return [*passive, "nmap-service-discovery"]


def _generate_template_scope(request: ScopeTemplateRequest) -> tuple[ScopePackage, str]:
    target = _root_url(request.target_url)
    parsed = urlparse(target)
    host = parsed.hostname
    if host is None:
        raise HTTPException(status_code=400, detail="Target URL must include a host.")

    template_name = {
        "internal-audit": "Internal Audit",
        "web-surface-mapping": "Web Surface Mapping",
        "api-surface-mapping": "API Surface Mapping",
    }.get(request.template_id, request.scope_name or "Generated Assessment")

    allowed_subdomains = sorted(
        {
            *{sub.strip().lower() for sub in request.allowed_subdomains if sub.strip()},
            f"www.{host}",
            f"app.{host}",
        }
    )
    if request.template_id == "api-surface-mapping":
        allowed_subdomains = sorted({*allowed_subdomains, f"api.{host}"})

    allowed_urls = [target]
    if request.login_areas_allowed:
        allowed_urls.extend(
            _root_url(f"{parsed.scheme}://{host}{route if route.startswith('/') else '/' + route}")
            if route.startswith("http://") or route.startswith("https://")
            else f"{target.rstrip('/')}{route if route.startswith('/') else '/' + route}"
            for route in request.login_areas_allowed
        )
    if request.apis_allowed:
        allowed_urls.extend(
            route if route.startswith("http://") or route.startswith("https://") else f"{target.rstrip('/')}{route if route.startswith('/') else '/' + route}"
            for route in request.apis_allowed
        )

    scope_data = {
        "version": 1,
        "name": request.scope_name or template_name,
        "primary_domain": host,
        "base_url": target,
        "allowed_subdomains": allowed_subdomains,
        "allowed_urls": list(dict.fromkeys(allowed_urls)),
        "out_of_scope_assets": [],
        "login_areas_allowed": request.login_areas_allowed or ["/login"],
        "apis_allowed": request.apis_allowed or (["/api"] if request.template_id != "web-surface-mapping" else []),
        "tool_allowlist": request.tool_allowlist or _template_tool_allowlist(request.template_id),
        "rate_limits": {
            "max_requests_per_minute": 60,
            "max_concurrent_requests": 2,
            "delay_seconds_between_requests": 0.5,
        },
        "testing_window": {
            "start": _now(),
            "end": None,
        },
        "authorization_note": request.authorization_note,
        "contacts": request.contacts,
        "notes": request.notes,
    }
    scope = ScopePackage.model_validate(scope_data)
    generated_yaml = yaml.safe_dump(scope.model_dump(mode="json"), sort_keys=False)
    return scope, generated_yaml


def _frontend_fallback_response() -> HTMLResponse:
    return HTMLResponse(
        """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Pengetic</title>
    <style>
      :root {
        color-scheme: dark;
        font-family: Inter, ui-sans-serif, system-ui, sans-serif;
        background: #08111f;
        color: #d7e7ff;
      }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        background:
          radial-gradient(circle at top, rgba(59, 130, 246, 0.18), transparent 40%),
          linear-gradient(180deg, #08111f 0%, #050a14 100%);
      }
      main {
        width: min(720px, calc(100vw - 3rem));
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 20px;
        padding: 2rem;
        background: rgba(15, 23, 42, 0.8);
        box-shadow: 0 30px 90px rgba(2, 6, 23, 0.45);
      }
      h1 { margin: 0 0 0.75rem; font-size: 2rem; }
      p { line-height: 1.6; color: #b8c7dd; }
      code {
        padding: 0.15rem 0.4rem;
        border-radius: 6px;
        background: rgba(15, 23, 42, 0.9);
        color: #9cc5ff;
      }
      ul { line-height: 1.7; color: #c8d5e8; }
    </style>
  </head>
  <body>
    <main>
      <h1>Pengetic frontend is not built yet</h1>
      <p>The API is running, but the compiled React UI was not found at <code>frontend/dist</code>.</p>
      <p>Build the frontend once after installing dependencies:</p>
      <ul>
        <li><code>cd frontend</code></li>
        <li><code>npm install</code></li>
        <li><code>npm run build</code></li>
      </ul>
      <p>After that, restart <code>pengetic serve</code> and the GUI will load normally.</p>
    </main>
  </body>
</html>
        """.strip(),
        media_type="text/html",
    )


def _frontend_index_response(app_settings: AppSettings) -> Response:
    index_path = app_settings.paths.frontend_dist_dir / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return _frontend_fallback_response()


def _frontend_asset_response(app_settings: AppSettings, asset_path: str) -> Response:
    assets_root = (app_settings.paths.frontend_dist_dir / "assets").resolve()
    requested_asset = (assets_root / asset_path).resolve()
    try:
        requested_asset.relative_to(assets_root)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Frontend asset not found.") from exc
    if not requested_asset.exists() or not requested_asset.is_file():
        raise HTTPException(status_code=404, detail="Frontend asset not found.")
    return FileResponse(requested_asset)


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


def _tool_artifact_view(artifact: dict[str, Any]) -> ToolArtifactView:
    return ToolArtifactView.model_validate(artifact)


def _finding_candidate_view(candidate: dict[str, Any]) -> FindingCandidateView:
    return FindingCandidateView.model_validate(candidate)


def _tool_result_view(result: dict[str, Any]) -> ToolResultView:
    payload = dict(result)
    payload["artifacts"] = [_tool_artifact_view(item) for item in result.get("artifacts", [])]
    payload["findings_candidates"] = [_finding_candidate_view(item) for item in result.get("findings_candidates", [])]
    return ToolResultView.model_validate(payload)


def _evidence_correlation_view(correlation: dict[str, Any]) -> EvidenceCorrelationView:
    return EvidenceCorrelationView.model_validate(correlation)


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
    current_scope_id = store.current_scope_id()
    current_scope = _scope_view(store.get_current_scope())
    current_plan = _plan_view(store.get_current_plan(current_scope_id))
    latest_run = store.get_latest_run(current_scope_id)
    latest_run_view = _run_view(latest_run, store) if latest_run else None
    recent_runs = [_run_view(run, store) for run in store.list_runs(limit=5, scope_id=current_scope_id)]
    pending = [_run_action_view(action) for action in store.list_pending_approvals(latest_run["id"])] if latest_run else []
    recent_findings = [_finding_view(item) for item in (latest_run["findings"] if latest_run else [])[:5]]
    state = store.current_state() or (latest_run["state"] if latest_run else AssessmentState.idle.value)
    return DashboardView(
        current_scope=current_scope,
        current_plan=current_plan,
        latest_run=latest_run_view,
        counts=store.get_dashboard_counts(current_scope_id),
        pending_approvals=pending,
        recent_findings=recent_findings,
        recent_runs=recent_runs,
        state=state,
    )


def _run_view(run: dict[str, Any] | None, store: PengeticStore | None = None) -> RunView:
    if run is None:
        raise ValueError("Run data is required.")
    tool_results = store.list_tool_results(run["id"]) if store is not None else []
    correlation = store.correlate_tool_results(run["id"]) if store is not None else None
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
            "tool_results": [_tool_result_view(item) for item in tool_results],
            "evidence_correlation": _evidence_correlation_view(correlation) if correlation is not None else None,
            "approvals": [_approval_view(item) for item in run["approvals"]],
            "events": [_event_view(item) for item in run["events"]],
        }
    )


def create_app(settings: AppSettings | None = None) -> FastAPI:
    app_settings = settings or load_settings()
    store = PengeticStore(app_settings.paths.db_path)
    store.initialize()
    backend_default_model = app_settings.ollama_model
    persisted_model = store.get_selected_ollama_model()
    if persisted_model:
        app_settings = replace(app_settings, ollama_model=persisted_model)
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
    app.state.backend_default_model = backend_default_model
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
        return _plan_view(store.get_current_plan(store.current_scope_id()))

    @app.get("/api/llm/model", response_model=OllamaModelView)
    def get_ollama_model() -> OllamaModelView:
        return OllamaModelView.model_validate(
            {
                "selected_model": app_settings.ollama_model,
                "backend_default_model": app.state.backend_default_model,
                "source": "database" if store.get_selected_ollama_model() else "environment",
                "updated_at": _now(),
            }
        )

    @app.post("/api/llm/model", response_model=OllamaModelView)
    def set_ollama_model(request: OllamaModelUpdateRequest) -> OllamaModelView:
        nonlocal app_settings
        model = request.model.strip()
        if not model:
            raise HTTPException(status_code=400, detail="model is required.")
        store.set_selected_ollama_model(model)
        app_settings = replace(app_settings, ollama_model=model)
        app.state.settings = app_settings
        return OllamaModelView.model_validate(
            {
                "selected_model": model,
                "backend_default_model": app.state.backend_default_model,
                "source": "database",
                "updated_at": _now(),
            }
        )

    @app.get("/api/engine/pulse", response_model=EnginePulseView)
    async def engine_pulse() -> EnginePulseView:
        service = OllamaPulseService(base_url=app_settings.ollama_base_url)
        pulse = await service.pulse(selected_model=app_settings.ollama_model)
        return EnginePulseView.model_validate(pulse)

    @app.post("/api/scopes/templates/generate", response_model=ScopeTemplateResponse)
    def generate_scope_template(request: ScopeTemplateRequest) -> ScopeTemplateResponse:
        scope, generated_yaml = _generate_template_scope(request)
        saved_path = app_settings.paths.scopes_dir / f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{request.template_id}.yaml"
        saved_path.parent.mkdir(parents=True, exist_ok=True)
        saved_path.write_text(generated_yaml, encoding="utf-8")
        stored_scope = store.upsert_scope(scope, raw_yaml=generated_yaml, source_path=str(saved_path))
        coordinator = AssessmentRunCoordinator(
            scope,
            profile=request.profile,
            artifacts_root=app_settings.paths.artifacts_dir,
        )
        plan = coordinator.build_plan()
        stored_plan = store.save_plan(scope, request.profile, plan, activate=request.activate)
        store.set_assessment_state(AssessmentState.plan_ready.value)
        return ScopeTemplateResponse.model_validate(
            {
                "template_id": request.template_id,
                "generated_yaml": generated_yaml,
                "scope": _scope_view(stored_scope),
                "plan": _plan_view(stored_plan),
                "validation_message": f"Template {request.template_id} generated and validated for {scope.name}.",
            }
        )

    @app.get("/api/runs", response_model=list[RunView])
    def list_runs(limit: int = 20, scope_id: str | None = None) -> list[RunView]:
        return [_run_view(run, store) for run in store.list_runs(limit=limit, scope_id=scope_id)]

    @app.get("/api/runs/{run_id}", response_model=RunView)
    def get_run(run_id: str) -> RunView:
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return _run_view(run, store)

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

    @app.get("/api/runs/{run_id}/tool-results", response_model=list[ToolResultView])
    def get_run_tool_results(run_id: str, tool_id: str | None = None) -> list[ToolResultView]:
        if store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        results = store.list_tool_results(run_id, tool_id=tool_id)
        return [_tool_result_view(result) for result in results]

    @app.get("/api/runs/{run_id}/evidence-correlation", response_model=EvidenceCorrelationView)
    def get_run_evidence_correlation(run_id: str) -> EvidenceCorrelationView:
        if store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return _evidence_correlation_view(store.correlate_tool_results(run_id))

    @app.get("/api/runs/{run_id}/service-inventory", response_model=list[dict[str, Any]])
    def get_run_service_inventory(run_id: str) -> list[dict[str, Any]]:
        if store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return store.correlate_tool_results(run_id)["service_inventory"]

    @app.get("/api/runs/{run_id}/route-inventory", response_model=list[dict[str, Any]])
    def get_run_route_inventory(run_id: str) -> list[dict[str, Any]]:
        if store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return store.correlate_tool_results(run_id)["route_inventory"]

    @app.get("/api/runs/{run_id}/tls-summary", response_model=list[dict[str, Any]])
    def get_run_tls_summary(run_id: str) -> list[dict[str, Any]]:
        if store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return store.correlate_tool_results(run_id)["tls_posture"]

    @app.get("/api/runs/{run_id}/header-summary", response_model=list[dict[str, Any]])
    def get_run_header_summary(run_id: str) -> list[dict[str, Any]]:
        if store.get_run(run_id) is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return store.correlate_tool_results(run_id)["header_posture"]

    @app.get("/api/runs/{run_id}/planner-evidence-context", response_model=dict[str, Any])
    def get_run_planner_evidence_context(run_id: str) -> dict[str, Any]:
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found.")
        return {
            "run_id": run_id,
            "scope_id": run["scope_id"],
            "scope_name": run["scope_name"],
            "current_model": store.get_selected_ollama_model() or app.state.settings.ollama_model,
            "current_state": store.current_state() or run["state"],
            "correlation": store.correlate_tool_results(run_id),
            "tool_results": store.list_tool_results(run_id),
        }

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
        current_plan = store.get_current_plan(scope_row["id"])
        if current_plan is None or current_plan["scope_id"] != scope_row["id"] or current_plan["profile"] != request.profile:
            plan = coordinator.build_plan()
            store.save_plan(scope, request.profile, plan, activate=True)
        else:
            plan = AssessmentPlan.model_validate_json(current_plan["plan_json"])
        run_record = store.create_run(scope, plan, profile=request.profile, manual_notes=request.manual_notes)
        store.set_assessment_state(AssessmentState.running.value)
        launch_worker(run_id=run_record["id"], include_approved_active=request.include_approved_active, resume=False)
        return _run_view(run_record, store)

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
        return _run_view(refreshed, store)

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

    def _perform_workspace_purge(request: WorkspacePurgeRequest) -> WorkspacePurgeResponse:
        nonlocal app_settings
        reset = WorkspaceReset(store=store, settings=app_settings)
        try:
            outcome = reset.purge_all(confirmation=request.confirmation)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        app_settings = replace(app_settings, ollama_model=backend_default_model)
        app.state.settings = app_settings
        return WorkspacePurgeResponse.model_validate(outcome)

    @app.post("/api/system/purge-all", response_model=WorkspacePurgeResponse)
    def purge_all(request: WorkspacePurgeRequest) -> WorkspacePurgeResponse:
        return _perform_workspace_purge(request)

    @app.post("/api/system/factory-reset", response_model=WorkspacePurgeResponse)
    def factory_reset(request: WorkspacePurgeRequest) -> WorkspacePurgeResponse:
        return _perform_workspace_purge(request)

    @app.post("/api/llm/planner", response_model=LLMPlannerResponse)
    async def llm_planner(request: LLMPlannerRequest) -> LLMPlannerResponse:
        run = store.get_run(request.run_id) if request.run_id else store.get_latest_run()
        scope = store.get_current_scope() if request.scope_id is None else store.get_scope(request.scope_id)
        if scope is None:
            raise HTTPException(status_code=404, detail="No scope is available.")
        if run is None and request.run_id is not None:
            raise HTTPException(status_code=404, detail="Run not found.")
        plan = _plan_view(run["plan"]) if run and run.get("plan") else _plan_view(store.get_current_plan(store.current_scope_id()))
        if plan is None:
            raise HTTPException(status_code=404, detail="No plan is available.")
        findings = run["findings"] if run else []
        tool_results = store.list_tool_results(run["id"]) if run else []
        correlation = store.correlate_tool_results(run["id"]) if run else {
            "run_id": None,
            "tool_ids": [],
            "service_inventory": [],
            "route_inventory": [],
            "tls_posture": [],
            "header_posture": [],
            "http_probe": [],
            "dns_visibility": [],
            "evidence_refs": [],
            "observations": [],
            "by_tool": {},
        }
        pending_actions = [action for action in (run["actions"] if run else []) if action["status"] == "pending-approval"]
        approved_actions = [action for action in (run["actions"] if run else []) if action["status"] == "approved"]
        completed_actions = [
            action
            for action in (run["actions"] if run else [])
            if action["status"] in {"executed", "skipped", "blocked"}
        ]
        evidence_artifacts = [artifact for artifact in (run["artifacts"] if run else []) if artifact["kind"] == "evidence"]
        remaining_actions = [
            action.model_dump(mode="json")
            for action in plan.actions
            if action.action_id not in {item["action_id"] for item in completed_actions}
        ]
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
            tool_results=tool_results,
            correlated_evidence=correlation,
            service_inventory=correlation.get("service_inventory", []),
            route_inventory=correlation.get("route_inventory", []),
            tls_posture=correlation.get("tls_posture", []),
            header_posture=correlation.get("header_posture", []),
            model_state={
                "selected_model": store.get_selected_ollama_model() or app_settings.ollama_model,
                "backend_default_model": app.state.backend_default_model,
                "source": "database" if store.get_selected_ollama_model() else "environment",
            },
            completed_actions=completed_actions,
            evidence_artifacts=evidence_artifacts,
            remaining_actions=remaining_actions,
            rate_limit_snapshot={"current_scope_id": store.current_scope_id()},
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
        return _frontend_index_response(app_settings)

    @app.get("/assets/{asset_path:path}")
    def serve_frontend_asset(asset_path: str) -> Response:
        return _frontend_asset_response(app_settings, asset_path)

    @app.get("/{path:path}")
    def serve_frontend(path: str) -> Response:
        if path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not found.")
        frontend_root = app_settings.paths.frontend_dist_dir.resolve()
        requested_file = (frontend_root / path).resolve()
        try:
            requested_file.relative_to(frontend_root)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="Frontend asset not found.") from exc
        if requested_file.exists() and requested_file.is_file():
            return FileResponse(requested_file)
        if path.startswith("assets/") or "." in Path(path).name:
            raise HTTPException(status_code=404, detail="Frontend asset not found.")
        return _frontend_index_response(app_settings)

    return app
