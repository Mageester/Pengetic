from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any, Callable
import json

import anyio
import httpx

from scopeguard.policy.approvals import ApprovalRecord
from scopeguard.policy.risk import RISK_ORDER, RiskLevel
from scopeguard.policy.plan import AssessmentAction
from scopeguard.scope.models import ScopePackage
from scopeguard.findings.normalize import normalize_findings

from .execution import (
    build_run_summary_json,
    persist_action_outcome,
    render_and_store_report,
)
from .llm import OllamaPlannerService, PlannerContext
from .orchestrator import AssessmentRunCoordinator, ApprovalLookup
from .schemas import OrchestratorDecisionView, OrchestratorRunResponse, RunView
from .settings import AppSettings
from .state import AssessmentState
from .storage import PengeticStore


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _allow_passive(profile_name: str) -> bool:
    return profile_name != "report-only"


def _remaining_action_records(actions: list[dict[str, Any]], *, allow_passive: bool) -> list[dict[str, Any]]:
    remaining: list[dict[str, Any]] = []
    for action in actions:
        if action["allowed_by_scope"] is False:
            continue
        if action["status"] in {"executed", "skipped", "blocked"}:
            continue
        if action["classification"] == RiskLevel.passive_safe.value:
            if allow_passive:
                remaining.append(action)
            continue
        remaining.append(action)
    return remaining


@dataclass(slots=True)
class OrchestratorSnapshot:
    run: dict[str, Any]
    scope: dict[str, Any]
    plan: dict[str, Any]
    actions: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    artifacts: list[dict[str, Any]]
    steps: list[dict[str, Any]]
    pending_actions: list[dict[str, Any]]
    approved_actions: list[dict[str, Any]]
    completed_actions: list[dict[str, Any]]
    remaining_actions: list[dict[str, Any]]
    evidence_artifacts: list[dict[str, Any]]
    rate_limit_snapshot: dict[str, Any]


@dataclass(slots=True)
class AssessmentOrchestratorService:
    store: PengeticStore
    settings: AppSettings
    registry: Any = None
    planner_service: OllamaPlannerService | None = None

    def _coordinator(self, scope: ScopePackage, *, profile: str, http_client: httpx.Client | None = None) -> AssessmentRunCoordinator:
        return AssessmentRunCoordinator(
            scope,
            profile=profile,
            artifacts_root=self.settings.paths.artifacts_dir,
            registry=self.registry,
            http_client=http_client,
        )

    def _planner(self) -> OllamaPlannerService:
        return self.planner_service or OllamaPlannerService(
            base_url=self.settings.ollama_base_url,
            model=self.settings.ollama_model,
        )

    def _approval_lookup(self, run_id: str) -> ApprovalLookup:
        def lookup(action_id: str, scope_fingerprint_value: str) -> ApprovalRecord | None:
            for approval in reversed(self.store.list_approvals(run_id)):
                if approval["action_id"] != action_id or approval["scope_fingerprint"] != scope_fingerprint_value:
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

    def _snapshot(self, run_id: str) -> OrchestratorSnapshot:
        run = self.store.get_run(run_id)
        if run is None:
            raise ValueError(f"Run {run_id} not found.")
        scope = self.store.get_scope(run["scope_id"])
        if scope is None:
            raise ValueError(f"Scope {run['scope_id']} not found.")
        plan = self.store.get_plan(run["plan_id"]) if run.get("plan_id") else self.store.get_current_plan()
        if plan is None:
            raise ValueError(f"Plan for run {run_id} not found.")

        allow_passive = _allow_passive(run["profile"])
        actions = run["actions"]
        findings = run["findings"]
        artifacts = run["artifacts"]
        steps = self.store.list_orchestrator_steps(run_id)
        pending_actions = [
            action
            for action in actions
            if action["classification"] != RiskLevel.passive_safe.value and action["status"] in {"queued", "pending-approval"}
        ]
        approved_actions = [action for action in actions if action["status"] == "approved"]
        completed_actions = [action for action in actions if action["status"] in {"executed", "skipped", "blocked"}]
        remaining_actions = _remaining_action_records(actions, allow_passive=allow_passive)
        evidence_artifacts = [artifact for artifact in artifacts if artifact["kind"] == "evidence"]

        scope_json = scope.get("scope_json") or {}
        rate_limits = scope_json.get("rate_limits") or {}
        recent_executions = [
            action
            for action in actions
            if action["status"] == "executed" and _parse_iso(action["finished_at"]) is not None
        ]
        last_finished = max(
            (_parse_iso(action["finished_at"]) for action in recent_executions if _parse_iso(action["finished_at"]) is not None),
            default=None,
        )
        window_start = datetime.now(UTC) - timedelta(minutes=1)
        executions_last_minute = [
            action
            for action in recent_executions
            if (finished := _parse_iso(action["finished_at"])) is not None and finished >= window_start
        ]
        rate_limit_snapshot = {
            "max_requests_per_minute": rate_limits.get("max_requests_per_minute"),
            "max_concurrent_requests": rate_limits.get("max_concurrent_requests"),
            "delay_seconds_between_requests": rate_limits.get("delay_seconds_between_requests"),
            "recent_executions_last_minute": len(executions_last_minute),
            "last_execution_finished_at": last_finished.isoformat().replace("+00:00", "Z") if last_finished else None,
            "seconds_since_last_execution": (
                (datetime.now(UTC) - last_finished).total_seconds() if last_finished is not None else None
            ),
        }
        return OrchestratorSnapshot(
            run=run,
            scope=scope,
            plan=plan,
            actions=actions,
            findings=findings,
            artifacts=artifacts,
            steps=steps,
            pending_actions=pending_actions,
            approved_actions=approved_actions,
            completed_actions=completed_actions,
            remaining_actions=remaining_actions,
            evidence_artifacts=evidence_artifacts,
            rate_limit_snapshot=rate_limit_snapshot,
        )

    def _remaining_action_ids(self, snapshot: OrchestratorSnapshot) -> list[str]:
        return [action["action_id"] for action in snapshot.remaining_actions]

    def _completed_action_ids(self, snapshot: OrchestratorSnapshot) -> list[str]:
        return [action["action_id"] for action in snapshot.completed_actions]

    def _select_action(
        self,
        snapshot: OrchestratorSnapshot,
        suggestion: Any,
    ) -> tuple[dict[str, Any] | None, str]:
        remaining = {action["action_id"]: action for action in snapshot.remaining_actions}
        if suggestion.recommended_action_id:
            candidate = remaining.get(suggestion.recommended_action_id)
            if candidate is not None:
                return candidate, "planner_recommendation"

        passive = [action for action in snapshot.remaining_actions if action["classification"] == RiskLevel.passive_safe.value]
        if passive:
            return passive[0], "passive_fallback"

        approved = [action for action in snapshot.remaining_actions if action["status"] == "approved"]
        if approved:
            approved.sort(key=lambda item: RISK_ORDER[RiskLevel(item["classification"])])
            return approved[0], "approved_fallback"

        queued = [action for action in snapshot.remaining_actions if action["status"] in {"queued", "pending-approval"}]
        if queued:
            queued.sort(key=lambda item: RISK_ORDER[RiskLevel(item["classification"])])
            return queued[0], "queued_fallback"

        return None, "no_useful_actions"

    def _rate_limit_blocked(self, snapshot: OrchestratorSnapshot) -> str | None:
        limits = snapshot.rate_limit_snapshot
        max_per_minute = limits.get("max_requests_per_minute")
        if max_per_minute is not None and limits.get("recent_executions_last_minute", 0) >= max_per_minute:
            return "rate_limit_per_minute_reached"
        delay_seconds = limits.get("delay_seconds_between_requests")
        seconds_since_last = limits.get("seconds_since_last_execution")
        if delay_seconds is not None and seconds_since_last is not None and seconds_since_last < float(delay_seconds):
            return "delay_between_requests_not_met"
        return None

    def _decision_view(
        self,
        *,
        run_id: str,
        step_index: int,
        planner_model: str,
        planner_source: str,
        state_before: str,
        state_after: str,
        suggestion: Any,
        selected_action: dict[str, Any] | None,
        status: str,
        stop_reason: str,
        result: dict[str, Any] | None,
        snapshot: OrchestratorSnapshot,
        decision_id: int | None = None,
        created_at: str | None = None,
    ) -> OrchestratorDecisionView:
        return OrchestratorDecisionView.model_validate(
            {
                "id": decision_id,
                "run_id": run_id,
                "step_index": step_index,
                "planner_model": planner_model,
                "planner_source": planner_source,
                "state_before": state_before,
                "state_after": state_after,
                "selected_action_id": selected_action["action_id"] if selected_action else None,
                "selected_tool_id": selected_action["tool_id"] if selected_action else None,
                "selected_risk": selected_action["classification"] if selected_action else None,
                "status": status,
                "stop_reason": stop_reason,
                "summary": suggestion.summary,
                "next_allowed_step": suggestion.next_allowed_step,
                "recommended_action_id": suggestion.recommended_action_id,
                "rationale": suggestion.rationale,
                "confidence": suggestion.confidence,
                "approval_required": bool(selected_action and selected_action["classification"] != RiskLevel.passive_safe.value),
                "approved": bool((result is not None and result.get("status") == "executed") or (selected_action and selected_action["status"] == "approved")),
                "auto_approved": bool(selected_action and selected_action["classification"] == RiskLevel.passive_safe.value),
                "executed": bool(result is not None and result.get("status") == "executed"),
                "remaining_action_ids": self._remaining_action_ids(snapshot),
                "completed_action_ids": self._completed_action_ids(snapshot),
                "findings_count": len(snapshot.findings),
                "evidence_paths": sorted({artifact["path"] for artifact in snapshot.evidence_artifacts}),
                "result": result,
                "raw": suggestion.raw,
                "created_at": created_at,
                "updated_at": created_at,
            }
        )

    async def run_assessment(
        self,
        run_id: str,
        *,
        max_steps: int = 10,
        model: str | None = None,
        event_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> OrchestratorRunResponse:
        run = self.store.get_run(run_id)
        if run is None:
            raise ValueError(f"Run {run_id} not found.")
        scope_row = self.store.get_scope(run["scope_id"])
        if scope_row is None:
            raise ValueError(f"Scope {run['scope_id']} not found.")
        scope = ScopePackage.model_validate(scope_row["scope_json"])
        run_dir = self.settings.paths.runs_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        planner = self._planner()
        approvals = self._approval_lookup(run_id)
        http_client = httpx.Client(
            follow_redirects=True,
            timeout=httpx.Timeout(10.0),
            headers={"User-Agent": "Pengetic/2.0"},
        )
        coordinator = self._coordinator(scope, profile=run["profile"], http_client=http_client)
        decisions: list[OrchestratorDecisionView] = []
        step_index = len(self.store.list_orchestrator_steps(run_id))
        stop_reason = "no_useful_actions"
        final_state = run["state"]
        last_snapshot = self._snapshot(run_id)
        stopped = False

        try:
            for _ in range(max_steps):
                snapshot = self._snapshot(run_id)
                last_snapshot = snapshot
                current_run = snapshot.run
                active_model = model or self.settings.ollama_model
                context = PlannerContext(
                    scope_name=snapshot.scope["name"],
                    scope_id=snapshot.scope["id"],
                    run_id=run_id,
                    state=current_run["state"],
                    profile=current_run["profile"],
                    findings=snapshot.findings,
                    pending_actions=snapshot.pending_actions,
                    approved_actions=snapshot.approved_actions,
                    plan_actions=current_run["plan"]["actions"] if current_run.get("plan") else [],
                    completed_actions=snapshot.completed_actions,
                    evidence_artifacts=snapshot.evidence_artifacts,
                    remaining_actions=snapshot.remaining_actions,
                    rate_limit_snapshot=snapshot.rate_limit_snapshot,
                    latest_run_summary=json.dumps(current_run.get("summary_json") or {}, ensure_ascii=False, default=str),
                )
                suggestion = await planner.suggest(context, model=active_model)
                selected_action, selection_source = self._select_action(snapshot, suggestion)
                rate_limit_block = self._rate_limit_blocked(snapshot)

                if selected_action is None:
                    final_state = AssessmentState.completed.value if not snapshot.pending_actions else AssessmentState.awaiting_approval.value
                    stop_reason = "no_useful_actions"
                    decision = self._decision_view(
                        run_id=run_id,
                        step_index=step_index,
                        planner_model=suggestion.model,
                        planner_source=suggestion.source,
                        state_before=current_run["state"],
                        state_after=final_state,
                        suggestion=suggestion,
                        selected_action=None,
                        status="stopped",
                        stop_reason=stop_reason,
                        result=None,
                        snapshot=snapshot,
                    )
                    stored = self.store.add_orchestrator_step(
                        run_id=run_id,
                        step_index=step_index,
                        planner_model=suggestion.model,
                        planner_source=suggestion.source,
                        state_before=current_run["state"],
                        state_after=final_state,
                        selected_action_id=None,
                        selected_tool_id=None,
                        selected_risk=None,
                        status="stopped",
                        stop_reason=stop_reason,
                        decision_json=decision.model_dump(mode="json"),
                        result_json=None,
                    )
                    decisions.append(
                        decision.model_copy(update={"id": stored["id"], "created_at": stored["created_at"], "updated_at": stored["updated_at"]})
                    )
                    current_summary = build_run_summary_json(
                        self.store,
                        run_id,
                        state=final_state,
                        pending_action_ids=[item["action_id"] for item in snapshot.pending_actions],
                    )
                    render_and_store_report(
                        self.store,
                        snapshot.scope,
                        snapshot.plan,
                        run_id,
                        run_dir,
                        state=final_state,
                        summary_json=current_summary,
                        record_artifact=True,
                    )
                    stopped = True
                    break

                if rate_limit_block is not None:
                    final_state = AssessmentState.running.value
                    stop_reason = rate_limit_block
                    decision = self._decision_view(
                        run_id=run_id,
                        step_index=step_index,
                        planner_model=suggestion.model,
                        planner_source=suggestion.source,
                        state_before=current_run["state"],
                        state_after=final_state,
                        suggestion=suggestion,
                        selected_action=selected_action,
                        status="stopped",
                        stop_reason=stop_reason,
                        result=None,
                        snapshot=snapshot,
                    )
                    stored = self.store.add_orchestrator_step(
                        run_id=run_id,
                        step_index=step_index,
                        planner_model=suggestion.model,
                        planner_source=suggestion.source,
                        state_before=current_run["state"],
                        state_after=final_state,
                        selected_action_id=selected_action["action_id"],
                        selected_tool_id=selected_action["tool_id"],
                        selected_risk=selected_action["classification"],
                        status="stopped",
                        stop_reason=stop_reason,
                        decision_json=decision.model_dump(mode="json"),
                        result_json=None,
                    )
                    decisions.append(
                        decision.model_copy(update={"id": stored["id"], "created_at": stored["created_at"], "updated_at": stored["updated_at"]})
                    )
                    current_summary = build_run_summary_json(
                        self.store,
                        run_id,
                        state=final_state,
                        pending_action_ids=[item["action_id"] for item in snapshot.pending_actions],
                    )
                    render_and_store_report(
                        self.store,
                        snapshot.scope,
                        snapshot.plan,
                        run_id,
                        run_dir,
                        state=final_state,
                        summary_json=current_summary,
                        record_artifact=False,
                    )
                    stopped = True
                    break

                action_model = AssessmentAction.model_validate(
                    {
                        "action_id": selected_action["action_id"],
                        "title": selected_action["title"],
                        "objective": selected_action["objective"],
                        "target": selected_action["target"],
                        "tool_id": selected_action["tool_id"],
                        "classification": selected_action["classification"],
                        "expected_evidence": selected_action["expected_evidence"],
                        "approval_required": selected_action["approval_required"],
                        "allowed_by_scope": selected_action["allowed_by_scope"],
                        "notes": selected_action["notes"],
                    }
                )
                if event_sink is not None:
                    event_sink(
                        {
                            "type": "orchestrator_step_selected",
                            "message": f"Selected {action_model.action_id} via {selection_source}.",
                            "level": "info",
                            "action_id": action_model.action_id,
                            "tool_id": action_model.tool_id,
                            "payload": {
                                "selection_source": selection_source,
                                "planner_model": suggestion.model,
                                "planner_source": suggestion.source,
                            },
                        }
                    )

                outcome = await anyio.to_thread.run_sync(
                    partial(
                        coordinator.execute_action,
                        action_model,
                        run_id=run_id,
                        run_dir=run_dir,
                        approvals=approvals,
                        include_approved_active=True,
                        event_sink=event_sink,
                    )
                )
                normalized_findings = (
                    normalize_findings(outcome.result.findings, source_action_id=action_model.action_id)
                    if outcome.result is not None
                    else []
                )
                persist_action_outcome(
                    self.store,
                    run_id,
                    outcome,
                    normalized_findings=normalized_findings,
                )

                refreshed = self._snapshot(run_id)
                more_useful_actions = [
                    item for item in refreshed.remaining_actions if item["action_id"] != action_model.action_id
                ]

                if outcome.status == "pending-approval":
                    final_state = AssessmentState.awaiting_approval.value
                    stop_reason = "approval_required"
                elif not more_useful_actions:
                    final_state = AssessmentState.completed.value
                    stop_reason = "no_useful_actions"
                else:
                    final_state = AssessmentState.running.value
                    stop_reason = "step_completed"

                decision = self._decision_view(
                    run_id=run_id,
                    step_index=step_index,
                    planner_model=suggestion.model,
                    planner_source=suggestion.source,
                    state_before=current_run["state"],
                    state_after=final_state,
                    suggestion=suggestion,
                    selected_action=selected_action,
                    status=outcome.status,
                    stop_reason=stop_reason,
                    result=asdict(outcome.result) if outcome.result is not None else None,
                    snapshot=refreshed,
                )
                stored = self.store.add_orchestrator_step(
                    run_id=run_id,
                    step_index=step_index,
                    planner_model=suggestion.model,
                    planner_source=suggestion.source,
                    state_before=current_run["state"],
                    state_after=final_state,
                    selected_action_id=selected_action["action_id"],
                    selected_tool_id=selected_action["tool_id"],
                    selected_risk=selected_action["classification"],
                    status=outcome.status,
                    stop_reason=stop_reason,
                    decision_json=decision.model_dump(mode="json"),
                    result_json=asdict(outcome.result) if outcome.result is not None else None,
                )
                decisions.append(
                    decision.model_copy(update={"id": stored["id"], "created_at": stored["created_at"], "updated_at": stored["updated_at"]})
                )
                step_index += 1

                current_summary = build_run_summary_json(
                    self.store,
                    run_id,
                    state=final_state,
                    pending_action_ids=[item["action_id"] for item in refreshed.pending_actions],
                )
                render_and_store_report(
                    self.store,
                    refreshed.scope,
                    refreshed.plan,
                    run_id,
                    run_dir,
                    state=final_state,
                    summary_json=current_summary,
                    record_artifact=(final_state != AssessmentState.running.value),
                )

                if outcome.status == "pending-approval" or final_state == AssessmentState.completed.value:
                    stopped = True
                    break

            if not stopped:
                final_snapshot = self._snapshot(run_id)
                useful_remaining = final_snapshot.remaining_actions
                if useful_remaining:
                    final_state = AssessmentState.running.value
                    stop_reason = "max_steps_reached"
                else:
                    final_state = AssessmentState.completed.value if not final_snapshot.pending_actions else AssessmentState.awaiting_approval.value
                    stop_reason = "max_steps_reached"
                decision = self._decision_view(
                    run_id=run_id,
                    step_index=step_index,
                    planner_model=self.settings.ollama_model,
                    planner_source="pengetic-orchestrator",
                    state_before=final_snapshot.run["state"],
                    state_after=final_state,
                    suggestion=type("Suggestion", (), {
                        "summary": "Maximum orchestrator steps reached.",
                        "next_allowed_step": "Resume orchestration when more work is allowed.",
                        "recommended_action_id": None,
                        "rationale": "The orchestrator loop hit the configured step cap.",
                        "confidence": "medium",
                        "model": self.settings.ollama_model,
                        "source": "pengetic-orchestrator",
                        "raw": {"max_steps_reached": True},
                    })(),
                    selected_action=None,
                    status="stopped",
                    stop_reason=stop_reason,
                    result=None,
                    snapshot=final_snapshot,
                )
                stored = self.store.add_orchestrator_step(
                    run_id=run_id,
                    step_index=step_index,
                    planner_model=self.settings.ollama_model,
                    planner_source="pengetic-orchestrator",
                    state_before=final_snapshot.run["state"],
                    state_after=final_state,
                    selected_action_id=None,
                    selected_tool_id=None,
                    selected_risk=None,
                    status="stopped",
                    stop_reason=stop_reason,
                    decision_json=decision.model_dump(mode="json"),
                    result_json=None,
                )
                decisions.append(
                    decision.model_copy(update={"id": stored["id"], "created_at": stored["created_at"], "updated_at": stored["updated_at"]})
                )
                current_summary = build_run_summary_json(
                    self.store,
                    run_id,
                    state=final_state,
                    pending_action_ids=[item["action_id"] for item in final_snapshot.pending_actions],
                )
                render_and_store_report(
                    self.store,
                    final_snapshot.scope,
                    final_snapshot.plan,
                    run_id,
                    run_dir,
                    state=final_state,
                    summary_json=current_summary,
                    record_artifact=(final_state != AssessmentState.running.value),
                )

            updated_run = self.store.get_run(run_id)
            if updated_run is None:
                raise ValueError(f"Run {run_id} not found after orchestration.")
            if stop_reason == "approval_required":
                self.store.update_run(
                    run_id,
                    state=AssessmentState.awaiting_approval.value,
                )
                updated_run = self.store.get_run(run_id)
                if updated_run is None:
                    raise ValueError(f"Run {run_id} not found after approval state update.")
            persisted_state = updated_run["state"]
            run_payload = {
                "id": updated_run["id"],
                "scope_id": updated_run["scope_id"],
                "scope_name": updated_run["scope_name"],
                "scope_fingerprint": updated_run["scope_fingerprint"],
                "profile": updated_run["profile"],
                "state": updated_run["state"],
                "status": updated_run["status"],
                "started_at": updated_run["started_at"],
                "finished_at": updated_run["finished_at"],
                "created_at": updated_run["created_at"],
                "updated_at": updated_run["updated_at"],
                "report_path": updated_run["report_path"],
                "report_text": updated_run["report_text"],
                "manual_notes": updated_run["manual_notes"],
                "plan_id": updated_run["plan_id"],
                "plan": None,
                "actions": updated_run["actions"],
                "findings": updated_run["findings"],
                "artifacts": updated_run["artifacts"],
                "approvals": updated_run["approvals"],
                "events": updated_run["events"],
            }
            if updated_run.get("plan") is not None:
                plan = updated_run["plan"]
                run_payload["plan"] = {
                    "id": plan["id"],
                    "scope_id": plan["scope_id"],
                    "scope_name": plan["scope_name"],
                    "scope_fingerprint": plan["scope_fingerprint"],
                    "profile": plan["profile"],
                    "generated_at": plan["generated_at"],
                    "actions": plan["actions"],
                }
            return OrchestratorRunResponse(
                run_id=run_id,
                scope_id=updated_run["scope_id"],
                scope_name=updated_run["scope_name"],
                state=persisted_state,
                completed=persisted_state == AssessmentState.completed.value,
                stop_reason=stop_reason,
                steps=decisions,
                run=RunView.model_validate(run_payload),
            )
        finally:
            http_client.close()
