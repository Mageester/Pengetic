from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable
from uuid import uuid4

import httpx

from scopeguard.config import ProfileConfig, RuntimeProfile, resolve_profile
from scopeguard.evidence.audit import AuditLogger
from scopeguard.evidence.redaction import redact_sensitive_value
from scopeguard.evidence.store import EvidenceStore
from scopeguard.findings.models import Finding
from scopeguard.findings.normalize import normalize_findings
from scopeguard.policy.approvals import ApprovalRecord
from scopeguard.policy.gate import ApprovalGate, GateDecision
from scopeguard.policy.plan import AssessmentAction, AssessmentPlan, AssessmentPlanner
from scopeguard.policy.risk import RiskLevel
from scopeguard.reporting.markdown import render_report
from scopeguard.runtime import WorkspacePaths, build_run_dir, build_workspace
from scopeguard.scope.fingerprint import scope_fingerprint
from scopeguard.scope.models import ScopePackage
from scopeguard.tools.base import ExecutionContext, ToolResult
from scopeguard.tools.registry import ToolRegistry, default_tool_registry

from .state import AssessmentState


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class ActionOutcome:
    action: AssessmentAction
    decision: GateDecision
    status: str
    summary: str
    evidence_paths: list[str] = field(default_factory=list)
    result: ToolResult | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RunExecutionResult:
    run_id: str
    run_dir: Path
    scope_name: str
    scope_fingerprint: str
    profile: str
    plan: AssessmentPlan
    outcomes: list[ActionOutcome]
    findings: list[Finding]
    evidence_paths: list[str]
    report_path: Path
    report_text: str
    started_at: datetime
    finished_at: datetime
    state: AssessmentState
    pending_action_ids: list[str] = field(default_factory=list)
    notes: str | None = None
    report_generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(slots=True)
class ApprovalLookup:
    latest_for_action_fn: Callable[[str, str], ApprovalRecord | None]

    def latest_for_action(self, action_id: str, scope_fingerprint_value: str) -> ApprovalRecord | None:
        return self.latest_for_action_fn(action_id, scope_fingerprint_value)


EventSink = Callable[[dict[str, Any]], None]


class AssessmentRunCoordinator:
    def __init__(
        self,
        scope: ScopePackage,
        *,
        profile: str | RuntimeProfile | None = None,
        artifacts_root: Path | str = Path("artifacts"),
        registry: ToolRegistry | None = None,
        http_client: httpx.Client | None = None,
        manual_notes: str | None = None,
    ) -> None:
        self.scope = scope
        self.profile: ProfileConfig = resolve_profile(profile)
        self.registry = registry or default_tool_registry()
        self.workspace: WorkspacePaths = build_workspace(scope, artifacts_root)
        self.workspace.ensure()
        self.scope_fp = scope_fingerprint(scope)
        self.http_client = http_client or httpx.Client(
            follow_redirects=True,
            timeout=httpx.Timeout(10.0),
            headers={"User-Agent": "Pengetic/2.0"},
        )
        self._owns_http_client = http_client is None
        self.manual_notes = manual_notes

    def build_plan(self) -> AssessmentPlan:
        return AssessmentPlanner(self.registry).build(self.scope, self.profile.name)

    def build_run_dir(self, run_id: str) -> Path:
        return build_run_dir(self.workspace, run_id)

    def _execute_action(
        self,
        action: AssessmentAction,
        *,
        run_id: str,
        run_dir: Path,
        evidence_store: EvidenceStore,
        audit: AuditLogger,
        approvals: ApprovalLookup,
        include_approved_active: bool,
        gate: ApprovalGate,
        emit: EventSink | None,
    ) -> ActionOutcome:
        context = ExecutionContext(
            scope=self.scope,
            scope_fingerprint=self.scope_fp,
            run_id=run_id,
            run_dir=run_dir,
            evidence_store=evidence_store,
            audit_logger=audit,
            http_client=self.http_client,
            manual_notes=self.manual_notes,
        )
        decision = gate.evaluate(
            action_id=action.action_id,
            risk=action.classification,
            scope_fingerprint=self.scope_fp,
            approvals=approvals,
        )
        if emit is not None:
            emit(
                "decision",
                decision.reason,
                action=action,
                payload={
                    "approved": decision.approved,
                    "auto_approved": decision.auto_approved,
                    "reason": decision.reason,
                    "classification": action.classification.value,
                },
            )

        if action.classification == RiskLevel.forbidden:
            outcome = ActionOutcome(
                action=action,
                decision=decision,
                status="blocked",
                summary="Blocked by policy.",
                details={"reason": decision.reason},
            )
            if emit is not None:
                emit("blocked", "Action blocked by policy.", level="warning", action=action, payload={"reason": decision.reason})
            return outcome

        if not action.allowed_by_scope:
            outcome = ActionOutcome(
                action=action,
                decision=decision,
                status="skipped",
                summary="Tool is not present in the scope allowlist.",
                details={"reason": "Tool allowlist blocked execution."},
            )
            if emit is not None:
                emit("skipped", "Action skipped because the tool is out of scope.", level="warning", action=action)
            return outcome

        if action.classification != RiskLevel.passive_safe and not (include_approved_active and decision.approved):
            outcome = ActionOutcome(
                action=action,
                decision=decision,
                status="pending-approval" if not decision.approved else "skipped",
                summary=decision.reason,
                details={"reason": decision.reason},
            )
            if emit is not None:
                emit(
                    "pending",
                    "Action is waiting on approval.",
                    level="warning",
                    action=action,
                    payload={"reason": decision.reason},
                )
            return outcome

        if action.classification == RiskLevel.passive_safe and not self.profile.run_passive:
            outcome = ActionOutcome(
                action=action,
                decision=decision,
                status="skipped",
                summary="Passive execution disabled by profile.",
                details={"reason": "Profile suppressed passive execution."},
            )
            if emit is not None:
                emit("skipped", "Passive execution disabled by profile.", level="warning", action=action)
            return outcome

        tool = self.registry.get(action.tool_id)
        if emit is not None:
            emit("execution_start", f"Executing {tool.title}.", action=action)
        result = tool.executor(action, context)
        normalized_findings = normalize_findings(result.findings, source_action_id=action.action_id)
        audit.log(
            "execution",
            run_id=run_id,
            action_id=action.action_id,
            tool_id=action.tool_id,
            classification=action.classification.value,
            status="executed",
            summary=result.summary,
            evidence_paths=result.evidence_paths,
            findings=[finding.model_dump(mode="json") for finding in normalized_findings],
        )
        if emit is not None:
            emit(
                "execution_complete",
                result.summary,
                action=action,
                payload={
                    "summary": result.summary,
                    "evidence_paths": result.evidence_paths,
                    "findings": [finding.model_dump(mode="json") for finding in normalized_findings],
                },
            )
        return ActionOutcome(
            action=action,
            decision=decision,
            status="executed",
            summary=result.summary,
            evidence_paths=result.evidence_paths,
            result=result,
            started_at=datetime.fromisoformat(result.started_at.replace("Z", "+00:00")),
            finished_at=datetime.fromisoformat(result.finished_at.replace("Z", "+00:00")),
            details=result.details,
        )

    def execute_action(
        self,
        action: AssessmentAction,
        *,
        run_id: str,
        run_dir: Path,
        approvals: ApprovalLookup,
        include_approved_active: bool = True,
        event_sink: EventSink | None = None,
    ) -> ActionOutcome:
        run_dir.mkdir(parents=True, exist_ok=True)
        evidence_store = EvidenceStore(run_dir / "evidence")
        audit = AuditLogger(run_dir / "audit.jsonl")
        gate = ApprovalGate()
        try:
            return self._execute_action(
                action,
                run_id=run_id,
                run_dir=run_dir,
                evidence_store=evidence_store,
                audit=audit,
                approvals=approvals,
                include_approved_active=include_approved_active,
                gate=gate,
                emit=event_sink,
            )
        finally:
            if self._owns_http_client:
                self.http_client.close()

    def execute(
        self,
        plan: AssessmentPlan,
        *,
        run_id: str,
        run_dir: Path,
        approvals: ApprovalLookup,
        include_approved_active: bool = False,
        action_ids: set[str] | None = None,
        stop_on_pending_active: bool = False,
        event_sink: EventSink | None = None,
        resume: bool = False,
    ) -> RunExecutionResult:
        run_dir.mkdir(parents=True, exist_ok=True)
        evidence_store = EvidenceStore(run_dir / "evidence")
        audit = AuditLogger(run_dir / "audit.jsonl")
        gate = ApprovalGate()
        outcomes: list[ActionOutcome] = []
        findings: list[Finding] = []
        evidence_paths: list[str] = []
        started_at = datetime.now(UTC)
        pending_action_ids: list[str] = []

        def emit(
            event_type: str,
            message: str,
            *,
            level: str = "info",
            action: AssessmentAction | None = None,
            payload: dict[str, Any] | None = None,
        ) -> None:
            record = redact_sensitive_value(
                {
                    "timestamp": _now(),
                    "type": event_type,
                    "run_id": run_id,
                    "message": message,
                    "level": level,
                    "action_id": action.action_id if action else None,
                    "tool_id": action.tool_id if action else None,
                    "payload": payload or {},
                }
            )
            audit.log(
                event_type,
                run_id=run_id,
                message=message,
                level=level,
                action_id=action.action_id if action else None,
                tool_id=action.tool_id if action else None,
                payload=payload or {},
            )
            if event_sink is not None:
                event_sink(record)

        try:
            emit("run_start", "Run started." if not resume else "Run resumed.", payload={"profile": self.profile.name.value})

            selected_actions = [action for action in plan.actions if action_ids is None or action.action_id in action_ids]
            for index, action in enumerate(selected_actions):
                outcome = self._execute_action(
                    action,
                    run_id=run_id,
                    run_dir=run_dir,
                    evidence_store=evidence_store,
                    audit=audit,
                    approvals=approvals,
                    include_approved_active=include_approved_active,
                    gate=gate,
                    emit=emit,
                )
                outcomes.append(outcome)
                if outcome.result is not None:
                    evidence_paths.extend(outcome.result.evidence_paths)
                    normalized_findings = normalize_findings(outcome.result.findings, source_action_id=action.action_id)
                    findings.extend(normalized_findings)
                else:
                    normalized_findings = []
                if outcome.status == "pending-approval":
                    pending_action_ids.append(action.action_id)
                    if stop_on_pending_active:
                        for remaining in selected_actions[index + 1 :]:
                            if remaining.classification != RiskLevel.passive_safe:
                                pending_action_ids.append(remaining.action_id)
                        break

            finished_at = datetime.now(UTC)
            report_path = run_dir / "report.md"
            pending_action_ids = list(dict.fromkeys(pending_action_ids))
            state = AssessmentState.completed if not pending_action_ids else AssessmentState.awaiting_approval

            run_summary = RunExecutionResult(
                run_id=run_id,
                run_dir=run_dir,
                scope_name=self.scope.name,
                scope_fingerprint=self.scope_fp,
                profile=self.profile.name.value,
                plan=plan,
                outcomes=outcomes,
                findings=findings,
                evidence_paths=sorted(set(evidence_paths)),
                report_path=report_path,
                report_text="",
                started_at=started_at,
                finished_at=finished_at,
                state=state,
                pending_action_ids=pending_action_ids,
                notes=self.manual_notes,
            )
            report_text = render_report(self.scope, plan, run_summary)
            report_path.write_text(report_text, encoding="utf-8")
            run_summary.report_text = report_text
            audit.log(
                "run_complete" if state == AssessmentState.completed else "run_paused",
                run_id=run_id,
                report_path=str(report_path),
                findings=len(findings),
                outcomes=len(outcomes),
                pending_action_ids=pending_action_ids,
                state=state.value,
            )
            return run_summary
        finally:
            if self._owns_http_client:
                self.http_client.close()
