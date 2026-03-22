from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
import json
from typing import Any
from uuid import uuid4

import httpx

from .config import ProfileConfig, RuntimeProfile, resolve_profile
from .evidence.audit import AuditLogger
from .evidence.store import EvidenceStore
from .findings.models import Finding
from .findings.normalize import normalize_findings
from .policy.approvals import ApprovalStore
from .policy.gate import ApprovalGate, GateDecision
from .policy.plan import AssessmentAction, AssessmentPlan, AssessmentPlanner
from .policy.risk import RiskLevel
from .reporting.markdown import render_report
from .runtime import WorkspacePaths, build_run_dir, build_workspace
from .scope.fingerprint import scope_fingerprint
from .scope.models import ScopePackage
from .tools.base import ExecutionContext, ToolResult
from .tools.registry import ToolRegistry, default_tool_registry


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
class RunSummary:
    run_id: str
    started_at: datetime
    finished_at: datetime
    profile: str
    scope_name: str
    scope_fingerprint: str
    run_dir: Path
    report_path: Path
    outcomes: list[ActionOutcome] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    evidence_paths: list[str] = field(default_factory=list)
    report_generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class AssessmentEngine:
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
        self.approvals = ApprovalStore(self.workspace.approvals_path)
        self.planner = AssessmentPlanner(self.registry)
        self.http_client = http_client or httpx.Client(
            follow_redirects=True,
            timeout=httpx.Timeout(10.0),
            headers={"User-Agent": "ScopeGuard/0.1"},
        )
        self._owns_http_client = http_client is None
        self.manual_notes = manual_notes

    def build_plan(self) -> AssessmentPlan:
        plan = self.planner.build(self.scope, self.profile.name)
        self.workspace.plan_path.write_text(
            json.dumps(plan.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        self.workspace.scope_snapshot_path.write_text(
            json.dumps(self.scope.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return plan

    def run(self, *, include_approved_active: bool | None = None) -> RunSummary:
        plan = self.build_plan()
        include_active = (
            self.profile.include_approved_active if include_approved_active is None else include_approved_active
        )
        run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
        run_dir = build_run_dir(self.workspace, run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        evidence_store = EvidenceStore(run_dir / "evidence")
        audit = AuditLogger(run_dir / "audit.jsonl")
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
        gate = ApprovalGate()
        outcomes: list[ActionOutcome] = []
        findings: list[Finding] = []
        evidence_paths: list[str] = []
        started_at = datetime.now(UTC)

        audit.log(
            "run_start",
            run_id=run_id,
            profile=self.profile.name.value,
            scope_name=self.scope.name,
            scope_fingerprint=self.scope_fp,
            assessment_dir=str(self.workspace.assessment_dir),
        )

        for action in plan.actions:
            decision = gate.evaluate(
                action_id=action.action_id,
                risk=action.classification,
                scope_fingerprint=self.scope_fp,
                approvals=self.approvals,
            )
            audit.log(
                "decision",
                run_id=run_id,
                action_id=action.action_id,
                tool_id=action.tool_id,
                classification=action.classification.value,
                approved=decision.approved,
                auto_approved=decision.auto_approved,
                reason=decision.reason,
            )

            if action.classification == RiskLevel.forbidden:
                outcomes.append(
                    ActionOutcome(
                        action=action,
                        decision=decision,
                        status="blocked",
                        summary="Blocked by policy.",
                        details={"reason": decision.reason},
                    )
                )
                continue

            if not action.allowed_by_scope:
                outcomes.append(
                    ActionOutcome(
                        action=action,
                        decision=decision,
                        status="skipped",
                        summary="Tool is not present in the scope allowlist.",
                        details={"reason": "Tool allowlist blocked execution."},
                    )
                )
                continue

            if action.classification != RiskLevel.passive_safe and not (include_active and decision.approved):
                status = "pending-approval" if not decision.approved else "skipped"
                outcomes.append(
                    ActionOutcome(
                        action=action,
                        decision=decision,
                        status=status,
                        summary=decision.reason,
                        details={"reason": decision.reason},
                    )
                )
                continue

            if action.classification == RiskLevel.passive_safe and not self.profile.run_passive:
                outcomes.append(
                    ActionOutcome(
                        action=action,
                        decision=decision,
                        status="skipped",
                        summary="Passive execution disabled by profile.",
                        details={"reason": "Profile suppressed passive execution."},
                    )
                )
                continue

            tool = self.registry.get(action.tool_id)
            result = tool.executor(action, context)
            evidence_paths.extend(result.evidence_paths)
            normalized_findings = normalize_findings(result.findings, source_action_id=action.action_id)
            findings.extend(normalized_findings)
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
            outcomes.append(
                ActionOutcome(
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
            )

        finished_at = datetime.now(UTC)
        report_path = run_dir / "report.md"
        summary = RunSummary(
            run_id=run_id,
            started_at=started_at,
            finished_at=finished_at,
            profile=self.profile.name.value,
            scope_name=self.scope.name,
            scope_fingerprint=self.scope_fp,
            run_dir=run_dir,
            report_path=report_path,
            outcomes=outcomes,
            findings=findings,
            evidence_paths=sorted(set(evidence_paths)),
        )
        report_path.write_text(render_report(self.scope, plan, summary), encoding="utf-8")
        audit.log(
            "run_complete",
            run_id=run_id,
            report_path=str(report_path),
            findings=len(findings),
            outcomes=len(outcomes),
        )
        if self._owns_http_client:
            self.http_client.close()
        return summary

    def save_report(self, run_summary: RunSummary) -> Path:
        plan = AssessmentPlan.model_validate_json(self.workspace.plan_path.read_text(encoding="utf-8"))
        report_path = run_summary.report_path
        report_path.write_text(render_report(self.scope, plan, run_summary), encoding="utf-8")
        return report_path


def load_latest_run(workspace: WorkspacePaths, run_id: str | None = None) -> Path:
    runs_root = workspace.runs_dir
    if run_id is not None:
        candidate = runs_root / run_id
        if not candidate.exists():
            raise FileNotFoundError(candidate)
        return candidate
    if not runs_root.exists():
        raise FileNotFoundError("No runs have been recorded yet.")
    candidates = [child for child in runs_root.iterdir() if child.is_dir()]
    if not candidates:
        raise FileNotFoundError("No runs have been recorded yet.")
    return sorted(candidates)[-1]

