from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from scopeguard.findings.normalize import normalize_findings
from scopeguard.findings.models import Finding
from scopeguard.policy.plan import AssessmentPlan
from scopeguard.reporting.markdown import render_report
from scopeguard.scope.models import ScopePackage
from scopeguard.tools.base import ToolResult

from .state import AssessmentState
from .storage import PengeticStore


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _action_namespace(action: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(
        action_id=action["action_id"],
        title=action["title"],
    )


def _outcome_namespace(action: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(
        action=_action_namespace(action),
        status=action["status"],
        summary=action["decision_reason"] or action["status"],
        evidence_paths=action["evidence_paths"],
    )


def _scope_model(scope: ScopePackage | dict[str, Any]) -> ScopePackage:
    if isinstance(scope, ScopePackage):
        return scope
    if "scope_json" in scope and isinstance(scope["scope_json"], dict):
        return ScopePackage.model_validate(scope["scope_json"])
    return ScopePackage.model_validate(scope)


def _plan_model(plan: AssessmentPlan | dict[str, Any]) -> AssessmentPlan:
    if isinstance(plan, AssessmentPlan):
        return plan
    if "plan_json" in plan and isinstance(plan["plan_json"], str):
        return AssessmentPlan.model_validate_json(plan["plan_json"])
    return AssessmentPlan.model_validate(plan)


def build_run_summary(store: PengeticStore, run_id: str) -> SimpleNamespace:
    run = store.get_run(run_id)
    if run is None:
        raise ValueError(f"Run {run_id} was not found.")

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
    evidence_paths = sorted({artifact["path"] for artifact in run["artifacts"] if artifact["kind"] in {"evidence", "report"}})

    return SimpleNamespace(
        run_id=run["id"],
        started_at=started_at,
        finished_at=finished_at,
        profile=run["profile"],
        report_generated_at=datetime.now(UTC),
        outcomes=[_outcome_namespace(action) for action in run["actions"]],
        findings=[Finding.model_validate(item) for item in run["findings"]],
        evidence_paths=evidence_paths,
    )


def persist_action_outcome(
    store: PengeticStore,
    run_id: str,
    outcome: Any,
    *,
    normalized_findings: list[Any] | None = None,
) -> None:
    store.update_run_action(
        run_id,
        outcome.action.action_id,
        status=outcome.status,
        decision_reason=outcome.summary,
        result=asdict(outcome.result) if outcome.result is not None else None,
        evidence_paths=outcome.evidence_paths,
        started_at=outcome.started_at.isoformat().replace("+00:00", "Z") if outcome.started_at else None,
        finished_at=outcome.finished_at.isoformat().replace("+00:00", "Z") if outcome.finished_at else None,
    )

    if outcome.result is not None:
        for path in outcome.result.evidence_paths:
            store.add_artifact(
                run_id,
                kind="evidence",
                path=path,
                description=outcome.action.title,
                action_id=outcome.action.action_id,
            )

    for finding in normalized_findings or []:
        store.add_finding(run_id, finding, action_id=finding.source_action_id)


def build_run_summary_json(store: PengeticStore, run_id: str, *, state: str, pending_action_ids: list[str]) -> dict[str, Any]:
    run = store.get_run(run_id)
    if run is None:
        raise ValueError(f"Run {run_id} was not found.")
    executed = len([action for action in run["actions"] if action["status"] == "executed"])
    findings = len(run["findings"])
    return {
        "state": state,
        "pending_action_ids": pending_action_ids,
        "findings": findings,
        "executed_actions": executed,
        "completed_actions": len([action for action in run["actions"] if action["status"] in {"executed", "skipped", "blocked"}]),
    }


def render_and_store_report(
    store: PengeticStore,
    scope: ScopePackage | dict[str, Any],
    plan: AssessmentPlan | dict[str, Any],
    run_id: str,
    run_dir: Path,
    *,
    state: str,
    summary_json: dict[str, Any],
    record_artifact: bool = True,
) -> tuple[Path, str]:
    summary = build_run_summary(store, run_id)
    report_text = render_report(_scope_model(scope), _plan_model(plan), summary)
    report_path = run_dir / "report.md"
    report_path.write_text(report_text, encoding="utf-8")
    if record_artifact:
        store.add_artifact(
            run_id,
            kind="report",
            path=str(report_path),
            description="Rendered assessment report",
        )
    store.update_run(
        run_id,
        state=state,
        status=state,
        report_path=str(report_path),
        report_text=report_text,
        summary_json=summary_json,
        finished_at=_now() if state != AssessmentState.running.value else None,
    )
    return report_path, report_text


def normalize_tool_findings(result: ToolResult, *, source_action_id: str) -> list[Any]:
    return normalize_findings(result.findings, source_action_id=source_action_id)
