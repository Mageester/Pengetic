from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from .config import RuntimeProfile
from .engine import AssessmentEngine, load_latest_run
from .policy.approvals import ApprovalRecord, ApprovalStore
from .policy.plan import AssessmentPlan, AssessmentPlanner
from .policy.risk import RiskLevel
from .runtime import build_workspace
from .scope.errors import PengeticError
from .scope.fingerprint import scope_fingerprint
from .scope.loader import load_scope_package
from .tools.registry import default_tool_registry


app = typer.Typer(
    help="Pengetic: authorized defensive web assessment framework.",
    add_completion=False,
    no_args_is_help=True,
)


def _handle_error(exc: Exception) -> None:
    typer.echo(f"Error: {exc}", err=True)
    raise typer.Exit(code=1)


@app.command("validate-scope")
def validate_scope(
    scope_path: Annotated[Path, typer.Argument(help="Path to a YAML scope package.")],
) -> None:
    try:
        scope = load_scope_package(scope_path)
        typer.echo(f"Scope package is valid: {scope.name}")
        typer.echo(f"Primary domain: {scope.primary_domain}")
        typer.echo(f"Base URL: {scope.base_url}")
        typer.echo(f"Authorized hosts: {', '.join(scope.authorized_hosts)}")
    except Exception as exc:
        _handle_error(exc)


@app.command("plan")
def plan(
    scope_path: Annotated[Path, typer.Argument(help="Path to a YAML scope package.")],
    artifacts_root: Annotated[Path, typer.Option("--artifacts-root", "-o")] = Path("artifacts"),
    profile: Annotated[RuntimeProfile, typer.Option("--profile")] = RuntimeProfile.passive_only,
) -> None:
    try:
        scope = load_scope_package(scope_path)
        planner = AssessmentPlanner(default_tool_registry())
        assessment_plan = planner.build(scope, profile)
        workspace = build_workspace(scope, artifacts_root)
        workspace.ensure()
        workspace.plan_path.write_text(
            assessment_plan.model_dump_json(indent=2),
            encoding="utf-8",
        )
        workspace.scope_snapshot_path.write_text(
            scope.model_dump_json(indent=2),
            encoding="utf-8",
        )
        typer.echo(f"Plan written to {workspace.plan_path}")
        for action in assessment_plan.actions:
            status = "allowed" if action.allowed_by_scope else "blocked-by-allowlist"
            approval = "approval required" if action.approval_required else "no approval required"
            typer.echo(f"- {action.action_id}: {action.classification.value} | {status} | {approval}")
    except Exception as exc:
        _handle_error(exc)


@app.command("approve")
def approve(
    scope_path: Annotated[Path, typer.Argument(help="Path to a YAML scope package.")],
    action_id: Annotated[str, typer.Argument(help="Action identifier from the plan.")],
    approved_by: Annotated[str, typer.Option("--approved-by")] = "user",
    note: Annotated[str, typer.Option("--note")] = "Explicit user approval.",
    artifacts_root: Annotated[Path, typer.Option("--artifacts-root", "-o")] = Path("artifacts"),
) -> None:
    try:
        scope = load_scope_package(scope_path)
        workspace = build_workspace(scope, artifacts_root)
        if not workspace.plan_path.exists():
            raise PengeticError("No plan file exists yet. Run 'pengetic plan' first.")
        plan = AssessmentPlan.model_validate_json(workspace.plan_path.read_text(encoding="utf-8"))
        action = plan.get_action(action_id)
        if action.classification == RiskLevel.passive_safe:
            typer.echo("No approval is required for passive-safe actions.")
            raise typer.Exit(code=0)
        approval = ApprovalRecord.create(
            action_id=action.action_id,
            scope_fingerprint=scope_fingerprint(scope),
            approved_by=approved_by,
            note=note,
            risk=action.classification,
        )
        store = ApprovalStore(workspace.approvals_path)
        store.append(approval)
        typer.echo(f"Approval recorded for {action_id} at {workspace.approvals_path}")
    except KeyError:
        _handle_error(PengeticError(f"Unknown action id: {action_id}"))
    except Exception as exc:
        _handle_error(exc)


@app.command("run")
def run(
    scope_path: Annotated[Path, typer.Argument(help="Path to a YAML scope package.")],
    artifacts_root: Annotated[Path, typer.Option("--artifacts-root", "-o")] = Path("artifacts"),
    profile: Annotated[RuntimeProfile, typer.Option("--profile")] = RuntimeProfile.passive_only,
    include_approved_active: Annotated[bool, typer.Option("--include-approved-active")] = False,
    manual_notes: Annotated[str | None, typer.Option("--manual-notes")] = None,
) -> None:
    try:
        scope = load_scope_package(scope_path)
        engine = AssessmentEngine(
            scope,
            profile=profile,
            artifacts_root=artifacts_root,
            manual_notes=manual_notes,
        )
        summary = engine.run(include_approved_active=include_approved_active)
        typer.echo(f"Run ID: {summary.run_id}")
        typer.echo(f"Report: {summary.report_path}")
        typer.echo(f"Findings: {len(summary.findings)}")
        for finding in summary.findings:
            typer.echo(f"- [{finding.severity.value}] {finding.title}")
    except Exception as exc:
        _handle_error(exc)


@app.command("report")
def report(
    scope_path: Annotated[Path, typer.Argument(help="Path to a YAML scope package.")],
    run_id: Annotated[str | None, typer.Option("--run-id")] = None,
    artifacts_root: Annotated[Path, typer.Option("--artifacts-root", "-o")] = Path("artifacts"),
    output: Annotated[Path | None, typer.Option("--output")] = None,
) -> None:
    try:
        scope = load_scope_package(scope_path)
        workspace = build_workspace(scope, artifacts_root)
        run_dir = load_latest_run(workspace, run_id)
        report_path = run_dir / "report.md"
        if not report_path.exists():
            raise PengeticError(f"Run report does not exist: {report_path}")
        report_text = report_path.read_text(encoding="utf-8")
        if output is not None:
            output.write_text(report_text, encoding="utf-8")
            typer.echo(f"Report written to {output}")
        else:
            typer.echo(report_text)
    except Exception as exc:
        _handle_error(exc)
