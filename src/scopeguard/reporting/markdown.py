from __future__ import annotations

from collections import Counter
from typing import Any

from ..findings.models import Finding
from ..policy.plan import AssessmentPlan
from ..scope.models import ScopePackage


def _heading(text: str, level: int = 2) -> str:
    return f"{'#' * level} {text}"


def _bullet(text: str) -> str:
    return f"- {text}"


def render_report(scope: ScopePackage, plan: AssessmentPlan, run_summary: Any) -> str:
    findings: list[Finding] = list(run_summary.findings)
    severity_counts = Counter(finding.severity.value for finding in findings)
    executed = [outcome for outcome in run_summary.outcomes if outcome.status == "executed"]
    skipped = [outcome for outcome in run_summary.outcomes if outcome.status != "executed"]

    lines: list[str] = []
    lines.append("# ScopeGuard Assessment Report")
    lines.append("")
    lines.append(_heading("Executive Summary"))
    lines.append(
        f"This run executed {len(executed)} action(s), skipped {len(skipped)} action(s), and produced {len(findings)} finding(s)."
    )
    if findings:
        lines.append(
            "Severity breakdown: "
            + ", ".join(
                f"{name}={severity_counts.get(name, 0)}" for name in ["critical", "high", "medium", "low", "informational"]
            )
            + "."
        )
    else:
        lines.append("No passive findings were produced from the automatically executed checks.")

    lines.append("")
    lines.append(_heading("Scope Confirmation"))
    lines.append(_bullet(f"Name: {scope.name}"))
    lines.append(_bullet(f"Primary domain: {scope.primary_domain}"))
    lines.append(_bullet(f"Base URL: {scope.base_url}"))
    lines.append(_bullet(f"Authorized hosts: {', '.join(scope.authorized_hosts)}"))
    lines.append(_bullet(f"Tool allowlist: {', '.join(scope.tool_allowlist)}"))
    lines.append(_bullet(f"Scope fingerprint: `{plan.scope_fingerprint}`"))
    if scope.testing_window and scope.testing_window.start:
        lines.append(_bullet(f"Testing window start: {scope.testing_window.start.isoformat()}"))
    if scope.testing_window and scope.testing_window.end:
        lines.append(_bullet(f"Testing window end: {scope.testing_window.end.isoformat()}"))
    lines.append(_bullet(f"Authorization note: {scope.authorization_note}"))

    lines.append("")
    lines.append(_heading("Methodology"))
    lines.append("Passive checks were run automatically when their tools were present in the scope allowlist.")
    lines.append("Active validation steps were only recorded as gated stubs and remained blocked without explicit approval.")

    lines.append("")
    lines.append(_heading("Findings"))
    if findings:
        for finding in findings:
            lines.append(f"### {finding.title}")
            lines.append(_bullet(f"Severity: {finding.severity.value}"))
            lines.append(_bullet(f"Confidence: {finding.confidence.value}"))
            lines.append(_bullet(f"Affected asset: {finding.affected_asset}"))
            lines.append(_bullet(f"Safe verification status: {finding.safe_verification_status}"))
            lines.append(_bullet(f"Why it matters: {finding.why_it_matters}"))
            lines.append(_bullet("Evidence:"))
            for item in finding.evidence or ["No evidence captured."]:
                lines.append(f"  - {item}")
            lines.append(_bullet(f"Remediation: {finding.remediation}"))
            lines.append("")
    else:
        lines.append("No findings were confirmed from the passive checks that ran in this assessment.")

    lines.append(_heading("Execution Summary"))
    for outcome in run_summary.outcomes:
        lines.append(
            _bullet(f"{outcome.action.action_id} | {outcome.action.title} | {outcome.status} | {outcome.summary}")
        )
        if outcome.evidence_paths:
            for artifact in outcome.evidence_paths:
                lines.append(f"  - artifact: {artifact}")

    lines.append("")
    lines.append(_heading("Evidence"))
    if run_summary.evidence_paths:
        for path in run_summary.evidence_paths:
            lines.append(_bullet(path))
    else:
        lines.append("No evidence artifacts were recorded.")

    lines.append("")
    lines.append(_heading("Limitations"))
    lines.append("Only passive-safe actions are executed automatically.")
    lines.append("Active validations remain gated and are represented as safe stubs until approval and tooling are added.")
    lines.append("Observations are limited to the in-scope surface and whatever public content was returned during passive review.")

    lines.append("")
    lines.append(_heading("Run Metadata"))
    lines.append(_bullet(f"Run ID: {run_summary.run_id}"))
    lines.append(_bullet(f"Profile: {run_summary.profile}"))
    lines.append(_bullet(f"Started: {run_summary.started_at.isoformat()}"))
    lines.append(_bullet(f"Finished: {run_summary.finished_at.isoformat()}"))
    lines.append(_bullet(f"Report generated at: {run_summary.report_generated_at.isoformat()}"))

    return "\n".join(lines).rstrip() + "\n"

