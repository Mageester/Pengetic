from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from scopeguard.config import RuntimeProfile
from scopeguard.findings.models import Confidence, Finding, Severity
from scopeguard.policy.plan import AssessmentPlanner
from scopeguard.reporting.markdown import render_report
from scopeguard.scope.loader import load_scope_package
from scopeguard.tools.registry import default_tool_registry


@dataclass
class _Outcome:
    action: object
    status: str
    summary: str
    evidence_paths: list[str]


def test_report_contains_expected_sections() -> None:
    scope = load_scope_package(Path("examples/scope.demo.yaml"))
    plan = AssessmentPlanner(default_tool_registry()).build(scope, RuntimeProfile.passive_only)
    finding = Finding(
        title="Missing HSTS header",
        severity=Severity.medium,
        confidence=Confidence.high,
        affected_asset=str(scope.base_url),
        evidence=["No HSTS header observed."],
        why_it_matters="Transport downgrade risk remains higher without HSTS.",
        safe_verification_status="Verified passively.",
        remediation="Add HSTS.",
    )
    outcome = _Outcome(
        action=plan.get_action("passive-header-review"),
        status="executed",
        summary="Ran passive header review.",
        evidence_paths=["artifacts/run/evidence.json"],
    )
    run_summary = SimpleNamespace(
        run_id="run-1",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        profile="passive-only",
        report_generated_at=datetime.now(UTC),
        outcomes=[outcome],
        findings=[finding],
        evidence_paths=["artifacts/run/evidence.json"],
    )

    report = render_report(scope, plan, run_summary)

    assert "# Pengetic Assessment Report" in report
    assert "Executive Summary" in report
    assert "Missing HSTS header" in report
    assert "Execution Summary" in report
    assert "Limitations" in report
