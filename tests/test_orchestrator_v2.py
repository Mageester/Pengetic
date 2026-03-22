from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import yaml

from pengetic.agent import AssessmentOrchestratorService
from pengetic.api import create_app
from pengetic.llm import PlannerSuggestion
from pengetic.orchestrator import ActionOutcome
from scopeguard.findings.models import Confidence, Finding, Severity
from scopeguard.scope.loader import load_scope_package
from scopeguard.policy.gate import GateDecision
from scopeguard.policy.risk import RiskLevel
from scopeguard.tools.base import ToolResult


def _scope_payload() -> dict[str, object]:
    return {
        "version": 1,
        "name": "Demo Lab",
        "primary_domain": "demo.test",
        "base_url": "https://demo.test",
        "allowed_subdomains": ["app.demo.test"],
        "allowed_urls": ["https://demo.test/", "https://demo.test/login"],
        "out_of_scope_assets": ["admin.demo.test"],
        "login_areas_allowed": ["/login"],
        "apis_allowed": [],
        "tool_allowlist": [
            "header-review",
            "tls-review",
            "robots-fetch",
            "sitemap-fetch",
            "route-inventory",
            "tech-fingerprint",
            "manual-review",
            "approved-login-surface-probe",
        ],
        "rate_limits": {
            "max_requests_per_minute": 60,
            "max_concurrent_requests": 2,
            "delay_seconds_between_requests": 0.5,
        },
        "testing_window": {
            "start": "2026-03-22T00:00:00Z",
            "end": "2026-03-29T23:59:59Z",
        },
        "authorization_note": "Authorized by the site owner for defensive assessment only.",
        "contacts": ["security@demo.test"],
        "notes": "Local V2 test scope.",
    }


async def _fake_suggest(self, context, *, model=None):
    return PlannerSuggestion(
        model=model or "qwen2.5-coder:14b",
        source="ollama",
        summary="Continue with the next allowed passive step and then pause for approval.",
        next_allowed_step="Run the next permitted tool in the plan.",
        recommended_action_id="passive-header-review",
        rationale="The orchestrator should follow the next safe step from the existing plan.",
        confidence="high",
        raw={"stub": True},
    )


def _fake_execute(
    self,
    action,
    *,
    run_id,
    run_dir,
    approvals,
    include_approved_active=True,
    event_sink=None,
):
    now = datetime.now(UTC)
    if action.classification == RiskLevel.passive_safe:
        findings = []
        if action.action_id == "passive-header-review":
            findings.append(
                Finding(
                    title="Missing HSTS header",
                    severity=Severity.medium,
                    confidence=Confidence.high,
                    affected_asset="https://demo.test/",
                    evidence=["Header snapshot missing Strict-Transport-Security."],
                    why_it_matters="Transport hardening is weaker than expected for a security review target.",
                    safe_verification_status="Verified passively from the public root response.",
                    remediation="Add a Strict-Transport-Security header with a suitable max-age.",
                    source_tool="header-review",
                    source_action_id=action.action_id,
                )
            )
        result = ToolResult.create(
            tool_id=action.tool_id,
            action_id=action.action_id,
            target=action.target,
            summary="Passive review completed.",
            details={"headers": ["Strict-Transport-Security"]},
            evidence_paths=[str(run_dir / "evidence" / f"{action.action_id}.json")],
            findings=[finding.model_dump(mode="json") for finding in findings],
            started_at=now,
            finished_at=now,
        )
        return ActionOutcome(
            action=action,
            decision=GateDecision(approved=True, auto_approved=True, reason="Passive-safe actions may execute automatically."),
            status="executed",
            summary=result.summary,
            evidence_paths=result.evidence_paths,
            result=result,
            started_at=now,
            finished_at=now,
            details=result.details,
        )

    return ActionOutcome(
        action=action,
        decision=GateDecision(
            approved=False,
            auto_approved=False,
            reason="Explicit approval is required before this action can run.",
        ),
        status="pending-approval",
        summary="Waiting for approval.",
        evidence_paths=[],
        result=None,
        started_at=None,
        finished_at=None,
        details={"reason": "Awaiting explicit approval."},
    )


def test_orchestrator_service_persists_json_decisions_and_stops_for_approval(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PENGETIC_ROOT", str(tmp_path))
    monkeypatch.setenv("PENGETIC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PENGETIC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("PENGETIC_FRONTEND_DIST", str(tmp_path / "frontend-dist"))

    app = create_app()
    payload = _scope_payload()
    payload["rate_limits"] = {
        "max_requests_per_minute": 60,
        "max_concurrent_requests": 2,
        "delay_seconds_between_requests": 0,
    }
    scope_yaml = yaml.safe_dump(payload, sort_keys=False)
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(scope_yaml, encoding="utf-8")
    scope = load_scope_package(scope_path)

    store = app.state.store
    store.upsert_scope(scope, raw_yaml=scope_yaml, source_path=str(scope_path))
    coordinator = AssessmentOrchestratorService(store=store, settings=app.state.settings)
    plan = coordinator._coordinator(scope, profile="passive-only").build_plan()
    store.save_plan(scope, "passive-only", plan, activate=True)
    run = store.create_run(scope, plan, profile="passive-only", manual_notes="Orchestrator regression coverage.")
    run_id = run["id"]

    monkeypatch.setattr("pengetic.agent.OllamaPlannerService.suggest", _fake_suggest)
    monkeypatch.setattr("pengetic.agent.AssessmentRunCoordinator.execute_action", _fake_execute)

    result = asyncio.run(coordinator.run_assessment(run_id, max_steps=10, model="qwen2.5-coder:14b"))

    assert result.state == "awaiting_approval"
    assert result.stop_reason == "approval_required"
    assert result.steps
    assert result.steps[0].selected_action_id == "passive-header-review"
    assert result.steps[-1].status == "pending-approval"
    assert result.run.findings

    persisted_steps = store.list_orchestrator_steps(run_id)
    assert len(persisted_steps) == len(result.steps)
    assert persisted_steps[0]["decision_json"]["selected_action_id"] == "passive-header-review"

    refreshed_run = store.get_run(run_id)
    assert refreshed_run is not None
    assert refreshed_run["state"] == "awaiting_approval"
