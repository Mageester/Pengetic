from __future__ import annotations

from datetime import UTC, datetime
import time
from pathlib import Path

from fastapi.testclient import TestClient
import yaml

from pengetic.api import create_app
from pengetic.llm import PlannerSuggestion
from pengetic.orchestrator import ActionOutcome, RunExecutionResult
from pengetic.state import AssessmentState
from scopeguard.findings.models import Confidence, Finding, Severity
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


def _wait_for_run(client: TestClient, run_id: str, predicate, timeout: float = 5.0) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    last_response: dict[str, object] | None = None
    while time.monotonic() < deadline:
        response = client.get(f"/api/runs/{run_id}")
        assert response.status_code == 200, response.text
        last_response = response.json()
        if predicate(last_response):
            return last_response
        time.sleep(0.05)
    raise AssertionError(f"Timed out waiting for run {run_id}: {last_response}")


def test_v2_api_supports_scope_run_approval_resume_and_reporting(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PENGETIC_ROOT", str(tmp_path))
    monkeypatch.setenv("PENGETIC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PENGETIC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("PENGETIC_FRONTEND_DIST", str(tmp_path / "frontend-dist"))

    passive_finding = Finding(
        title="Missing HSTS header",
        severity=Severity.medium,
        confidence=Confidence.high,
        affected_asset="https://demo.test/",
        evidence=["Header snapshot missing Strict-Transport-Security."],
        why_it_matters="Transport hardening is weaker than expected for a security review target.",
        safe_verification_status="Verified passively from the public root response.",
        remediation="Add a Strict-Transport-Security header with a suitable max-age.",
        source_tool="header-review",
        source_action_id="passive-header-review",
    )

    def fake_execute(
        self,
        plan,
        *,
        run_id,
        run_dir,
        approvals,
        include_approved_active=False,
        action_ids=None,
        stop_on_pending_active=False,
        event_sink=None,
        resume=False,
    ):
        run_dir.mkdir(parents=True, exist_ok=True)
        now = datetime.now(UTC)
        selected_actions = [action for action in plan.actions if action_ids is None or action.action_id in action_ids]
        outcomes: list[ActionOutcome] = []
        findings: list[Finding] = []
        evidence_paths: list[str] = []
        pending_action_ids: list[str] = []

        passive_actions = [action for action in selected_actions if action.classification == RiskLevel.passive_safe]
        active_actions = [action for action in selected_actions if action.classification != RiskLevel.passive_safe]

        for action in passive_actions:
            action_findings = [passive_finding.model_dump(mode="json")] if action.action_id == "passive-header-review" else []
            result = ToolResult.create(
                tool_id=action.tool_id,
                action_id=action.action_id,
                target=action.target,
                summary="Passive review completed.",
                details={"headers": ["Strict-Transport-Security"]},
                evidence_paths=[str(run_dir / "evidence" / f"{action.action_id}.json")],
                findings=action_findings,
                started_at=now,
                finished_at=now,
            )
            if action.action_id == "passive-header-review":
                findings.append(passive_finding)
            evidence_paths.extend(result.evidence_paths)
            outcomes.append(
                ActionOutcome(
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
            )

        for action in active_actions:
            if resume or action_ids is not None:
                result = ToolResult.create(
                    tool_id=action.tool_id,
                    action_id=action.action_id,
                    target=action.target,
                    summary="Approved action executed.",
                    evidence_paths=[str(run_dir / "evidence" / f"{action.action_id}.json")],
                    started_at=now,
                    finished_at=now,
                )
                evidence_paths.extend(result.evidence_paths)
                outcomes.append(
                    ActionOutcome(
                        action=action,
                        decision=GateDecision(approved=True, auto_approved=False, reason="Matching approval record found."),
                        status="executed",
                        summary=result.summary,
                        evidence_paths=result.evidence_paths,
                        result=result,
                        started_at=now,
                        finished_at=now,
                        details=result.details,
                    )
                )
            else:
                pending_action_ids.append(action.action_id)
                outcomes.append(
                    ActionOutcome(
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
                )

        state = AssessmentState.completed if not pending_action_ids else AssessmentState.awaiting_approval
        return RunExecutionResult(
            run_id=run_id,
            run_dir=run_dir,
            scope_name=self.scope.name,
            scope_fingerprint=self.scope_fp,
            profile=self.profile.name.value,
            plan=plan,
            outcomes=outcomes,
            findings=findings,
            evidence_paths=sorted(set(evidence_paths)),
            report_path=run_dir / "report.md",
            report_text="",
            started_at=now,
            finished_at=now,
            state=state,
            pending_action_ids=pending_action_ids,
            notes=self.manual_notes,
        )

    async def fake_suggest(self, context, *, model=None):
        return PlannerSuggestion(
            model=model or "llama3.1",
            source="ollama",
            summary="One passive finding is recorded and the login probe is now approved.",
            next_allowed_step="Execute the approved login probe.",
            recommended_action_id="active-login-surface-probe",
            rationale="The approved active action remains in scope and should be the next allowed step.",
            confidence="high",
            raw={"stub": True},
        )

    monkeypatch.setattr("pengetic.api.AssessmentRunCoordinator.execute", fake_execute)
    monkeypatch.setattr("pengetic.api.OllamaPlannerService.suggest", fake_suggest)

    scope_yaml = yaml.safe_dump(_scope_payload(), sort_keys=False)
    app = create_app()

    with TestClient(app) as client:
        upload = client.post(
            "/api/scopes/upload",
            files={"file": ("scope.yaml", scope_yaml, "text/yaml")},
            data={"profile": "passive-only", "activate": "true"},
        )
        assert upload.status_code == 200, upload.text
        upload_payload = upload.json()
        assert upload_payload["scope"]["name"] == "Demo Lab"
        assert upload_payload["plan"]["actions"]

        dashboard = client.get("/api/dashboard")
        assert dashboard.status_code == 200, dashboard.text
        dashboard_payload = dashboard.json()
        assert dashboard_payload["state"] == "plan_ready"
        assert dashboard_payload["current_scope"]["name"] == "Demo Lab"
        assert dashboard_payload["current_plan"]["actions"]

        start = client.post(
            "/api/runs",
            json={
                "profile": "passive-only",
                "manual_notes": "Initial local-first assessment.",
                "include_approved_active": False,
            },
        )
        assert start.status_code == 202, start.text
        run_id = start.json()["id"]

        first_run = _wait_for_run(
            client,
            run_id,
            lambda payload: payload["state"] == "awaiting_approval" and payload["report_path"],
        )
        assert any(action["status"] == "executed" for action in first_run["actions"])
        assert any(action["status"] == "pending-approval" for action in first_run["actions"])
        assert first_run["findings"]
        assert any(artifact["kind"] == "report" for artifact in first_run["artifacts"])

        pending = client.get("/api/dashboard").json()["pending_approvals"]
        assert len(pending) == 1
        assert pending[0]["action_id"] == "active-login-surface-probe"

        approval = client.post(
            "/api/approvals",
            json={
                "run_id": run_id,
                "action_id": "active-login-surface-probe",
                "approved_by": "tester",
                "note": "Approved for local regression coverage.",
            },
        )
        assert approval.status_code == 200, approval.text
        assert approval.json()["status"] == "approved"

        approvals = client.get(f"/api/runs/{run_id}/approvals")
        assert approvals.status_code == 200, approvals.text
        assert len(approvals.json()) == 1

        resumed = client.post(f"/api/runs/{run_id}/resume", json={"include_approved_active": True})
        assert resumed.status_code == 202, resumed.text

        completed = _wait_for_run(
            client,
            run_id,
            lambda payload: payload["state"] == "completed" and payload["report_path"],
        )
        assert any(action["status"] == "executed" for action in completed["actions"])
        assert any(finding["title"] == "Missing HSTS header" for finding in completed["findings"])

        report = client.get(f"/api/reports/{run_id}")
        assert report.status_code == 200, report.text
        assert "Demo Lab" in report.json()["report_text"]

        export = client.get(f"/api/reports/{run_id}/export")
        assert export.status_code == 200, export.text
        assert "Demo Lab" in export.text

        events = client.get(f"/api/runs/{run_id}/events")
        assert events.status_code == 200, events.text
        assert events.json()

        planner = client.post(
            "/api/llm/planner",
            json={
                "run_id": run_id,
                "scope_id": None,
                "model": "llama3.1",
            },
        )
        assert planner.status_code == 200, planner.text
        planner_payload = planner.json()
        assert planner_payload["source"] == "ollama"
        assert planner_payload["recommended_action_id"] == "active-login-surface-probe"
        assert planner_payload["next_allowed_step"] == "Execute the approved login probe."


def test_v2_frontend_assets_are_served_as_static_files(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PENGETIC_ROOT", str(tmp_path))
    monkeypatch.setenv("PENGETIC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PENGETIC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    frontend_dist = tmp_path / "frontend-dist"
    assets_dir = frontend_dist / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    (frontend_dist / "index.html").write_text(
        "<!doctype html><html><body><div id=\"root\"></div><script type=\"module\" src=\"/assets/app-123.js\"></script></body></html>",
        encoding="utf-8",
    )
    (assets_dir / "app-123.js").write_text("console.log('Pengetic asset');", encoding="utf-8")
    monkeypatch.setenv("PENGETIC_FRONTEND_DIST", str(frontend_dist))

    app = create_app()
    with TestClient(app) as client:
        asset_response = client.get("/assets/app-123.js")
        assert asset_response.status_code == 200, asset_response.text
        assert "text/html" not in asset_response.headers["content-type"]
        assert "javascript" in asset_response.headers["content-type"]
        assert "Pengetic asset" in asset_response.text

        app_route = client.get("/dashboard")
        assert app_route.status_code == 200, app_route.text
        assert "<div id=\"root\"></div>" in app_route.text

        missing_asset = client.get("/assets/missing.js")
        assert missing_asset.status_code == 404, missing_asset.text
