from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
import ssl
import subprocess

import httpx
import yaml
from fastapi.testclient import TestClient

from pengetic.api import create_app
from pengetic.llm import PlannerSuggestion
from scopeguard.findings.models import Confidence, Finding, Severity
from scopeguard.config import RuntimeProfile
from scopeguard.evidence.audit import AuditLogger
from scopeguard.evidence.store import EvidenceStore
from scopeguard.policy.plan import AssessmentPlanner
from scopeguard.scope.loader import load_scope_package
from scopeguard.tools.base import ExecutionContext, ToolResult
from scopeguard.tools.http_probe import probe_http_surface
from scopeguard.tools.nmap import nmap_service_discovery
from scopeguard.tools.tls import review_tls_posture


def _scope_payload(*, name: str, base_url: str, include_nmap: bool = False) -> dict[str, object]:
    tool_allowlist = [
        "header-review",
        "tls-review",
        "robots-fetch",
        "sitemap-fetch",
        "route-inventory",
        "tech-fingerprint",
        "manual-review",
    ]
    if include_nmap:
        tool_allowlist.append("nmap-service-discovery")
    return {
        "version": 1,
        "name": name,
        "primary_domain": base_url.split("//", 1)[-1].rstrip("/"),
        "base_url": base_url,
        "allowed_subdomains": [],
        "allowed_urls": [base_url],
        "out_of_scope_assets": [],
        "login_areas_allowed": ["/login"],
        "apis_allowed": ["/api"],
        "tool_allowlist": tool_allowlist,
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
        "contacts": ["security@example.com"],
        "notes": f"{name} test scope.",
    }


def test_model_persistence_pulse_template_and_purge(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PENGETIC_ROOT", str(tmp_path))
    monkeypatch.setenv("PENGETIC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PENGETIC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("PENGETIC_FRONTEND_DIST", str(tmp_path / "frontend-dist"))

    async def fake_pulse(self, *, selected_model: str):
        return {
            "status": "ok",
            "service": "ollama",
            "selected_model": selected_model,
            "available_models": [selected_model],
            "selected_model_available": True,
            "checked_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "error": None,
            "raw": {"models": [{"name": selected_model}]},
        }

    monkeypatch.setattr("pengetic.api.OllamaPulseService.pulse", fake_pulse)

    app = create_app()
    with TestClient(app) as client:
        save_model = client.post("/api/llm/model", json={"model": "qwen2.5-coder:14b"})
        assert save_model.status_code == 200, save_model.text
        assert save_model.json()["selected_model"] == "qwen2.5-coder:14b"

        stored_model = client.get("/api/llm/model")
        assert stored_model.status_code == 200, stored_model.text
        stored_payload = stored_model.json()
        assert stored_payload["selected_model"] == "qwen2.5-coder:14b"
        assert stored_payload["source"] == "database"

        pulse = client.get("/api/engine/pulse")
        assert pulse.status_code == 200, pulse.text
        pulse_payload = pulse.json()
        assert pulse_payload["status"] == "ok"
        assert pulse_payload["selected_model_available"] is True

        template = client.post(
            "/api/scopes/templates/generate",
            json={
                "template_id": "web-surface-mapping",
                "scope_name": "Template Lab",
                "target_url": "https://template.example",
                "allowed_subdomains": ["app.template.example"],
                "login_areas_allowed": ["/login"],
                "apis_allowed": ["/api"],
                "tool_allowlist": [],
                "authorization_note": "Authorized by the site owner for defensive assessment only.",
                "contacts": ["security@template.example"],
                "notes": "Generated from the wizard.",
                "profile": "passive-only",
                "activate": True,
            },
        )
        assert template.status_code == 200, template.text
        template_payload = template.json()
        assert template_payload["scope"]["name"] == "Template Lab"
        assert template_payload["plan"]["actions"]
        assert any(action["action_id"] == "active-nmap-service-discovery" for action in template_payload["plan"]["actions"])

        dashboard = client.get("/api/dashboard")
        assert dashboard.status_code == 200, dashboard.text
        dashboard_payload = dashboard.json()
        assert dashboard_payload["current_scope"]["name"] == "Template Lab"
        assert dashboard_payload["counts"]["runs"] == 0

        bad_purge = client.post("/api/system/purge-all", json={"confirmation": "NOPE"})
        assert bad_purge.status_code == 400, bad_purge.text

        purge = client.post("/api/system/purge-all", json={"confirmation": "CONFIRM_PURGE"})
        assert purge.status_code == 200, purge.text
        assert purge.json()["status"] == "purged"

        dashboard_after = client.get("/api/dashboard")
        assert dashboard_after.status_code == 200, dashboard_after.text
        dashboard_after_payload = dashboard_after.json()
        assert dashboard_after_payload["current_scope"] is None
        assert dashboard_after_payload["counts"]["runs"] == 0
        assert client.get("/api/runs").json() == []

        reset_model = client.get("/api/llm/model")
        assert reset_model.status_code == 200, reset_model.text
        assert reset_model.json()["selected_model"] == "llama3.1"


def test_active_scope_filters_run_history_and_dashboard(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PENGETIC_ROOT", str(tmp_path))
    monkeypatch.setenv("PENGETIC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PENGETIC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("PENGETIC_FRONTEND_DIST", str(tmp_path / "frontend-dist"))

    app = create_app()
    store = app.state.store

    scope_a_yaml = yaml.safe_dump(_scope_payload(name="Scope A", base_url="https://scope-a.test"), sort_keys=False)
    scope_b_yaml = yaml.safe_dump(_scope_payload(name="Scope B", base_url="https://scope-b.test"), sort_keys=False)
    scope_a_path = tmp_path / "scope-a.yaml"
    scope_b_path = tmp_path / "scope-b.yaml"
    scope_a_path.write_text(scope_a_yaml, encoding="utf-8")
    scope_b_path.write_text(scope_b_yaml, encoding="utf-8")
    scope_a = load_scope_package(scope_a_path)
    scope_b = load_scope_package(scope_b_path)

    scope_a_record = store.upsert_scope(scope_a, raw_yaml=scope_a_yaml, source_path=str(scope_a_path))
    plan_a = AssessmentPlanner().build(scope_a, RuntimeProfile.passive_only)
    stored_plan_a = store.save_plan(scope_a, "passive-only", plan_a, activate=True)
    run_a = store.create_run(scope_a, plan_a, profile="passive-only")

    store.upsert_scope(scope_b, raw_yaml=scope_b_yaml, source_path=str(scope_b_path))
    plan_b = AssessmentPlanner().build(scope_b, RuntimeProfile.passive_only)
    store.save_plan(scope_b, "passive-only", plan_b, activate=True)
    store.create_run(scope_b, plan_b, profile="passive-only")

    store.set_current_scope(scope_a_record["id"])
    store.set_current_plan(stored_plan_a["id"])

    with TestClient(app) as client:
        dashboard = client.get("/api/dashboard")
        assert dashboard.status_code == 200, dashboard.text
        dashboard_payload = dashboard.json()
        assert dashboard_payload["current_scope"]["name"] == "Scope A"
        assert dashboard_payload["counts"]["runs"] == 1
        assert len(dashboard_payload["recent_runs"]) == 1
        assert dashboard_payload["recent_runs"][0]["id"] == run_a["id"]

        runs = client.get("/api/runs")
        assert runs.status_code == 200, runs.text
        run_ids = [item["id"] for item in runs.json()]
        assert run_ids == [run_a["id"]]


def test_nmap_service_discovery_parses_services_and_recommendations(tmp_path: Path, monkeypatch) -> None:
    scope_yaml = yaml.safe_dump(
        _scope_payload(name="Nmap Lab", base_url="https://demo.test", include_nmap=True),
        sort_keys=False,
    )
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(scope_yaml, encoding="utf-8")
    scope = load_scope_package(scope_path)

    evidence_root = tmp_path / "evidence"
    run_dir = tmp_path / "run"
    context = ExecutionContext(
        scope=scope,
        scope_fingerprint="scope-fp",
        run_id="run-1",
        run_dir=run_dir,
        evidence_store=EvidenceStore(evidence_root),
        audit_logger=AuditLogger(tmp_path / "audit.jsonl"),
        http_client=httpx.Client(),
    )
    action = SimpleNamespace(tool_id="nmap-service-discovery", action_id="active-nmap-service-discovery", target="https://demo.test/")

    def fake_run(command, capture_output, text, check):
        assert command[0] == "nmap"
        output_base = Path(command[command.index("-oA") + 1])
        xml_path = output_base.with_suffix(".xml")
        xml_path.write_text(
            """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" />
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="9.6" />
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" />
        <service name="https" product="nginx" version="1.24.0" />
      </port>
    </ports>
  </host>
</nmaprun>
""",
            encoding="utf-8",
        )
        output_base.with_suffix(".nmap").write_text("Nmap scan report for demo.test\n", encoding="utf-8")
        output_base.with_suffix(".gnmap").write_text("Host: demo.test () Ports: 22/open/tcp//ssh///, 443/open/tcp//https///\n", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="Nmap done", stderr="")

    monkeypatch.setattr("scopeguard.tools.nmap.subprocess.run", fake_run)

    result = nmap_service_discovery(action, context)

    assert result.success is True
    assert result.details["services"]
    assert any(service["port"] == "443" for service in result.details["services"])
    assert any("Verify SSL configuration" in recommendation for recommendation in result.details["recommendations"])
    assert any(path.endswith(".xml") for path in result.evidence_paths)
    assert result.findings


def test_tool_result_schema_normalizes_legacy_findings_and_artifacts(tmp_path: Path) -> None:
    legacy_finding = Finding(
        title="Missing HSTS header",
        severity=Severity.medium,
        confidence=Confidence.high,
        affected_asset="https://demo.test/",
        evidence=["Header snapshot missing Strict-Transport-Security."],
        why_it_matters="Transport hardening is weaker than expected.",
        safe_verification_status="Verified passively from the public root response.",
        remediation="Add a Strict-Transport-Security header with a suitable max-age.",
        source_tool="header-review",
        source_action_id="passive-header-review",
    ).model_dump(mode="json")

    result = ToolResult.create(
        tool_id="header-review",
        action_id="passive-header-review",
        target="https://demo.test/",
        run_id="run-1",
        scope_id="scope-1",
        raw_output={"headers": {"strict-transport-security": None}},
        parsed_output={"security_headers": {"strict-transport-security": False}},
        artifacts=[{"kind": "evidence", "path": str(tmp_path / "header.json"), "description": "Header snapshot"}],
        findings=[legacy_finding],
        next_safe_checks=["Review the HSTS header policy."],
        metadata={"summary": "Header review completed."},
    )

    payload = result.to_dict()
    assert payload["tool_id"] == "header-review"
    assert payload["findings_candidates"][0]["title"] == "Missing HSTS header"
    assert payload["artifacts"][0]["path"].endswith("header.json")
    assert payload["summary"] == "Header review completed."
    assert payload["details"] == {"security_headers": {"strict-transport-security": False}}


def test_http_and_tls_parsers_return_structured_evidence(tmp_path: Path, monkeypatch) -> None:
    scope_yaml = yaml.safe_dump(_scope_payload(name="HTTP TLS Lab", base_url="https://demo.test"), sort_keys=False)
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(scope_yaml, encoding="utf-8")
    scope = load_scope_package(scope_path)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                302,
                headers={"Location": "/landing", "Server": "MockServer/2.0"},
                text="",
            )
        if request.url.path == "/landing":
            return httpx.Response(
                200,
                headers={
                    "Content-Type": "text/html; charset=utf-8",
                    "Server": "MockServer/2.0",
                    "Set-Cookie": "sessionid=secret123; Path=/; HttpOnly",
                },
                text=(
                    "<html><head><title>Demo Landing</title><meta name='generator' content='MockCMS'></head>"
                    "<body><form action='/login' method='post'><input name='user' /></form></body></html>"
                ),
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    context = ExecutionContext(
        scope=scope,
        scope_fingerprint="scope-fp",
        run_id="run-1",
        run_dir=tmp_path / "run",
        evidence_store=EvidenceStore(tmp_path / "artifacts"),
        audit_logger=AuditLogger(tmp_path / "audit.jsonl"),
        http_client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True),
    )
    http_action = SimpleNamespace(tool_id="http-probe", action_id="passive-http-probe", target="https://demo.test/")
    http_result = probe_http_surface(http_action, context)

    assert http_result.parsed_output["status_code"] == 200
    assert http_result.parsed_output["title"] == "Demo Landing"
    assert len(http_result.parsed_output["redirects"]) == 1
    assert http_result.parsed_output["forms"]
    assert http_result.next_safe_checks
    assert http_result.artifacts

    class _FakeTlsSocket:
        def __enter__(self) -> "_FakeTlsSocket":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

        def getpeercert(self) -> dict[str, object]:
            return {
                "subject": ((("commonName", "demo.test"),),),
                "issuer": ((("commonName", "Mock CA"),),),
                "notBefore": "Jan  1 00:00:00 2025 GMT",
                "notAfter": "Jan  1 00:00:00 2030 GMT",
                "subjectAltName": (("DNS", "demo.test"), ("DNS", "www.demo.test")),
            }

        def cipher(self) -> tuple[str, str, int]:
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def version(self) -> str:
            return "TLSv1.3"

    class _FakeSocket:
        def __enter__(self) -> "_FakeSocket":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    class _FakeContext:
        def wrap_socket(self, sock, server_hostname=None):
            return _FakeTlsSocket()

    monkeypatch.setattr("scopeguard.tools.tls.socket.create_connection", lambda *args, **kwargs: _FakeSocket())
    monkeypatch.setattr("scopeguard.tools.tls.ssl.create_default_context", lambda: _FakeContext())

    tls_action = SimpleNamespace(tool_id="tls-review", action_id="passive-tls-review", target="https://demo.test/")
    tls_result = review_tls_posture(tls_action, context)

    assert tls_result.parsed_output["protocol"] == "TLSv1.3"
    assert tls_result.parsed_output["certificate"]["subject_alt_names"] == ["demo.test", "www.demo.test"]
    assert tls_result.success is True


def test_tool_result_persistence_and_correlation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PENGETIC_ROOT", str(tmp_path))
    monkeypatch.setenv("PENGETIC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PENGETIC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("PENGETIC_FRONTEND_DIST", str(tmp_path / "frontend-dist"))

    app = create_app()
    store = app.state.store

    scope_yaml = yaml.safe_dump(_scope_payload(name="Correlation Lab", base_url="https://demo.test"), sort_keys=False)
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(scope_yaml, encoding="utf-8")
    scope = load_scope_package(scope_path)
    store.upsert_scope(scope, raw_yaml=scope_yaml, source_path=str(scope_path))
    plan = AssessmentPlanner().build(scope, RuntimeProfile.passive_only)
    store.save_plan(scope, "passive-only", plan, activate=True)
    run = store.create_run(scope, plan, profile="passive-only")

    nmap_result = ToolResult.create(
        tool_id="nmap-service-discovery",
        action_id="active-nmap-service-discovery",
        target="demo.test",
        run_id=run["id"],
        scope_id=run["scope_id"],
        raw_output={"command": ["nmap"], "stdout": "scan", "stderr": ""},
        parsed_output={
            "target_host": "demo.test",
            "services": [
                {
                    "protocol": "tcp",
                    "port": "443",
                    "state": "open",
                    "service": "https",
                    "product": "nginx",
                    "version": "1.24.0",
                }
            ],
            "recommendations": ["Verify SSL configuration and certificate posture for exposed web services."],
        },
        artifacts=[{"kind": "xml", "path": str(tmp_path / "nmap.xml"), "description": "Nmap XML"}],
        findings=[],
        next_safe_checks=["Verify SSL configuration and certificate posture for exposed web services."],
        metadata={"summary": "Nmap service discovery completed."},
    )
    http_result = ToolResult.create(
        tool_id="http-probe",
        action_id="passive-http-probe",
        target="https://demo.test/",
        run_id=run["id"],
        scope_id=run["scope_id"],
        raw_output={"status_code": 200, "headers": {"content-type": "text/html"}},
        parsed_output={
            "status_code": 200,
            "title": "Demo",
            "redirects": [],
            "headers": {"content-type": "text/html"},
            "server": "MockServer/2.0",
        },
        artifacts=[{"kind": "evidence", "path": str(tmp_path / "http.json"), "description": "HTTP probe"}],
        findings=[],
        next_safe_checks=[],
        metadata={"summary": "HTTP probe completed."},
    )

    store.add_tool_result(run["id"], run["scope_id"], nmap_result, action_id=nmap_result.action_id)
    store.add_tool_result(run["id"], run["scope_id"], http_result, action_id=http_result.action_id)

    persisted = store.list_tool_results(run["id"])
    assert {item["tool_id"] for item in persisted} == {"nmap-service-discovery", "http-probe"}

    correlation = store.correlate_tool_results(run["id"])
    assert correlation["service_inventory"][0]["services"][0]["port"] == "443"
    assert correlation["http_probe"][0]["title"] == "Demo"
    assert any("Nmap discovered" in observation for observation in correlation["observations"])
    assert any(path.endswith("http.json") for path in correlation["evidence_refs"])


def test_planner_context_includes_structured_evidence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PENGETIC_ROOT", str(tmp_path))
    monkeypatch.setenv("PENGETIC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PENGETIC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("PENGETIC_FRONTEND_DIST", str(tmp_path / "frontend-dist"))

    app = create_app()
    store = app.state.store

    scope_yaml = yaml.safe_dump(_scope_payload(name="Planner Lab", base_url="https://demo.test"), sort_keys=False)
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(scope_yaml, encoding="utf-8")
    scope = load_scope_package(scope_path)
    store.upsert_scope(scope, raw_yaml=scope_yaml, source_path=str(scope_path))
    plan = AssessmentPlanner().build(scope, RuntimeProfile.passive_only)
    store.save_plan(scope, "passive-only", plan, activate=True)
    run = store.create_run(scope, plan, profile="passive-only")

    evidence_result = ToolResult.create(
        tool_id="http-probe",
        action_id="passive-http-probe",
        target="https://demo.test/",
        run_id=run["id"],
        scope_id=run["scope_id"],
        raw_output={"status_code": 200, "headers": {"content-type": "text/html"}},
        parsed_output={"status_code": 200, "title": "Demo", "redirects": [], "headers": {"content-type": "text/html"}},
        artifacts=[{"kind": "evidence", "path": str(tmp_path / "http.json"), "description": "HTTP probe"}],
        findings=[],
        next_safe_checks=[],
        metadata={"summary": "HTTP probe completed."},
    )
    store.add_tool_result(run["id"], run["scope_id"], evidence_result, action_id=evidence_result.action_id)

    captured: dict[str, object] = {}

    async def fake_suggest(self, context, *, model=None):
        captured["context"] = context
        return PlannerSuggestion(
            model=model or "llama3.1",
            source="ollama",
            summary="Structured evidence review complete.",
            likely_areas_of_concern=["Missing security headers"],
            evidence_references=["/tmp/http.json"],
            next_allowed_step="Review security headers.",
            recommended_action_id=None,
            rationale="The planner can correlate tool results and evidence artifacts.",
            confidence="high",
            raw={"stub": True},
        )

    monkeypatch.setattr("pengetic.api.OllamaPlannerService.suggest", fake_suggest)

    with TestClient(app) as client:
        response = client.post(
            "/api/llm/planner",
            json={
                "run_id": run["id"],
                "scope_id": run["scope_id"],
                "model": "qwen2.5-coder:14b",
            },
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["likely_areas_of_concern"] == ["Missing security headers"]
        assert payload["evidence_references"] == ["/tmp/http.json"]

    context = captured["context"]
    assert context.tool_results
    assert context.correlated_evidence["http_probe"]
    assert context.service_inventory == []
    assert context.header_posture == []
