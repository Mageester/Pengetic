from __future__ import annotations

from pathlib import Path

import httpx
import yaml

from scopeguard.engine import AssessmentEngine
from scopeguard.scope.loader import load_scope_package


def test_engine_run_produces_report_and_findings(tmp_path: Path) -> None:
    scope_path = tmp_path / "scope.yaml"
    payload = {
        "version": 1,
        "name": "Mocked Demo",
        "primary_domain": "demo.local",
        "base_url": "http://demo.local",
        "allowed_subdomains": [],
        "allowed_urls": ["http://demo.local/"],
        "out_of_scope_assets": [],
        "login_areas_allowed": [],
        "apis_allowed": [],
        "tool_allowlist": [
            "header-review",
            "tls-review",
            "robots-fetch",
            "sitemap-fetch",
            "route-inventory",
            "tech-fingerprint",
            "manual-review",
        ],
        "authorization_note": "Authorized.",
    }
    scope_path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    scope = load_scope_package(scope_path)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers={
                    "Content-Type": "text/html",
                    "Server": "MockServer/1.0",
                    "Set-Cookie": "sessionid=secret123; Path=/; HttpOnly",
                },
                text="<html><head><meta name='generator' content='MockCMS'></head><body><a href='/dashboard'>Dashboard</a></body></html>",
            )
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /admin\n")
        if request.url.path == "/sitemap.xml":
            return httpx.Response(200, text="<urlset><url><loc>http://demo.local/dashboard</loc></url></urlset>")
        if request.url.path in {"/.well-known/security.txt", "/favicon.ico"}:
            return httpx.Response(404, text="Not found")
        return httpx.Response(404, text="Not found")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    engine = AssessmentEngine(
        scope,
        artifacts_root=tmp_path / "artifacts",
        http_client=client,
    )

    summary = engine.run()

    assert summary.report_path.exists()
    assert summary.findings
    assert any(outcome.status == "executed" for outcome in summary.outcomes)
    report_text = summary.report_path.read_text(encoding="utf-8")
    assert "Mocked Demo" in report_text
    assert "Missing HSTS header" in report_text or "Server banner is exposed" in report_text

