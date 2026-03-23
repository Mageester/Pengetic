from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..findings.models import Confidence, Finding, Severity
from .base import ExecutionContext, FindingCandidate, ToolArtifact, ToolResult
from .common import make_evidence_name, scope_base_url
from .http import safe_fetch


def _cookie_flags(cookie: str) -> dict[str, Any]:
    lower = cookie.lower()
    return {
        "cookie": cookie,
        "secure": "secure" in lower,
        "httponly": "httponly" in lower,
        "samesite": "samesite" in lower,
    }


def review_security_headers(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    result = safe_fetch(context, scope_base_url(context))
    evidence_name = make_evidence_name(context, action.action_id, "headers.json")

    headers = result.headers
    security_headers = {
        "strict-transport-security": headers.get("strict-transport-security"),
        "content-security-policy": headers.get("content-security-policy"),
        "x-frame-options": headers.get("x-frame-options"),
        "permissions-policy": headers.get("permissions-policy"),
        "referrer-policy": headers.get("referrer-policy"),
        "x-content-type-options": headers.get("x-content-type-options"),
    }
    cookie_flags = [_cookie_flags(cookie) for cookie in result.set_cookie_headers]
    cors = {
        "access-control-allow-origin": headers.get("access-control-allow-origin"),
        "access-control-allow-credentials": headers.get("access-control-allow-credentials"),
        "access-control-allow-methods": headers.get("access-control-allow-methods"),
        "access-control-allow-headers": headers.get("access-control-allow-headers"),
    }
    parsed_output = {
        "requested_url": result.requested_url,
        "final_url": result.final_url,
        "status_code": result.status_code,
        "security_headers": security_headers,
        "cookie_flags": cookie_flags,
        "cors": cors,
        "server_banner": headers.get("server"),
        "redirects": result.redirects,
        "content_type": headers.get("content-type"),
    }
    raw_output = result.to_dict()
    findings: list[FindingCandidate] = []

    if result.final_url.startswith("https://") and not security_headers["strict-transport-security"]:
        findings.append(
            FindingCandidate(
                title="Missing HSTS header",
                severity=Severity.medium.value,
                confidence=Confidence.high.value,
                affected_asset=result.final_url,
                evidence=["strict-transport-security header was not present in the response headers."],
                why_it_matters="Browsers will not be instructed to prefer HTTPS for this host, increasing downgrade risk.",
                safe_verification_status="Verified passively by inspecting response headers.",
                remediation="Add a Strict-Transport-Security header with an appropriate max-age and includeSubDomains if appropriate.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            )
        )
    if not security_headers["content-security-policy"]:
        findings.append(
            FindingCandidate(
                title="Content Security Policy not present",
                severity=Severity.low.value,
                confidence=Confidence.high.value,
                affected_asset=result.final_url,
                evidence=["No content-security-policy header was observed."],
                why_it_matters="CSP reduces the blast radius of client-side injection bugs and limits unexpected script execution.",
                safe_verification_status="Verified passively by inspecting response headers.",
                remediation="Deploy a CSP that reflects the application's script, frame, and connect requirements.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            )
        )
    if not security_headers["x-frame-options"] and not security_headers["content-security-policy"]:
        findings.append(
            FindingCandidate(
                title="Clickjacking defense not evident in headers",
                severity=Severity.low.value,
                confidence=Confidence.medium.value,
                affected_asset=result.final_url,
                evidence=["Neither x-frame-options nor a frame-ancestors CSP directive was observed."],
                why_it_matters="Embedding protections are absent or not visible from the passive sample, which can leave sensitive actions exposed to clickjacking.",
                safe_verification_status="Verified passively by inspecting response headers.",
                remediation="Set X-Frame-Options or, preferably, a frame-ancestors directive in CSP.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            )
        )
    if cookie_flags:
        insecure_cookies = [cookie for cookie in cookie_flags if not (cookie["secure"] and cookie["httponly"] and cookie["samesite"])]
        if insecure_cookies:
            findings.append(
                FindingCandidate(
                    title="Cookie security flags not fully set",
                    severity=Severity.medium.value,
                    confidence=Confidence.medium.value,
                    affected_asset=result.final_url,
                    evidence=[f"Observed cookie headers without Secure/HttpOnly/SameSite coverage: {len(insecure_cookies)}"],
                    why_it_matters="Session cookies without defensive flags are more likely to leak or be abused by client-side attacks.",
                    safe_verification_status="Verified passively from the response headers.",
                    remediation="Set Secure, HttpOnly, and SameSite on session-bearing cookies where compatible.",
                    source_tool=action.tool_id,
                    source_action_id=action.action_id,
                )
            )
    if headers.get("server"):
        findings.append(
            FindingCandidate(
                title="Server banner is exposed",
                severity=Severity.informational.value,
                confidence=Confidence.high.value,
                affected_asset=result.final_url,
                evidence=[f"Server: {headers['server']}"],
                why_it_matters="Banner disclosure increases stack fingerprinting accuracy for an external observer.",
                safe_verification_status="Verified passively by inspecting response headers.",
                remediation="Trim banner detail where operationally safe.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            )
        )
    if not security_headers["permissions-policy"]:
        findings.append(
            FindingCandidate(
                title="Permissions-Policy header not present",
                severity=Severity.informational.value,
                confidence=Confidence.medium.value,
                affected_asset=result.final_url,
                evidence=["No permissions-policy header was observed."],
                why_it_matters="A Permissions-Policy header reduces the browser feature surface available to embedded content and scripts.",
                safe_verification_status="Verified passively by inspecting response headers.",
                remediation="Add a Permissions-Policy header aligned to the app's browser feature needs.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            )
        )

    summary = "Reviewed security headers for the base URL response."
    if result.error:
        summary = f"Header review completed with fetch error: {result.error}"
    parsed_path = context.evidence_store.write_json(f"{evidence_name}.parsed.json", parsed_output)
    raw_path = context.evidence_store.write_json(f"{evidence_name}.raw.json", raw_output)
    artifacts = [
        ToolArtifact(kind="evidence", path=str(raw_path), description="Raw header review output"),
        ToolArtifact(kind="evidence", path=str(parsed_path), description="Parsed header review summary"),
    ]
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=action.target,
        run_id=context.run_id,
        scope_id=context.scope_fingerprint,
        status="success" if not result.error else "partial",
        raw_output=raw_output,
        parsed_output=parsed_output,
        artifacts=artifacts,
        findings_candidates=findings,
        next_safe_checks=[
            "Compare header posture with the HTTP probe and TLS posture for a coherent evidence picture.",
        ],
        metadata={
            "summary": summary,
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
        | ({"error": result.error} if result.error else {}),
        started_at=started,
        finished_at=datetime.now(UTC),
    )
