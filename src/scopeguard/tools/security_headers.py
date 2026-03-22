from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..findings.models import Confidence, Finding, Severity
from .base import ExecutionContext, ToolResult
from .common import make_evidence_name, scope_base_url
from .http import safe_fetch


def review_security_headers(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    result = safe_fetch(context, scope_base_url(context))
    findings: list[dict[str, Any]] = []
    evidence_name = make_evidence_name(context, action.action_id, "headers.json")

    headers = result.headers
    if result.final_url.startswith("https://") and "strict-transport-security" not in headers:
        findings.append(
            Finding(
                title="Missing HSTS header",
                severity=Severity.medium,
                confidence=Confidence.high,
                affected_asset=result.final_url,
                evidence=["strict-transport-security header was not present in the response headers."],
                why_it_matters="Browsers will not be instructed to prefer HTTPS for this host, increasing downgrade risk.",
                safe_verification_status="Verified passively by inspecting response headers.",
                remediation="Add a Strict-Transport-Security header with an appropriate max-age and includeSubDomains if appropriate.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            ).model_dump()
        )
    if "content-security-policy" not in headers:
        findings.append(
            Finding(
                title="Content Security Policy not present",
                severity=Severity.low,
                confidence=Confidence.high,
                affected_asset=result.final_url,
                evidence=["No content-security-policy header was observed."],
                why_it_matters="CSP reduces the blast radius of client-side injection bugs and limits unexpected script execution.",
                safe_verification_status="Verified passively by inspecting response headers.",
                remediation="Deploy a CSP that reflects the application's script, frame, and connect requirements.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            ).model_dump()
        )
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        findings.append(
            Finding(
                title="Clickjacking defense not evident in headers",
                severity=Severity.low,
                confidence=Confidence.medium,
                affected_asset=result.final_url,
                evidence=["Neither x-frame-options nor a frame-ancestors CSP directive was observed."],
                why_it_matters="Embedding protections are absent or not visible from the passive sample, which can leave sensitive actions exposed to clickjacking.",
                safe_verification_status="Verified passively by inspecting response headers.",
                remediation="Set X-Frame-Options or, preferably, a frame-ancestors directive in CSP.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            ).model_dump()
        )
    set_cookie_headers = result.set_cookie_headers
    if set_cookie_headers:
        insecure_cookies = []
        for cookie in set_cookie_headers:
            lower = cookie.lower()
            if "secure" not in lower or "httponly" not in lower or "samesite" not in lower:
                insecure_cookies.append(cookie)
        if insecure_cookies:
            findings.append(
                Finding(
                    title="Cookie security flags not fully set",
                    severity=Severity.medium,
                    confidence=Confidence.medium,
                    affected_asset=result.final_url,
                    evidence=[f"Observed cookie headers without Secure/HttpOnly/SameSite coverage: {len(insecure_cookies)}"],
                    why_it_matters="Session cookies without defensive flags are more likely to leak or be abused by client-side attacks.",
                    safe_verification_status="Verified passively from the response headers.",
                    remediation="Set Secure, HttpOnly, and SameSite on session-bearing cookies where compatible.",
                    source_tool=action.tool_id,
                    source_action_id=action.action_id,
                ).model_dump()
            )
    if "server" in headers:
        findings.append(
            Finding(
                title="Server banner is exposed",
                severity=Severity.informational,
                confidence=Confidence.high,
                affected_asset=result.final_url,
                evidence=[f"Server: {headers['server']}"],
                why_it_matters="Banner disclosure increases stack fingerprinting accuracy for an external observer.",
                safe_verification_status="Verified passively by inspecting response headers.",
                remediation="Trim banner detail where operationally safe.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            ).model_dump()
        )
    if "permissions-policy" not in headers:
        findings.append(
            Finding(
                title="Permissions-Policy header not present",
                severity=Severity.informational,
                confidence=Confidence.medium,
                affected_asset=result.final_url,
                evidence=["No permissions-policy header was observed."],
                why_it_matters="A Permissions-Policy header reduces the browser feature surface available to embedded content and scripts.",
                safe_verification_status="Verified passively by inspecting response headers.",
                remediation="Add a Permissions-Policy header aligned to the app's browser feature needs.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            ).model_dump()
        )

    summary = "Reviewed security headers for the base URL response."
    if result.error:
        summary = f"Header review completed with fetch error: {result.error}"
    evidence_path = context.evidence_store.write_json(
        evidence_name,
        {
            "requested_url": result.requested_url,
            "final_url": result.final_url,
            "status_code": result.status_code,
            "headers": result.headers,
            "set_cookie_headers": result.set_cookie_headers,
        },
    )
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=action.target,
        summary=summary,
        details={"response": result.to_dict()},
        evidence_paths=[str(evidence_path)],
        findings=findings,
        started_at=started,
        finished_at=datetime.now(UTC),
    )
