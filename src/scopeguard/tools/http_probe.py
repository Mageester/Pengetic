from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
import re

from ..findings.models import Confidence, Finding, Severity
from .base import ExecutionContext, FindingCandidate, ToolArtifact, ToolResult
from .common import LinkExtractor, make_evidence_name, scope_base_url
from .http import safe_fetch


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(html: str) -> str | None:
    match = _TITLE_RE.search(html or "")
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip() or None


def probe_http_surface(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    base_url = scope_base_url(context)
    result = safe_fetch(context, base_url)
    evidence_name = make_evidence_name(context, action.action_id, "http.json")

    parser = LinkExtractor()
    try:
        parser.feed(result.body or "")
    except Exception:
        pass

    title = _extract_title(result.body or "")
    content_type = result.headers.get("content-type")
    server = result.headers.get("server")
    parsed_output = {
        "requested_url": result.requested_url,
        "final_url": result.final_url,
        "status_code": result.status_code,
        "redirects": result.redirects,
        "headers": result.headers,
        "set_cookie_headers": result.set_cookie_headers,
        "content_type": content_type,
        "server": server,
        "title": title,
        "forms": parser.forms,
        "meta": parser.meta,
    }
    raw_output = result.to_dict()
    findings: list[FindingCandidate] = []
    next_safe_checks: list[str] = []

    if result.redirects:
        next_safe_checks.append("Review redirect targets and ensure the final landing page is intentional.")
    if title is None:
        findings.append(
            FindingCandidate(
                title="Page title not detected",
                severity=Severity.informational.value,
                confidence=Confidence.medium.value,
                affected_asset=result.final_url,
                evidence=["No <title> element was found in the fetched HTML."],
                why_it_matters="A missing title can indicate a minimal surface or a non-HTML response that deserves further review.",
                safe_verification_status="Verified passively from the fetched HTML response.",
                remediation="If this is an HTML page, add a descriptive title for usability and operator clarity.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            )
        )
    if parser.forms:
        next_safe_checks.append("Review form actions and inputs during route and login-surface analysis.")

    evidence_path = context.evidence_store.write_json(f"{evidence_name}.raw.json", raw_output)
    parsed_path = context.evidence_store.write_json(f"{evidence_name}.parsed.json", parsed_output)
    artifacts = [
        ToolArtifact(kind="evidence", path=str(evidence_path), description="Raw HTTP probe output"),
        ToolArtifact(kind="evidence", path=str(parsed_path), description="Parsed HTTP probe summary"),
    ]
    metadata = {
        "summary": "Captured HTTP response metadata for the base URL.",
        "content_type": content_type,
        "server": server,
        "forms": len(parser.forms),
        "redirect_count": len(result.redirects),
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=base_url,
        run_id=context.run_id,
        scope_id=context.scope_fingerprint,
        status="success" if result.error is None else "partial",
        raw_output=raw_output,
        parsed_output=parsed_output,
        artifacts=artifacts,
        findings_candidates=findings,
        next_safe_checks=next_safe_checks,
        metadata=metadata | ({"error": result.error} if result.error else {}),
        started_at=started,
        finished_at=datetime.now(UTC),
    )
