from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin

from ..findings.models import Confidence, Finding, Severity
from .base import ExecutionContext, ToolResult
from .common import make_evidence_name, scope_base_url
from .http import safe_fetch


def review_robots_txt(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    robots_url = urljoin(scope_base_url(context), "/robots.txt")
    result = safe_fetch(context, robots_url)
    evidence_name = make_evidence_name(context, action.action_id, "robots.txt")
    findings: list[dict[str, Any]] = []

    if result.status_code == 200 and result.body:
        disallows = [line.strip() for line in result.body.splitlines() if line.lower().startswith("disallow:")]
        if disallows:
            findings.append(
                Finding(
                    title="robots.txt discloses private paths",
                    severity=Severity.informational,
                    confidence=Confidence.high,
                    affected_asset=robots_url,
                    evidence=[f"Disallow entries: {', '.join(disallows[:10])}"],
                    why_it_matters="robots.txt is public and may disclose path names that can help an attacker map sensitive sections.",
                    safe_verification_status="Verified passively from robots.txt.",
                    remediation="Keep robots directives minimal and avoid listing sensitive paths unless required.",
                    source_tool=action.tool_id,
                    source_action_id=action.action_id,
                ).model_dump()
            )

    evidence_path = context.evidence_store.write_text(evidence_name, result.body or "")
    context.evidence_store.write_json(f"{evidence_name}.json", result.to_dict())
    summary = "Fetched robots.txt."
    if result.error:
        summary = f"robots.txt fetch error: {result.error}"
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=robots_url,
        summary=summary,
        details={"response": result.to_dict()},
        evidence_paths=[str(evidence_path)],
        findings=findings,
        started_at=started,
        finished_at=datetime.now(UTC),
    )

