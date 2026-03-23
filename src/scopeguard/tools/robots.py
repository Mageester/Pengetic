from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin

from ..findings.models import Confidence, Finding, Severity
from .base import ExecutionContext, FindingCandidate, ToolArtifact, ToolResult
from .common import make_evidence_name, scope_base_url
from .http import safe_fetch


def review_robots_txt(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    robots_url = urljoin(scope_base_url(context), "/robots.txt")
    result = safe_fetch(context, robots_url)
    evidence_name = make_evidence_name(context, action.action_id, "robots.txt")
    disallows = [line.strip() for line in result.body.splitlines() if line.lower().startswith("disallow:")]
    findings: list[FindingCandidate] = []

    if result.status_code == 200 and disallows:
        findings.append(
            FindingCandidate(
                title="robots.txt discloses private paths",
                severity=Severity.informational.value,
                confidence=Confidence.high.value,
                affected_asset=robots_url,
                evidence=[f"Disallow entries: {', '.join(disallows[:10])}"],
                why_it_matters="robots.txt is public and may disclose path names that can help an attacker map sensitive sections.",
                safe_verification_status="Verified passively from robots.txt.",
                remediation="Keep robots directives minimal and avoid listing sensitive paths unless required.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            )
        )

    parsed_output = {
        "url": robots_url,
        "status_code": result.status_code,
        "disallow_entries": disallows,
        "redirects": result.redirects,
        "headers": result.headers,
    }
    raw_output = result.to_dict()
    raw_path = context.evidence_store.write_text(evidence_name, result.body or "")
    parsed_path = context.evidence_store.write_json(f"{evidence_name}.parsed.json", parsed_output)
    summary = "Fetched robots.txt."
    if result.error:
        summary = f"robots.txt fetch error: {result.error}"
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=robots_url,
        run_id=context.run_id,
        scope_id=context.scope_fingerprint,
        status="success" if result.error is None else "partial",
        raw_output=raw_output,
        parsed_output=parsed_output,
        artifacts=[
            ToolArtifact(kind="evidence", path=str(raw_path), description="Raw robots.txt body"),
            ToolArtifact(kind="evidence", path=str(parsed_path), description="Parsed robots.txt summary"),
        ],
        findings_candidates=findings,
        next_safe_checks=["Compare robots.txt disclosures with sitemap and route inventory."],
        metadata={
            "summary": summary,
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        },
        started_at=started,
        finished_at=datetime.now(UTC),
    )
