from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin
import re

from ..findings.models import Confidence, Finding, Severity
from .base import ExecutionContext, FindingCandidate, ToolArtifact, ToolResult
from .common import make_evidence_name, scope_base_url
from .http import safe_fetch


def review_sitemap_xml(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    sitemap_url = urljoin(scope_base_url(context), "/sitemap.xml")
    result = safe_fetch(context, sitemap_url)
    evidence_name = make_evidence_name(context, action.action_id, "sitemap.xml")
    findings: list[FindingCandidate] = []
    route_count = 0
    if result.status_code == 200 and result.body:
        route_count = len(re.findall(r"<loc>(.*?)</loc>", result.body, flags=re.I | re.S))
        if route_count:
            findings.append(
                FindingCandidate(
                    title="Sitemap exposes route inventory",
                    severity=Severity.informational.value,
                    confidence=Confidence.high.value,
                    affected_asset=sitemap_url,
                    evidence=[f"sitemap.xml contains approximately {route_count} URL entries."],
                    why_it_matters="Sitemaps intentionally expose public URLs and can reveal routes that are not linked elsewhere.",
                    safe_verification_status="Verified passively from sitemap.xml.",
                    remediation="No remediation is needed if the sitemap is intended for public discovery.",
                    source_tool=action.tool_id,
                    source_action_id=action.action_id,
                )
            )

    parsed_output = {
        "url": sitemap_url,
        "status_code": result.status_code,
        "route_count": route_count,
        "redirects": result.redirects,
        "headers": result.headers,
    }
    raw_output = result.to_dict()
    raw_path = context.evidence_store.write_text(evidence_name, result.body or "")
    parsed_path = context.evidence_store.write_json(f"{evidence_name}.parsed.json", parsed_output)
    summary = "Fetched sitemap.xml."
    if result.error:
        summary = f"sitemap.xml fetch error: {result.error}"
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=sitemap_url,
        run_id=context.run_id,
        scope_id=context.scope_fingerprint,
        status="success" if result.error is None else "partial",
        raw_output=raw_output,
        parsed_output=parsed_output,
        artifacts=[
            ToolArtifact(kind="evidence", path=str(raw_path), description="Raw sitemap.xml body"),
            ToolArtifact(kind="evidence", path=str(parsed_path), description="Parsed sitemap.xml summary"),
        ],
        findings_candidates=findings,
        next_safe_checks=["Cross-reference sitemap routes with the route inventory and HTTP probe."],
        metadata={
            "summary": summary,
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        },
        started_at=started,
        finished_at=datetime.now(UTC),
    )
