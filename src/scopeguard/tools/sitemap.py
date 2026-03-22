from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin
import re

from ..findings.models import Confidence, Finding, Severity
from .base import ExecutionContext, ToolResult
from .common import make_evidence_name, scope_base_url
from .http import safe_fetch


def review_sitemap_xml(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    sitemap_url = urljoin(scope_base_url(context), "/sitemap.xml")
    result = safe_fetch(context, sitemap_url)
    evidence_name = make_evidence_name(context, action.action_id, "sitemap.xml")
    findings: list[dict[str, Any]] = []
    summary = "Fetched sitemap.xml."

    if result.status_code == 200 and result.body:
        route_count = len(re.findall(r"<loc>(.*?)</loc>", result.body, flags=re.I | re.S))
        if route_count:
            findings.append(
                Finding(
                    title="Sitemap exposes route inventory",
                    severity=Severity.informational,
                    confidence=Confidence.high,
                    affected_asset=sitemap_url,
                    evidence=[f"sitemap.xml contains approximately {route_count} URL entries."],
                    why_it_matters="Sitemaps intentionally expose public URLs and can reveal routes that are not linked elsewhere.",
                    safe_verification_status="Verified passively from sitemap.xml.",
                    remediation="No remediation is needed if the sitemap is intended for public discovery.",
                    source_tool=action.tool_id,
                    source_action_id=action.action_id,
                ).model_dump()
            )
    if result.error:
        summary = f"sitemap.xml fetch error: {result.error}"

    evidence_path = context.evidence_store.write_text(evidence_name, result.body or "")
    context.evidence_store.write_json(f"{evidence_name}.json", result.to_dict())
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=sitemap_url,
        summary=summary,
        details={"response": result.to_dict()},
        evidence_paths=[str(evidence_path)],
        findings=findings,
        started_at=started,
        finished_at=datetime.now(UTC),
    )

