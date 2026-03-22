from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from ..findings.models import Confidence, Finding, Severity
from .base import ExecutionContext, ToolResult
from .common import make_evidence_name, parse_same_host_paths, scope_base_url
from .http import safe_fetch


def inventory_public_routes(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    base_url = scope_base_url(context)
    base_result = safe_fetch(context, base_url)
    routes: set[str] = {"/"}
    evidence_name = make_evidence_name(context, action.action_id, "routes.json")

    if base_result.body:
        allowed_hosts = set(context.scope.authorized_hosts)
        routes.update(parse_same_host_paths(base_result.body, base_url, allowed_hosts))

    for route in context.scope.login_areas_allowed + context.scope.apis_allowed:
        if route.startswith("http://") or route.startswith("https://"):
            parsed = urlparse(route)
            if parsed.hostname and parsed.hostname.lower() in set(context.scope.authorized_hosts):
                routes.add(parsed.path or "/")
        else:
            routes.add(route if route.startswith("/") else f"/{route}")

    for standard_path in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/favicon.ico"]:
        routes.add(standard_path)

    sorted_routes = sorted(routes)
    findings: list[dict[str, Any]] = []
    sensitive_markers = ("admin", "debug", "internal", "staging", "backup", "test", "console")
    flagged = [route for route in sorted_routes if any(marker in route.lower() for marker in sensitive_markers)]
    if flagged:
        findings.append(
            Finding(
                title="Potentially sensitive routes are publicly discoverable",
                severity=Severity.low,
                confidence=Confidence.medium,
                affected_asset=base_url,
                evidence=[f"Discovered routes with sensitive markers: {', '.join(flagged[:10])}"],
                why_it_matters="Public discovery of route names can make it easier to focus testing on higher-value surfaces.",
                safe_verification_status="Verified passively from visible links, scope routes, or public discovery files.",
                remediation="Review whether the flagged routes should remain publicly linked or indexed.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            ).model_dump()
        )

    evidence_path = context.evidence_store.write_json(
        evidence_name,
        {
            "base_url": base_url,
            "routes": sorted_routes,
            "base_response": base_result.to_dict(),
        },
    )
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=base_url,
        summary=f"Collected {len(sorted_routes)} public route candidates.",
        details={"routes": sorted_routes, "base_response": base_result.to_dict()},
        evidence_paths=[str(evidence_path)],
        findings=findings,
        started_at=started,
        finished_at=datetime.now(UTC),
    )

