from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from ..findings.models import Confidence, Finding, Severity
from .base import ExecutionContext, FindingCandidate, ToolArtifact, ToolResult
from .common import LinkExtractor, make_evidence_name, parse_same_host_paths, scope_base_url
from .http import safe_fetch


def inventory_public_routes(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    base_url = scope_base_url(context)
    base_result = safe_fetch(context, base_url)
    evidence_name = make_evidence_name(context, action.action_id, "routes.json")

    routes: set[str] = {"/"}
    source_links: list[str] = []
    source_forms: list[str] = []
    parser = LinkExtractor()
    try:
        parser.feed(base_result.body or "")
    except Exception:
        pass

    allowed_hosts = set(context.scope.authorized_hosts)
    if base_result.body:
        source_links = sorted(parser.links)
        source_forms = sorted(parser.forms)
        routes.update(parse_same_host_paths(base_result.body, base_url, allowed_hosts))

    for route in context.scope.login_areas_allowed + context.scope.apis_allowed:
        if route.startswith("http://") or route.startswith("https://"):
            parsed = urlparse(route)
            if parsed.hostname and parsed.hostname.lower() in allowed_hosts:
                routes.add(parsed.path or "/")
        else:
            routes.add(route if route.startswith("/") else f"/{route}")

    discovery_paths = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/favicon.ico"]
    routes.update(discovery_paths)

    sorted_routes = sorted(routes)
    sensitive_markers = ("admin", "debug", "internal", "staging", "backup", "test", "console")
    flagged = [route for route in sorted_routes if any(marker in route.lower() for marker in sensitive_markers)]
    findings: list[FindingCandidate] = []
    if flagged:
        findings.append(
            FindingCandidate(
                title="Potentially sensitive routes are publicly discoverable",
                severity=Severity.low.value,
                confidence=Confidence.medium.value,
                affected_asset=base_url,
                evidence=[f"Discovered routes with sensitive markers: {', '.join(flagged[:10])}"],
                why_it_matters="Public discovery of route names can make it easier to focus testing on higher-value surfaces.",
                safe_verification_status="Verified passively from visible links, scope routes, or public discovery files.",
                remediation="Review whether the flagged routes should remain publicly linked or indexed.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            )
        )

    parsed_output = {
        "base_url": base_url,
        "routes": sorted_routes,
        "source_links": source_links,
        "source_forms": source_forms,
        "base_response": base_result.to_dict(),
        "discovery_paths": discovery_paths,
        "sensitive_markers": flagged,
    }
    raw_output = {
        "base_response": base_result.to_dict(),
        "html": base_result.body,
    }
    raw_path = context.evidence_store.write_json(f"{evidence_name}.raw.json", raw_output)
    parsed_path = context.evidence_store.write_json(f"{evidence_name}.parsed.json", parsed_output)
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=base_url,
        run_id=context.run_id,
        scope_id=context.scope_fingerprint,
        status="success" if base_result.error is None else "partial",
        raw_output=raw_output,
        parsed_output=parsed_output,
        artifacts=[
            ToolArtifact(kind="evidence", path=str(raw_path), description="Raw route inventory output"),
            ToolArtifact(kind="evidence", path=str(parsed_path), description="Parsed route inventory summary"),
        ],
        findings_candidates=findings,
        next_safe_checks=[
            "Use the route inventory to prioritize header, login-surface, and API review.",
        ],
        metadata={
            "summary": f"Collected {len(sorted_routes)} public route candidates.",
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        },
        started_at=started,
        finished_at=datetime.now(UTC),
    )
