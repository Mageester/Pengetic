from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..findings.models import Confidence, Finding, Severity
from .base import ExecutionContext, ToolResult
from .common import LinkExtractor, make_evidence_name, scope_base_url
from .http import safe_fetch


def fingerprint_technology(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    base_url = scope_base_url(context)
    result = safe_fetch(context, base_url)
    evidence_name = make_evidence_name(context, action.action_id, "fingerprint.json")
    html = result.body or ""
    headers = result.headers
    findings: list[dict[str, Any]] = []
    signals: list[str] = []

    for header_name in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
        if header_name in headers:
            signals.append(f"{header_name}: {headers[header_name]}")

    parser = LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    for meta_name, values in parser.meta.items():
        if meta_name in {"generator", "framework", "application-name"}:
            signals.extend(f"meta {meta_name}: {value}" for value in values)

    lowered = html.lower()
    for label, marker in {
        "wordpress": "wordpress",
        "drupal": "drupal",
        "django": "django",
        "next.js": "next",
        "nuxt": "nuxt",
        "vue": "vue",
        "react": "react",
        "angular": "angular",
        "svelte": "svelte",
        "laravel": "laravel",
        "express": "express",
        "rails": "rails",
    }.items():
        if marker in lowered:
            signals.append(f"body marker: {label}")

    if signals:
        findings.append(
            Finding(
                title="Technology stack identifiers are exposed",
                severity=Severity.informational,
                confidence=Confidence.high,
                affected_asset=base_url,
                evidence=signals[:10],
                why_it_matters="Technology fingerprints improve an observer's ability to tailor follow-up testing and exploit selection.",
                safe_verification_status="Verified passively from headers and response content.",
                remediation="Minimize non-essential version and framework disclosures where feasible.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            ).model_dump()
        )

    evidence_path = context.evidence_store.write_json(
        evidence_name,
        {
            "response": result.to_dict(),
            "signals": signals,
        },
    )
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=base_url,
        summary="Derived passive technology fingerprints from headers and content.",
        details={"signals": signals, "response": result.to_dict()},
        evidence_paths=[str(evidence_path)],
        findings=findings,
        started_at=started,
        finished_at=datetime.now(UTC),
    )

