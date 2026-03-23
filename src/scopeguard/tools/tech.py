from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..findings.models import Confidence, Finding, Severity
from .base import ExecutionContext, FindingCandidate, ToolArtifact, ToolResult
from .common import LinkExtractor, make_evidence_name, scope_base_url
from .http import safe_fetch


def fingerprint_technology(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    base_url = scope_base_url(context)
    result = safe_fetch(context, base_url)
    evidence_name = make_evidence_name(context, action.action_id, "fingerprint.json")
    html = result.body or ""
    headers = result.headers
    findings: list[FindingCandidate] = []
    signals: list[str] = []
    header_signals: dict[str, str] = {}

    for header_name in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
        if header_name in headers:
            header_signals[header_name] = headers[header_name]
            signals.append(f"{header_name}: {headers[header_name]}")

    parser = LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    for meta_name, values in parser.meta.items():
        if meta_name in {"generator", "framework", "application-name"}:
            for value in values:
                signals.append(f"meta {meta_name}: {value}")

    lowered = html.lower()
    body_markers: list[str] = []
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
            body_markers.append(label)
            signals.append(f"body marker: {label}")

    if signals:
        findings.append(
            FindingCandidate(
                title="Technology stack identifiers are exposed",
                severity=Severity.informational.value,
                confidence=Confidence.high.value,
                affected_asset=base_url,
                evidence=signals[:10],
                why_it_matters="Technology fingerprints improve an observer's ability to tailor follow-up testing and exploit selection.",
                safe_verification_status="Verified passively from headers and response content.",
                remediation="Minimize non-essential version and framework disclosures where feasible.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            )
        )

    parsed_output = {
        "response": result.to_dict(),
        "signals": signals,
        "header_signals": header_signals,
        "meta_signals": parser.meta,
        "body_markers": body_markers,
    }
    raw_output = {
        "response": result.to_dict(),
        "html": html,
    }
    raw_path = context.evidence_store.write_json(f"{evidence_name}.raw.json", raw_output)
    parsed_path = context.evidence_store.write_json(f"{evidence_name}.parsed.json", parsed_output)
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=base_url,
        run_id=context.run_id,
        scope_id=context.scope_fingerprint,
        status="success" if result.error is None else "partial",
        raw_output=raw_output,
        parsed_output=parsed_output,
        artifacts=[
            ToolArtifact(kind="evidence", path=str(raw_path), description="Raw technology fingerprint output"),
            ToolArtifact(kind="evidence", path=str(parsed_path), description="Parsed technology fingerprint summary"),
        ],
        findings_candidates=findings,
        next_safe_checks=["Compare technology fingerprints with service inventory and header posture."],
        metadata={
            "summary": "Derived passive technology fingerprints from headers and content.",
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        },
        started_at=started,
        finished_at=datetime.now(UTC),
    )
