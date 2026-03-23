from __future__ import annotations

from datetime import UTC, datetime, timezone
from typing import Any
from urllib.parse import urlparse
import socket
import ssl

from ..findings.models import Confidence, Finding, Severity
from .base import ExecutionContext, FindingCandidate, ToolArtifact, ToolResult
from .common import make_evidence_name


def _certificate_posture(certificate: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(certificate, dict):
        return {"certificate": certificate}
    san_dns = [entry[1] for entry in certificate.get("subjectAltName", []) if isinstance(entry, tuple) and entry and entry[0] == "DNS"]
    issuer = certificate.get("issuer")
    issuer_text = None
    if isinstance(issuer, tuple):
        issuer_parts: list[str] = []
        for group in issuer:
            if not isinstance(group, tuple):
                continue
            for item in group:
                if isinstance(item, tuple) and len(item) == 2:
                    issuer_parts.append(f"{item[0]}={item[1]}")
        issuer_text = ", ".join(issuer_parts) or None
    return {
        "subject": certificate.get("subject"),
        "issuer": issuer_text or issuer,
        "not_before": certificate.get("notBefore"),
        "not_after": certificate.get("notAfter"),
        "subject_alt_names": san_dns,
        "serial_number": certificate.get("serialNumber"),
    }


def review_tls_posture(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    url = str(context.scope.base_url)
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    evidence_name = make_evidence_name(context, action.action_id, "tls.json")
    findings: list[FindingCandidate] = []
    parsed_output: dict[str, Any] = {"host": host, "port": port, "scheme": parsed.scheme}

    if parsed.scheme != "https":
        parsed_output["note"] = "TLS review skipped because the base URL does not use HTTPS."
        raw_output = {"note": parsed_output["note"], "url": url}
        raw_path = context.evidence_store.write_json(f"{evidence_name}.raw.json", raw_output)
        parsed_path = context.evidence_store.write_json(f"{evidence_name}.parsed.json", parsed_output)
        return ToolResult.create(
            tool_id=action.tool_id,
            action_id=action.action_id,
            target=url,
            run_id=context.run_id,
            scope_id=context.scope_fingerprint,
            status="skipped",
            raw_output=raw_output,
            parsed_output=parsed_output,
            artifacts=[
                ToolArtifact(kind="evidence", path=str(raw_path), description="Raw TLS posture note"),
                ToolArtifact(kind="evidence", path=str(parsed_path), description="Parsed TLS posture summary"),
            ],
            findings_candidates=findings,
            next_safe_checks=["Enable HTTPS and repeat the TLS posture review."],
            metadata={
                "summary": "TLS review skipped for a non-HTTPS base URL.",
                "started_at": started.isoformat().replace("+00:00", "Z"),
                "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            },
            started_at=started,
            finished_at=datetime.now(UTC),
        )

    try:
        client_context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with client_context.wrap_socket(sock, server_hostname=host) as tls_sock:
                certificate = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                protocol = tls_sock.version()
                parsed_output.update(
                    {
                        "cipher": cipher[0] if cipher else None,
                        "protocol": protocol,
                        "certificate": _certificate_posture(certificate),
                    }
                )
                if protocol and protocol not in {"TLSv1.2", "TLSv1.3"}:
                    findings.append(
                        FindingCandidate(
                            title="Legacy TLS protocol negotiated",
                            severity=Severity.high.value,
                            confidence=Confidence.high.value,
                            affected_asset=url,
                            evidence=[f"Negotiated protocol: {protocol}"],
                            why_it_matters="Older TLS versions weaken transport security and may lack modern protections.",
                            safe_verification_status="Verified passively via TLS handshake metadata.",
                            remediation="Disable legacy TLS versions and require TLS 1.2 or newer.",
                            source_tool=action.tool_id,
                            source_action_id=action.action_id,
                        )
                    )
                not_after = certificate.get("notAfter") if isinstance(certificate, dict) else None
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    delta_days = (expiry - datetime.now(timezone.utc)).days
                    if delta_days <= 30:
                        findings.append(
                            FindingCandidate(
                                title="TLS certificate expires soon",
                                severity=Severity.medium.value,
                                confidence=Confidence.high.value,
                                affected_asset=url,
                                evidence=[f"Certificate expiry: {not_after}"],
                                why_it_matters="Certificates nearing expiry can lead to service disruption and weaken operational trust.",
                                safe_verification_status="Verified passively via certificate metadata.",
                                remediation="Renew the certificate before expiry and monitor renewal windows.",
                                source_tool=action.tool_id,
                                source_action_id=action.action_id,
                            )
                        )
    except Exception as exc:
        parsed_output["error"] = str(exc)

    raw_output = {
        "host": host,
        "port": port,
        "scheme": parsed.scheme,
        "parsed": parsed_output,
    }
    raw_path = context.evidence_store.write_json(f"{evidence_name}.raw.json", raw_output)
    parsed_path = context.evidence_store.write_json(f"{evidence_name}.parsed.json", parsed_output)
    summary = "Reviewed TLS handshake posture."
    if "error" in parsed_output:
        summary = f"TLS posture review encountered an error: {parsed_output['error']}"
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=url,
        run_id=context.run_id,
        scope_id=context.scope_fingerprint,
        status="success" if "error" not in parsed_output else "partial",
        raw_output=raw_output,
        parsed_output=parsed_output,
        artifacts=[
            ToolArtifact(kind="evidence", path=str(raw_path), description="Raw TLS posture output"),
            ToolArtifact(kind="evidence", path=str(parsed_path), description="Parsed TLS posture summary"),
        ],
        findings_candidates=findings,
        next_safe_checks=[
            "Compare TLS posture with the HTTP probe and header analysis results.",
        ],
        metadata={
            "summary": summary,
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        },
        started_at=started,
        finished_at=datetime.now(UTC),
    )
