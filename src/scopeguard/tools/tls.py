from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse
import socket
import ssl

from ..findings.models import Confidence, Finding, Severity
from .base import ExecutionContext, ToolResult
from .common import make_evidence_name


def review_tls_posture(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    url = str(context.scope.base_url)
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    evidence_name = make_evidence_name(context, action.action_id, "tls.json")
    findings: list[dict[str, Any]] = []
    details: dict[str, Any] = {"host": host, "port": port, "scheme": parsed.scheme}

    if parsed.scheme != "https":
        details["note"] = "TLS review skipped because the base URL does not use HTTPS."
        evidence_path = context.evidence_store.write_json(evidence_name, details)
        return ToolResult.create(
            tool_id=action.tool_id,
            action_id=action.action_id,
            target=url,
            summary="TLS review skipped for a non-HTTPS base URL.",
            details=details,
            evidence_paths=[str(evidence_path)],
            findings=findings,
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
                details.update(
                    {
                        "cipher": cipher[0] if cipher else None,
                        "protocol": protocol,
                        "certificate": certificate,
                    }
                )
                if protocol and protocol not in {"TLSv1.2", "TLSv1.3"}:
                    findings.append(
                        Finding(
                            title="Legacy TLS protocol negotiated",
                            severity=Severity.high,
                            confidence=Confidence.high,
                            affected_asset=url,
                            evidence=[f"Negotiated protocol: {protocol}"],
                            why_it_matters="Older TLS versions weaken transport security and may lack modern protections.",
                            safe_verification_status="Verified passively via TLS handshake metadata.",
                            remediation="Disable legacy TLS versions and require TLS 1.2 or newer.",
                            source_tool=action.tool_id,
                            source_action_id=action.action_id,
                        ).model_dump()
                    )
                not_after = certificate.get("notAfter") if isinstance(certificate, dict) else None
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    delta_days = (expiry - datetime.utcnow()).days
                    if delta_days <= 30:
                        findings.append(
                            Finding(
                                title="TLS certificate expires soon",
                                severity=Severity.medium,
                                confidence=Confidence.high,
                                affected_asset=url,
                                evidence=[f"Certificate expiry: {not_after}"],
                                why_it_matters="Certificates nearing expiry can lead to service disruption and weaken operational trust.",
                                safe_verification_status="Verified passively via certificate metadata.",
                                remediation="Renew the certificate before expiry and monitor renewal windows.",
                                source_tool=action.tool_id,
                                source_action_id=action.action_id,
                            ).model_dump()
                        )
    except Exception as exc:
        details["error"] = str(exc)

    evidence_path = context.evidence_store.write_json(evidence_name, details)
    summary = "Reviewed TLS handshake posture."
    if "error" in details:
        summary = f"TLS posture review encountered an error: {details['error']}"
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=url,
        summary=summary,
        details=details,
        evidence_paths=[str(evidence_path)],
        findings=findings,
        started_at=started,
        finished_at=datetime.now(UTC),
    )

