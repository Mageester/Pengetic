from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import subprocess
import xml.etree.ElementTree as ET

from ..findings.models import Confidence, Finding, Severity
from .base import ExecutionContext, FindingCandidate, ToolArtifact, ToolResult
from .common import make_evidence_name


_CLEARTEXT_SERVICE_MARKERS = {
    "ftp",
    "http",
    "imap",
    "ldap",
    "mssql",
    "mysql",
    "netbios-ssn",
    "pop3",
    "postgresql",
    "redis",
    "smtp",
    "telnet",
    "vnc",
}


def _resolve_target_host(action: Any, context: ExecutionContext) -> str:
    candidate = str(getattr(action, "target", "") or "").strip() or str(context.scope.base_url)
    parsed = urlparse(candidate)
    host = parsed.hostname or candidate
    host = host.strip().lower()
    if not host:
        raise ValueError("Nmap target host is empty.")
    if host not in set(context.scope.authorized_hosts):
        raise ValueError(f"Nmap target host '{host}' is outside the validated scope.")
    return host


def _parse_nmap_xml(xml_path: Path) -> list[dict[str, Any]]:
    if not xml_path.exists():
        return []
    try:
        root = ET.fromstring(xml_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    services: list[dict[str, Any]] = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        service = port.find("service")
        service_info = {
            "protocol": port.attrib.get("protocol"),
            "port": port.attrib.get("portid"),
            "state": state.attrib.get("state"),
            "service": service.attrib.get("name") if service is not None else None,
            "product": service.attrib.get("product") if service is not None else None,
            "version": service.attrib.get("version") if service is not None else None,
            "extrainfo": service.attrib.get("extrainfo") if service is not None else None,
            "ostype": service.attrib.get("ostype") if service is not None else None,
        }
        services.append(service_info)
    return services


def _recommendations(services: list[dict[str, Any]]) -> list[str]:
    recommendations: list[str] = []
    if any(service.get("service") in {"https", "ssl/http"} for service in services):
        recommendations.append("Verify SSL configuration and certificate posture for exposed web services.")
    if any(service.get("version") or service.get("product") for service in services):
        recommendations.append("Audit version-specific service headers and compare exposed software to the approved baseline.")
    if any(service.get("service") in {"ssh", "rdp"} for service in services):
        recommendations.append("Review remote administration hardening, access control, and authentication settings.")
    if any(service.get("service") in _CLEARTEXT_SERVICE_MARKERS for service in services):
        recommendations.append("Review cleartext service exposure and prefer encrypted transport where feasible.")
    if not recommendations and services:
        recommendations.append("Review the newly discovered service surface and confirm each exposure is intentional.")
    return recommendations


def nmap_service_discovery(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    target_host = _resolve_target_host(action, context)
    output_name = make_evidence_name(context, action.action_id, "nmap")
    output_base = context.evidence_store.root / output_name.replace("/", "-")
    output_base.parent.mkdir(parents=True, exist_ok=True)

    command = [
        "nmap",
        "-sV",
        "-Pn",
        "--version-light",
        "--top-ports",
        "100",
        "-T2",
        "-oA",
        str(output_base),
        target_host,
    ]

    xml_path = output_base.with_suffix(".xml")
    text_path = output_base.with_suffix(".nmap")
    grepable_path = output_base.with_suffix(".gnmap")

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except FileNotFoundError as exc:
        raw_output = {"command": command, "error": str(exc), "target_host": target_host}
        raw_path = context.evidence_store.write_json(f"{output_name}.raw.json", raw_output)
        return ToolResult.create(
            tool_id=action.tool_id,
            action_id=action.action_id,
            target=target_host,
            run_id=context.run_id,
            scope_id=context.scope_fingerprint,
            status="failed",
            raw_output=raw_output,
            parsed_output={"error": str(exc), "target_host": target_host},
            artifacts=[ToolArtifact(kind="evidence", path=str(raw_path), description="Raw Nmap failure output")],
            findings_candidates=[],
            next_safe_checks=[],
            metadata={
                "summary": "Nmap is not installed on this system.",
                "started_at": started.isoformat().replace("+00:00", "Z"),
                "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            },
            started_at=started,
            finished_at=datetime.now(UTC),
        )
    except Exception as exc:
        raw_output = {"command": command, "error": str(exc), "target_host": target_host}
        raw_path = context.evidence_store.write_json(f"{output_name}.raw.json", raw_output)
        return ToolResult.create(
            tool_id=action.tool_id,
            action_id=action.action_id,
            target=target_host,
            run_id=context.run_id,
            scope_id=context.scope_fingerprint,
            status="failed",
            raw_output=raw_output,
            parsed_output={"error": str(exc), "target_host": target_host},
            artifacts=[ToolArtifact(kind="evidence", path=str(raw_path), description="Raw Nmap failure output")],
            findings_candidates=[],
            next_safe_checks=[],
            metadata={
                "summary": f"Nmap scan could not start: {exc}",
                "started_at": started.isoformat().replace("+00:00", "Z"),
                "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            },
            started_at=started,
            finished_at=datetime.now(UTC),
        )

    services = _parse_nmap_xml(xml_path)
    recommendations = _recommendations(services)
    raw_output = {
        "command": command,
        "returncode": return_code,
        "stdout": stdout,
        "stderr": stderr,
        "xml_path": str(xml_path),
        "text_path": str(text_path),
        "grepable_path": str(grepable_path),
    }
    parsed_output = {
        "target_host": target_host,
        "returncode": return_code,
        "services": services,
        "recommendations": recommendations,
    }
    raw_path = context.evidence_store.write_json(f"{output_name}.raw.json", raw_output)
    parsed_path = context.evidence_store.write_json(f"{output_name}.parsed.json", parsed_output)

    artifacts = [
        ToolArtifact(kind="evidence", path=str(raw_path), description="Raw Nmap command output"),
        ToolArtifact(kind="evidence", path=str(parsed_path), description="Parsed Nmap service inventory"),
    ]
    for path, kind in [(xml_path, "xml"), (text_path, "text"), (grepable_path, "grepable")]:
        if path.exists():
            artifacts.append(ToolArtifact(kind=kind, path=str(path), description=f"Nmap {kind} output"))

    findings: list[FindingCandidate] = []
    if services:
        findings.append(
            FindingCandidate(
                title="Open services discovered via Nmap",
                severity=Severity.informational.value,
                confidence=Confidence.high.value,
                affected_asset=target_host,
                evidence=[
                    ", ".join(
                        filter(
                            None,
                            [
                                f"{service.get('protocol')}/{service.get('port')}",
                                service.get("service"),
                                service.get("product"),
                                service.get("version"),
                            ],
                        )
                    )
                    for service in services[:10]
                ],
                why_it_matters="Open ports and service banners expand the observable attack surface and should be reviewed against the authorized baseline.",
                safe_verification_status="Verified through a scope-bound, approval-gated Nmap service scan.",
                remediation="Review the exposed services, remove unneeded listeners, and harden the required services.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            )
        )
        if any(service.get("service") in _CLEARTEXT_SERVICE_MARKERS for service in services):
            findings.append(
                FindingCandidate(
                    title="Potential cleartext service exposure detected",
                    severity=Severity.low.value,
                    confidence=Confidence.medium.value,
                    affected_asset=target_host,
                    evidence=[
                        ", ".join(
                            filter(
                                None,
                                [
                                    f"{service.get('protocol')}/{service.get('port')}",
                                    service.get("service"),
                                    service.get("version"),
                                ],
                            )
                        )
                        for service in services
                        if service.get("service") in _CLEARTEXT_SERVICE_MARKERS
                    ][:10],
                    why_it_matters="Cleartext or legacy services are easier to fingerprint and often deserve immediate hardening review.",
                    safe_verification_status="Verified through service inventory parsing of the approved scan output.",
                    remediation="Review whether the exposed service can be removed, encrypted, or restricted to a smaller trust boundary.",
                    source_tool=action.tool_id,
                    source_action_id=action.action_id,
                )
            )

    status = "success" if return_code == 0 else "partial"
    summary = (
        f"Nmap discovered {len(services)} open service(s) on {target_host}."
        if services
        else f"Nmap completed against {target_host} and did not report open services in the captured top ports."
    )
    if recommendations:
        summary = f"{summary} Next best action: {recommendations[0]}"
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=target_host,
        run_id=context.run_id,
        scope_id=context.scope_fingerprint,
        status=status,
        raw_output=raw_output,
        parsed_output=parsed_output,
        artifacts=artifacts,
        findings_candidates=findings,
        next_safe_checks=recommendations,
        metadata={
            "summary": summary,
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        },
        started_at=started,
        finished_at=datetime.now(UTC),
    )
