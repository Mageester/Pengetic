from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import ipaddress
import json
import socket
import subprocess
from typing import Any
from urllib.parse import urlparse

from ..findings.models import Confidence, Severity
from .base import ExecutionContext, FindingCandidate, ToolArtifact, ToolResult
from .common import make_evidence_name, scope_base_url


@dataclass(slots=True)
class _DnsQueryResult:
    record_type: str
    values: list[str]
    source: str


def _resolve_target_host(action: Any, context: ExecutionContext) -> str:
    candidate = str(getattr(action, "target", "") or "") or scope_base_url(context)
    parsed = urlparse(candidate)
    host = parsed.hostname or candidate
    host = host.strip().lower().rstrip(".")
    if not host:
        raise ValueError("DNS visibility target host is empty.")
    if host not in set(context.scope.authorized_hosts):
        raise ValueError(f"DNS visibility target host '{host}' is outside the validated scope.")
    return host


def _records_from_getaddrinfo(host: str) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {"A": [], "AAAA": []}
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return records
    seen_v4: set[str] = set()
    seen_v6: set[str] = set()
    for family, _, _, _, sockaddr in infos:
        if family == socket.AF_INET and sockaddr:
            address = sockaddr[0]
            if address not in seen_v4:
                seen_v4.add(address)
                records["A"].append(address)
        elif family == socket.AF_INET6 and sockaddr:
            address = sockaddr[0]
            if address not in seen_v6:
                seen_v6.add(address)
                records["AAAA"].append(address)
    return records


def _parse_nslookup_output(output: str) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {"CNAME": [], "MX": [], "TXT": [], "NS": []}
    current_type: str | None = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        lower = line.lower()
        if not line:
            continue
        if lower.startswith("canonical name ="):
            current_type = "CNAME"
            value = line.split("=", 1)[1].strip().rstrip(".")
            if value:
                records["CNAME"].append(value)
            continue
        if lower.startswith("mail exchanger ="):
            current_type = "MX"
            value = line.split("=", 1)[1].strip().rstrip(".")
            if value:
                records["MX"].append(value)
            continue
        if lower.startswith("nameserver ="):
            current_type = "NS"
            value = line.split("=", 1)[1].strip().rstrip(".")
            if value:
                records["NS"].append(value)
            continue
        if "text =" in lower:
            current_type = "TXT"
            value = line.split("=", 1)[1].strip().strip('"')
            if value:
                records["TXT"].append(value)
            continue
        if current_type == "TXT" and line.startswith('"') and line.endswith('"'):
            value = line.strip('"')
            if value:
                records["TXT"].append(value)
    return records


def _nslookup_record(host: str, record_type: str) -> _DnsQueryResult:
    command = ["nslookup", f"-type={record_type}", host]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=6, check=False)
    except FileNotFoundError:
        return _DnsQueryResult(record_type=record_type, values=[], source="nslookup-unavailable")
    except subprocess.TimeoutExpired:
        return _DnsQueryResult(record_type=record_type, values=[], source="nslookup-timeout")

    output = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
    parsed = _parse_nslookup_output(output)
    values = parsed.get(record_type, [])
    return _DnsQueryResult(record_type=record_type, values=values, source="nslookup")


def _reverse_lookup(host: str) -> _DnsQueryResult:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return _DnsQueryResult(record_type="PTR", values=[], source="not-an-ip")

    try:
        hostname, aliases, _ = socket.gethostbyaddr(host)
    except (socket.herror, socket.gaierror):
        return _DnsQueryResult(record_type="PTR", values=[], source="socket")

    values = [hostname.rstrip(".")]
    values.extend(alias.rstrip(".") for alias in aliases if alias)
    return _DnsQueryResult(record_type="PTR", values=list(dict.fromkeys(values)), source="socket")


def dns_visibility(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    host = _resolve_target_host(action, context)

    a_records = _records_from_getaddrinfo(host)
    cname = _nslookup_record(host, "CNAME")
    mx = _nslookup_record(host, "MX")
    txt = _nslookup_record(host, "TXT")
    ns = _nslookup_record(host, "NS")
    ptr = _reverse_lookup(host)

    records = {
        "A": a_records["A"],
        "AAAA": a_records["AAAA"],
        "CNAME": cname.values,
        "MX": mx.values,
        "TXT": txt.values,
        "NS": ns.values,
        "PTR": ptr.values,
    }

    parsed_output = {
        "host": host,
        "records": records,
        "sources": {
            "A": "socket.getaddrinfo",
            "AAAA": "socket.getaddrinfo",
            "CNAME": cname.source,
            "MX": mx.source,
            "TXT": txt.source,
            "NS": ns.source,
            "PTR": ptr.source,
        },
    }
    raw_output = {
        "host": host,
        "queries": records,
        "sources": parsed_output["sources"],
    }

    findings: list[FindingCandidate] = []
    next_safe_checks: list[str] = []

    if records["CNAME"]:
        next_safe_checks.append("Review CNAME targets for service hosting or third-party boundary changes.")
    if records["TXT"]:
        next_safe_checks.append("Review TXT records for SPF, DKIM, DMARC, and verification metadata.")
    if records["MX"]:
        next_safe_checks.append("Review MX hosts and mail posture separately from the web surface.")
    if records["NS"]:
        next_safe_checks.append("Confirm delegated name servers match the expected authority boundary.")
    if not any(records.values()):
        findings.append(
            FindingCandidate(
                title="DNS visibility returned no records",
                severity=Severity.informational.value,
                confidence=Confidence.low.value,
                affected_asset=host,
                evidence=["No DNS records were returned by the local resolver and nslookup checks used for this assessment."],
                why_it_matters="A lack of visible DNS data can limit passive infrastructure correlation and may deserve a resolver review.",
                safe_verification_status="Verified passively via DNS lookups.",
                remediation="Check resolver availability and confirm the domain's records are published as intended.",
                source_tool=action.tool_id,
                source_action_id=action.action_id,
            )
        )

    evidence_name = make_evidence_name(context, action.action_id, "dns.json")
    raw_path = context.evidence_store.write_json(f"{evidence_name}.raw.json", raw_output)
    parsed_path = context.evidence_store.write_json(f"{evidence_name}.parsed.json", parsed_output)
    artifacts = [
        ToolArtifact(kind="evidence", path=str(raw_path), description="Raw DNS visibility output"),
        ToolArtifact(kind="evidence", path=str(parsed_path), description="Parsed DNS visibility summary"),
    ]
    metadata = {
        "summary": f"Collected DNS visibility records for {host}.",
        "resolver": socket.getdefaulttimeout(),
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=host,
        run_id=context.run_id,
        scope_id=context.scope_fingerprint,
        status="success",
        raw_output=raw_output,
        parsed_output=parsed_output,
        artifacts=artifacts,
        findings_candidates=findings,
        next_safe_checks=next_safe_checks,
        metadata=metadata,
        started_at=started,
        finished_at=datetime.now(UTC),
    )
