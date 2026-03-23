from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..policy.risk import RiskLevel
from .base import ToolDefinition
from .dns_visibility import dns_visibility
from .http_probe import probe_http_surface
from .manual import manual_review_capture
from .nmap import nmap_service_discovery
from .robots import review_robots_txt
from .routes import inventory_public_routes
from .security_headers import review_security_headers
from .sitemap import review_sitemap_xml
from .tech import fingerprint_technology
from .tls import review_tls_posture
from .stubs import active_validation_stub


@dataclass(slots=True)
class ToolRegistry:
    definitions: dict[str, ToolDefinition]

    def get(self, tool_id: str) -> ToolDefinition:
        if tool_id not in self.definitions:
            raise KeyError(tool_id)
        return self.definitions[tool_id]

    def has(self, tool_id: str) -> bool:
        return tool_id in self.definitions

    def all(self) -> Iterable[ToolDefinition]:
        return self.definitions.values()


def default_tool_registry() -> ToolRegistry:
    definitions = {
        "header-review": ToolDefinition(
            tool_id="header-review",
            title="Review response headers",
            description="Inspect the base URL response headers and cookie flags for common hardening issues.",
            default_risk=RiskLevel.passive_safe,
            executor=review_security_headers,
            approval_required=False,
            expected_artifact_kinds=("evidence",),
            parser_available=True,
        ),
        "http-probe": ToolDefinition(
            tool_id="http-probe",
            title="HTTP probe",
            description="Capture response metadata, redirects, cookies, and page title for the base URL.",
            default_risk=RiskLevel.passive_safe,
            executor=probe_http_surface,
            approval_required=False,
            expected_artifact_kinds=("evidence",),
            parser_available=True,
        ),
        "tls-review": ToolDefinition(
            tool_id="tls-review",
            title="Review TLS posture",
            description="Inspect the negotiated TLS version and certificate metadata for the base URL.",
            default_risk=RiskLevel.passive_safe,
            executor=review_tls_posture,
            approval_required=False,
            expected_artifact_kinds=("evidence",),
            parser_available=True,
        ),
        "dns-visibility": ToolDefinition(
            tool_id="dns-visibility",
            title="DNS visibility",
            description="Collect safe DNS records that help correlate the exposed infrastructure surface.",
            default_risk=RiskLevel.passive_safe,
            executor=dns_visibility,
            approval_required=False,
            expected_artifact_kinds=("evidence",),
            parser_available=True,
        ),
        "robots-fetch": ToolDefinition(
            tool_id="robots-fetch",
            title="Fetch robots.txt",
            description="Retrieve robots.txt and surface any public path disclosure.",
            default_risk=RiskLevel.passive_safe,
            executor=review_robots_txt,
            approval_required=False,
        ),
        "sitemap-fetch": ToolDefinition(
            tool_id="sitemap-fetch",
            title="Fetch sitemap.xml",
            description="Retrieve sitemap.xml and summarize its public route inventory.",
            default_risk=RiskLevel.passive_safe,
            executor=review_sitemap_xml,
            approval_required=False,
        ),
        "route-inventory": ToolDefinition(
            tool_id="route-inventory",
            title="Inventory public routes",
            description="Collect public routes from visible links, scope routes, and discovery files.",
            default_risk=RiskLevel.passive_safe,
            executor=inventory_public_routes,
            approval_required=False,
        ),
        "tech-fingerprint": ToolDefinition(
            tool_id="tech-fingerprint",
            title="Fingerprint technology",
            description="Derive passive technology signals from headers, metadata, and response content.",
            default_risk=RiskLevel.passive_safe,
            executor=fingerprint_technology,
            approval_required=False,
        ),
        "manual-review": ToolDefinition(
            tool_id="manual-review",
            title="Capture manual review notes",
            description="Store analyst notes in an evidence artifact without altering the target.",
            default_risk=RiskLevel.passive_safe,
            executor=manual_review_capture,
            approval_required=False,
        ),
        "nmap-service-discovery": ToolDefinition(
            tool_id="nmap-service-discovery",
            title="Nmap service discovery",
            description="Run an approval-gated, scope-bound Nmap service scan and capture the raw XML/text output.",
            default_risk=RiskLevel.low_risk_active,
            executor=nmap_service_discovery,
            allowed_in_passive_profile=False,
            approval_required=True,
            allowed_target_kinds=("scope_base_url", "authorized_host"),
            expected_artifact_kinds=("evidence", "xml", "text", "grepable"),
            parser_available=True,
            scope_rule="target host must be in authorized_hosts and the action must be approved",
        ),
        "approved-login-surface-probe": ToolDefinition(
            tool_id="approved-login-surface-probe",
            title="Approved login surface probe",
            description="Safe stub representing a gated login-surface validation step.",
            default_risk=RiskLevel.low_risk_active,
            executor=active_validation_stub,
            allowed_in_passive_profile=False,
            approval_required=True,
            parser_available=False,
        ),
        "approved-api-surface-probe": ToolDefinition(
            tool_id="approved-api-surface-probe",
            title="Approved API surface probe",
            description="Safe stub representing a gated API validation step.",
            default_risk=RiskLevel.low_risk_active,
            executor=active_validation_stub,
            allowed_in_passive_profile=False,
            approval_required=True,
            parser_available=False,
        ),
        "approved-rate-limit-probe": ToolDefinition(
            tool_id="approved-rate-limit-probe",
            title="Approved rate-limit probe",
            description="Safe stub representing a gated high-risk validation step.",
            default_risk=RiskLevel.high_risk_active,
            executor=active_validation_stub,
            allowed_in_passive_profile=False,
            approval_required=True,
            parser_available=False,
        ),
    }
    return ToolRegistry(definitions=definitions)
