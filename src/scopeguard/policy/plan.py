from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from ..config import RuntimeProfile
from ..scope.fingerprint import scope_fingerprint
from ..scope.models import ScopePackage
from ..tools.registry import ToolRegistry, default_tool_registry
from .risk import RiskLevel


class AssessmentAction(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action_id: str
    title: str
    objective: str
    target: str
    tool_id: str
    classification: RiskLevel
    expected_evidence: list[str] = Field(default_factory=list)
    approval_required: bool = False
    allowed_by_scope: bool = True
    notes: str | None = None


class AssessmentPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    scope_name: str
    scope_fingerprint: str
    generated_at: str
    profile: str
    actions: list[AssessmentAction] = Field(default_factory=list)

    def get_action(self, action_id: str) -> AssessmentAction:
        for action in self.actions:
            if action.action_id == action_id:
                return action
        raise KeyError(action_id)


class AssessmentPlanner:
    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry or default_tool_registry()

    def build(self, scope: ScopePackage, profile: RuntimeProfile) -> AssessmentPlan:
        actions: list[AssessmentAction] = []
        base_target = str(scope.base_url)
        plan_scope_fingerprint = scope_fingerprint(scope)

        def add_action(
            *,
            action_id: str,
            title: str,
            objective: str,
            target: str,
            tool_id: str,
            classification: RiskLevel,
            expected_evidence: list[str],
            approval_required: bool = False,
            notes: str | None = None,
        ) -> None:
            actions.append(
                AssessmentAction(
                    action_id=action_id,
                    title=title,
                    objective=objective,
                    target=target,
                    tool_id=tool_id,
                    classification=classification,
                    expected_evidence=expected_evidence,
                    approval_required=approval_required,
                    allowed_by_scope=tool_id in scope.tool_allowlist,
                    notes=notes,
                )
            )

        if "nmap-service-discovery" in scope.tool_allowlist:
            add_action(
                action_id="active-nmap-service-discovery",
                title="Nmap service discovery",
                objective="Run an approval-gated service scan to inventory open ports, service signatures, and version banners.",
                target=base_target,
                tool_id="nmap-service-discovery",
                classification=RiskLevel.low_risk_active,
                expected_evidence=["Nmap XML output", "Nmap text output", "Parsed open service inventory"],
                approval_required=True,
                notes="Approval-gated service discovery; safe output capture only.",
            )

        add_action(
            action_id="passive-http-probe",
            title="Probe HTTP surface",
            objective="Capture response metadata, redirects, cookies, and title data from the base URL.",
            target=base_target,
            tool_id="http-probe",
            classification=RiskLevel.passive_safe,
            expected_evidence=["HTTP status", "Redirect chain", "Headers", "Cookie flags", "Title"],
        )
        add_action(
            action_id="passive-tls-review",
            title="Review TLS posture",
            objective="Inspect the negotiated TLS version and certificate metadata without altering state.",
            target=base_target,
            tool_id="tls-review",
            classification=RiskLevel.passive_safe,
            expected_evidence=["TLS posture", "Certificate metadata", "Protocol/cipher hints"],
        )
        add_action(
            action_id="passive-route-inventory",
            title="Inventory public routes",
            objective="Map public routes from visible links, robots.txt, sitemap.xml, and scope-listed public paths.",
            target=base_target,
            tool_id="route-inventory",
            classification=RiskLevel.passive_safe,
            expected_evidence=["Normalized public routes", "Sensitive route markers", "Base response snapshot"],
        )
        add_action(
            action_id="passive-header-review",
            title="Review security headers",
            objective="Inspect the base response headers for common hardening gaps and cookie flags.",
            target=base_target,
            tool_id="header-review",
            classification=RiskLevel.passive_safe,
            expected_evidence=["Structured header analysis", "Cookie flag summary", "CSP/HSTS posture"],
        )
        add_action(
            action_id="passive-dns-visibility",
            title="Collect DNS visibility",
            objective="Gather safe DNS records to support infrastructure correlation.",
            target=base_target,
            tool_id="dns-visibility",
            classification=RiskLevel.passive_safe,
            expected_evidence=["A/AAAA/CNAME/MX/TXT/NS records", "Reverse lookup hints"],
        )
        add_action(
            action_id="passive-robots-fetch",
            title="Fetch robots.txt",
            objective="Retrieve the public robots.txt file for route-discovery signals.",
            target=f"{base_target.rstrip('/')}/robots.txt",
            tool_id="robots-fetch",
            classification=RiskLevel.passive_safe,
            expected_evidence=["robots.txt body", "Disallow entries", "Public path hints"],
        )
        add_action(
            action_id="passive-sitemap-fetch",
            title="Fetch sitemap.xml",
            objective="Retrieve sitemap.xml for public route discovery.",
            target=f"{base_target.rstrip('/')}/sitemap.xml",
            tool_id="sitemap-fetch",
            classification=RiskLevel.passive_safe,
            expected_evidence=["sitemap.xml body", "URL inventory"],
        )
        add_action(
            action_id="passive-tech-fingerprint",
            title="Fingerprint visible technology",
            objective="Derive non-invasive technology signals from headers, metadata, and response content.",
            target=base_target,
            tool_id="tech-fingerprint",
            classification=RiskLevel.passive_safe,
            expected_evidence=["Header fingerprints", "Meta generator hints", "Framework markers", "Parsed tech signals"],
        )
        add_action(
            action_id="passive-manual-review",
            title="Capture manual review notes",
            objective="Store analyst notes alongside the run without altering the target.",
            target=base_target,
            tool_id="manual-review",
            classification=RiskLevel.passive_safe,
            expected_evidence=["Manual review artifact"],
        )

        if scope.login_areas_allowed:
            login_targets = ", ".join(scope.login_areas_allowed)
            add_action(
                action_id="active-login-surface-probe",
                title="Approved login-surface probe",
                objective="Gated login-surface validation remains a stub until explicit approval is recorded.",
                target=login_targets,
                tool_id="approved-login-surface-probe",
                classification=RiskLevel.low_risk_active,
                expected_evidence=["Approval record", "Stub execution record"],
                approval_required=True,
                notes="Deferred by default; safe stub only.",
            )

        if scope.apis_allowed:
            api_targets = ", ".join(scope.apis_allowed)
            add_action(
                action_id="active-api-surface-probe",
                title="Approved API-surface probe",
                objective="Gated API-surface validation remains a stub until explicit approval is recorded.",
                target=api_targets,
                tool_id="approved-api-surface-probe",
                classification=RiskLevel.low_risk_active,
                expected_evidence=["Approval record", "Stub execution record"],
                approval_required=True,
                notes="Deferred by default; safe stub only.",
            )
            add_action(
                action_id="active-rate-limit-probe",
                title="Approved rate-limit probe",
                objective="High-risk rate-limit validation is represented as a gated stub only.",
                target=api_targets,
                tool_id="approved-rate-limit-probe",
                classification=RiskLevel.high_risk_active,
                expected_evidence=["Approval record", "Stub execution record"],
                approval_required=True,
                notes="Deferred until explicit per-action approval.",
            )

        return AssessmentPlan(
            scope_name=scope.name,
            scope_fingerprint=plan_scope_fingerprint,
            generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            profile=profile.value,
            actions=actions,
        )
