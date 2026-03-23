from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ScopeSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str
    name: str
    primary_domain: str
    base_url: str
    authorized_hosts: list[str] = Field(default_factory=list)
    allowed_subdomains: list[str] = Field(default_factory=list)
    allowed_urls: list[str] = Field(default_factory=list)
    login_areas_allowed: list[str] = Field(default_factory=list)
    apis_allowed: list[str] = Field(default_factory=list)
    tool_allowlist: list[str] = Field(default_factory=list)
    authorization_note: str
    notes: str | None = None
    created_at: str
    updated_at: str


class PlanActionView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    action_id: str
    title: str
    objective: str
    target: str
    tool_id: str
    classification: str
    expected_evidence: list[str] = Field(default_factory=list)
    approval_required: bool = False
    allowed_by_scope: bool = True
    notes: str | None = None


class PlanView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str
    scope_id: str
    scope_name: str
    scope_fingerprint: str
    profile: str
    generated_at: str
    actions: list[PlanActionView] = Field(default_factory=list)


class RunActionView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: int
    run_id: str
    action_id: str
    title: str
    objective: str
    target: str
    tool_id: str
    classification: str
    expected_evidence: list[str] = Field(default_factory=list)
    approval_required: bool = False
    allowed_by_scope: bool = True
    notes: str | None = None
    status: str
    decision_reason: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    evidence_paths: list[str] = Field(default_factory=list)
    result: dict[str, Any] | None = None
    created_at: str
    updated_at: str


class FindingView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: int
    run_id: str
    action_id: str | None = None
    title: str
    severity: str
    confidence: str
    affected_asset: str
    evidence: list[str] = Field(default_factory=list)
    why_it_matters: str
    safe_verification_status: str
    remediation: str
    source_tool: str | None = None
    source_action_id: str | None = None
    created_at: str | None = None


class ArtifactView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: int
    run_id: str
    action_id: str | None = None
    kind: str
    path: str
    description: str | None = None
    created_at: str


class ToolArtifactView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    kind: str
    path: str
    description: str | None = None
    evidence_id: str | None = None
    persisted: bool = True


class FindingCandidateView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    title: str
    severity: str
    confidence: str
    affected_asset: str
    evidence: list[str] = Field(default_factory=list)
    why_it_matters: str = ""
    safe_verification_status: str = ""
    remediation: str = ""
    source_tool: str | None = None
    source_action_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolResultView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: int
    run_id: str
    scope_id: str
    action_id: str | None = None
    tool_id: str
    target: str
    timestamp: str
    status: str
    raw_output: dict[str, Any] = Field(default_factory=dict)
    parsed_output: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[ToolArtifactView] = Field(default_factory=list)
    findings_candidates: list[FindingCandidateView] = Field(default_factory=list)
    next_safe_checks: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    summary: str | None = None
    success: bool = False
    created_at: str


class EvidenceCorrelationView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    run_id: str
    tool_ids: list[str] = Field(default_factory=list)
    service_inventory: list[dict[str, Any]] = Field(default_factory=list)
    route_inventory: list[dict[str, Any]] = Field(default_factory=list)
    tls_posture: list[dict[str, Any]] = Field(default_factory=list)
    header_posture: list[dict[str, Any]] = Field(default_factory=list)
    http_probe: list[dict[str, Any]] = Field(default_factory=list)
    dns_visibility: list[dict[str, Any]] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    by_tool: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)


class ApprovalView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str
    run_id: str
    action_id: str
    scope_fingerprint: str
    risk: str
    status: str
    approved_by: str | None = None
    approved_at: str | None = None
    note: str | None = None
    decision_reason: str | None = None
    created_at: str
    updated_at: str


class EventView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: int
    run_id: str
    created_at: str
    event_type: str
    level: str
    message: str
    action_id: str | None = None
    tool_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class RunView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str
    scope_id: str
    scope_name: str
    scope_fingerprint: str
    profile: str
    state: str
    status: str
    started_at: str | None = None
    finished_at: str | None = None
    created_at: str
    updated_at: str
    report_path: str | None = None
    report_text: str | None = None
    manual_notes: str | None = None
    plan_id: str | None = None
    plan: PlanView | None = None
    actions: list[RunActionView] = Field(default_factory=list)
    findings: list[FindingView] = Field(default_factory=list)
    artifacts: list[ArtifactView] = Field(default_factory=list)
    tool_results: list[ToolResultView] = Field(default_factory=list)
    evidence_correlation: EvidenceCorrelationView | None = None
    approvals: list[ApprovalView] = Field(default_factory=list)
    events: list[EventView] = Field(default_factory=list)


class DashboardView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    current_scope: ScopeSummary | None = None
    current_plan: PlanView | None = None
    latest_run: RunView | None = None
    counts: dict[str, int] = Field(default_factory=dict)
    pending_approvals: list[RunActionView] = Field(default_factory=list)
    recent_findings: list[FindingView] = Field(default_factory=list)
    recent_runs: list[RunView] = Field(default_factory=list)
    state: str = "idle"


class ScopeUploadResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    scope: ScopeSummary
    plan: PlanView
    validation_message: str


class ScopeActivationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    scope: ScopeSummary
    status: str = "activated"


class RunCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    profile: str = "passive-only"
    manual_notes: str | None = None
    include_approved_active: bool = False


class RunResumeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    include_approved_active: bool = True


class ApprovalCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    run_id: str
    action_id: str
    approved_by: str = "user"
    note: str = "Explicit approval."


class LLMPlannerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    run_id: str | None = None
    scope_id: str | None = None
    model: str | None = None


class LLMPlannerResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    model: str
    source: str
    summary: str
    likely_areas_of_concern: list[str] = Field(default_factory=list)
    evidence_references: list[str] = Field(default_factory=list)
    next_allowed_step: str
    recommended_action_id: str | None = None
    approval_required: bool = False
    rationale: str
    confidence: str = "medium"
    raw: dict[str, Any] = Field(default_factory=dict)


class OllamaModelView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    selected_model: str
    backend_default_model: str
    source: str
    updated_at: str


class OllamaModelUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    model: str


class EnginePulseView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    status: str
    service: str = "ollama"
    selected_model: str
    available_models: list[str] = Field(default_factory=list)
    selected_model_available: bool = False
    checked_at: str
    error: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class ScopeTemplateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    template_id: str
    scope_name: str
    target_url: str
    allowed_subdomains: list[str] = Field(default_factory=list)
    login_areas_allowed: list[str] = Field(default_factory=list)
    apis_allowed: list[str] = Field(default_factory=list)
    tool_allowlist: list[str] = Field(default_factory=list)
    authorization_note: str = "Authorized by the site owner for defensive assessment only."
    contacts: list[str] = Field(default_factory=list)
    notes: str | None = None
    profile: str = "passive-only"
    activate: bool = True


class ScopeTemplateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    template_id: str
    generated_yaml: str
    scope: ScopeSummary
    plan: PlanView
    validation_message: str


class WorkspacePurgeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    confirmation: str


class WorkspacePurgeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    status: str
    removed_paths: list[str] = Field(default_factory=list)


class ScopeResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    confirmation: str


class ScopeResetResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    status: str
    scope_id: str | None = None


class ScopeRunsDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    confirmation: str


class ScopeRunsDeleteResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    status: str
    scope_id: str | None = None
    deleted_run_ids: list[str] = Field(default_factory=list)
    removed_paths: list[str] = Field(default_factory=list)


class OrchestratorRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    model: str | None = None
    max_steps: int = 10
    resume: bool = True


class OrchestratorDecisionView(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: int | None = None
    run_id: str
    step_index: int
    planner_model: str
    planner_source: str
    state_before: str
    state_after: str
    selected_action_id: str | None = None
    selected_tool_id: str | None = None
    selected_risk: str | None = None
    status: str
    stop_reason: str
    summary: str
    likely_areas_of_concern: list[str] = Field(default_factory=list)
    evidence_references: list[str] = Field(default_factory=list)
    next_allowed_step: str
    recommended_action_id: str | None = None
    rationale: str
    confidence: str = "medium"
    approval_required: bool = False
    approved: bool = False
    auto_approved: bool = False
    executed: bool = False
    remaining_action_ids: list[str] = Field(default_factory=list)
    completed_action_ids: list[str] = Field(default_factory=list)
    findings_count: int = 0
    evidence_paths: list[str] = Field(default_factory=list)
    result: dict[str, Any] | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    created_at: str | None = None
    updated_at: str | None = None


class OrchestratorRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    run_id: str
    scope_id: str
    scope_name: str
    state: str
    completed: bool
    stop_reason: str
    steps: list[OrchestratorDecisionView] = Field(default_factory=list)
    run: RunView
