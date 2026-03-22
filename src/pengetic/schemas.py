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
    next_allowed_step: str
    recommended_action_id: str | None = None
    rationale: str
    confidence: str = "medium"
    raw: dict[str, Any] = Field(default_factory=dict)


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
