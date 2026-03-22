export type AssessmentState =
  | "idle"
  | "scope_uploaded"
  | "scope_validated"
  | "plan_ready"
  | "running"
  | "awaiting_approval"
  | "completed"
  | "failed";

export interface ScopeSummary {
  id: string;
  name: string;
  primary_domain: string;
  base_url: string;
  authorized_hosts: string[];
  allowed_subdomains: string[];
  allowed_urls: string[];
  login_areas_allowed: string[];
  apis_allowed: string[];
  tool_allowlist: string[];
  authorization_note: string;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface PlanActionView {
  action_id: string;
  title: string;
  objective: string;
  target: string;
  tool_id: string;
  classification: string;
  expected_evidence: string[];
  approval_required: boolean;
  allowed_by_scope: boolean;
  notes: string | null;
}

export interface PlanView {
  id: string;
  scope_id: string;
  scope_name: string;
  scope_fingerprint: string;
  profile: string;
  generated_at: string;
  actions: PlanActionView[];
}

export interface RunActionView extends PlanActionView {
  id: number;
  run_id: string;
  status: string;
  decision_reason: string | null;
  started_at: string | null;
  finished_at: string | null;
  evidence_paths: string[];
  result: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

export interface FindingView {
  id: number;
  run_id: string;
  action_id: string | null;
  title: string;
  severity: string;
  confidence: string;
  affected_asset: string;
  evidence: string[];
  why_it_matters: string;
  safe_verification_status: string;
  remediation: string;
  source_tool: string | null;
  source_action_id: string | null;
  created_at: string | null;
}

export interface ArtifactView {
  id: number;
  run_id: string;
  action_id: string | null;
  kind: string;
  path: string;
  description: string | null;
  created_at: string;
}

export interface ApprovalView {
  id: string;
  run_id: string;
  action_id: string;
  scope_fingerprint: string;
  risk: string;
  status: string;
  approved_by: string | null;
  approved_at: string | null;
  note: string | null;
  decision_reason: string | null;
  created_at: string;
  updated_at: string;
}

export interface EventView {
  id: number;
  run_id: string;
  created_at: string;
  event_type: string;
  level: string;
  message: string;
  action_id: string | null;
  tool_id: string | null;
  payload: Record<string, unknown>;
}

export interface RunView {
  id: string;
  scope_id: string;
  scope_name: string;
  scope_fingerprint: string;
  profile: string;
  state: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
  report_path: string | null;
  report_text: string | null;
  manual_notes: string | null;
  plan_id: string | null;
  plan: PlanView | null;
  actions: RunActionView[];
  findings: FindingView[];
  artifacts: ArtifactView[];
  approvals: ApprovalView[];
  events: EventView[];
}

export interface DashboardView {
  current_scope: ScopeSummary | null;
  current_plan: PlanView | null;
  latest_run: RunView | null;
  counts: Record<string, number>;
  pending_approvals: RunActionView[];
  recent_findings: FindingView[];
  recent_runs: RunView[];
  state: AssessmentState | string;
}

export interface ScopeUploadResponse {
  scope: ScopeSummary;
  plan: PlanView;
  validation_message: string;
}

export interface RunCreateRequest {
  profile: string;
  manual_notes?: string | null;
  include_approved_active: boolean;
}

export interface RunResumeRequest {
  include_approved_active: boolean;
}

export interface ApprovalCreateRequest {
  run_id: string;
  action_id: string;
  approved_by: string;
  note: string;
}

export interface LLMPlannerRequest {
  run_id?: string | null;
  scope_id?: string | null;
  model?: string | null;
}

export interface LLMPlannerResponse {
  model: string;
  source: string;
  summary: string;
  next_allowed_step: string;
  recommended_action_id: string | null;
  rationale: string;
  confidence: string;
  raw: Record<string, unknown>;
}

export interface ReportResponse {
  run_id: string;
  report_path: string | null;
  report_text: string | null;
}
