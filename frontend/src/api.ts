import type {
  ApprovalCreateRequest,
  ApprovalView,
  EvidenceCorrelationView,
  EnginePulseView,
  DashboardView,
  LLMPlannerRequest,
  LLMPlannerResponse,
  OllamaModelView,
  PlanView,
  ReportResponse,
  RunCreateRequest,
  RunResumeRequest,
  RunView,
  ScopeActivationResponse,
  ScopeTemplateRequest,
  ScopeTemplateResponse,
  ScopeSummary,
  ScopeResetResponse,
  ScopeRunsDeleteResponse,
  ScopeUploadResponse,
  WorkspacePurgeRequest,
  WorkspacePurgeResponse,
  ToolResultView,
} from "./types";

const rawBase = import.meta.env.VITE_PENGETIC_API_BASE as string | undefined;
const API_BASE = rawBase?.replace(/\/+$/, "") ?? "";

export function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
}

async function parseJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `${response.status} ${response.statusText}`);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(apiUrl(path), {
    headers: {
      Accept: "application/json",
    },
  });
  return parseJson<T>(response);
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(apiUrl(path), {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  return parseJson<T>(response);
}

async function postForm<T>(path: string, formData: FormData): Promise<T> {
  const response = await fetch(apiUrl(path), {
    method: "POST",
    headers: {
      Accept: "application/json",
    },
    body: formData,
  });
  return parseJson<T>(response);
}

export const api = {
  health: () => getJson<{ status: string; service: string }>("/api/health"),
  dashboard: () => getJson<DashboardView>("/api/dashboard"),
  scopes: () => getJson<ScopeSummary[]>("/api/scopes"),
  currentScope: () => getJson<ScopeSummary | null>("/api/scopes/current"),
  activateScope: (scopeId: string) => postJson<ScopeActivationResponse>(`/api/scopes/${encodeURIComponent(scopeId)}/activate`, {}),
  currentPlan: () => getJson<PlanView | null>("/api/plans/current"),
  ollamaModel: () => getJson<OllamaModelView>("/api/llm/model"),
  setOllamaModel: (model: string) => postJson<OllamaModelView>("/api/llm/model", { model }),
  enginePulse: () => getJson<EnginePulseView>("/api/engine/pulse"),
  runs: (limit = 12, scopeId?: string | null) =>
    getJson<RunView[]>(
      `/api/runs?limit=${encodeURIComponent(String(limit))}${scopeId ? `&scope_id=${encodeURIComponent(scopeId)}` : ""}`,
    ),
  run: (runId: string) => getJson<RunView>(`/api/runs/${encodeURIComponent(runId)}`),
  runToolResults: (runId: string, toolId?: string) =>
    getJson<ToolResultView[]>(
      `/api/runs/${encodeURIComponent(runId)}/tool-results${toolId ? `?tool_id=${encodeURIComponent(toolId)}` : ""}`,
    ),
  runEvidenceCorrelation: (runId: string) => getJson<EvidenceCorrelationView>(`/api/runs/${encodeURIComponent(runId)}/evidence-correlation`),
  runServiceInventory: (runId: string) => getJson<Record<string, unknown>[]>(`/api/runs/${encodeURIComponent(runId)}/service-inventory`),
  runRouteInventory: (runId: string) => getJson<Record<string, unknown>[]>(`/api/runs/${encodeURIComponent(runId)}/route-inventory`),
  runTlsSummary: (runId: string) => getJson<Record<string, unknown>[]>(`/api/runs/${encodeURIComponent(runId)}/tls-summary`),
  runHeaderSummary: (runId: string) => getJson<Record<string, unknown>[]>(`/api/runs/${encodeURIComponent(runId)}/header-summary`),
  runPlannerEvidenceContext: (runId: string) => getJson<Record<string, unknown>>(`/api/runs/${encodeURIComponent(runId)}/planner-evidence-context`),
  report: (runId: string) => getJson<ReportResponse>(`/api/reports/${encodeURIComponent(runId)}`),
  reportUrl: (runId: string) => apiUrl(`/api/reports/${encodeURIComponent(runId)}/export`),
  uploadScope: (file: File, profile: string, activate = true) => {
    const form = new FormData();
    form.append("file", file);
    form.append("profile", profile);
    form.append("activate", activate ? "true" : "false");
    return postForm<ScopeUploadResponse>("/api/scopes/upload", form);
  },
  startRun: (body: RunCreateRequest) => postJson<RunView>("/api/runs", body),
  resumeRun: (runId: string, body: RunResumeRequest) =>
    postJson<RunView>(`/api/runs/${encodeURIComponent(runId)}/resume`, body),
  approveAction: (body: ApprovalCreateRequest) => postJson<ApprovalView>("/api/approvals", body),
  planner: (body: LLMPlannerRequest) => postJson<LLMPlannerResponse>("/api/llm/planner", body),
  generateScopeTemplate: (body: ScopeTemplateRequest) => postJson<ScopeTemplateResponse>("/api/scopes/templates/generate", body),
  resetCurrentScope: (confirmation: string) =>
    postJson<ScopeResetResponse>("/api/scopes/current/reset", { confirmation }),
  deleteCurrentScopeRuns: (confirmation: string) =>
    postJson<ScopeRunsDeleteResponse>("/api/scopes/current/runs/delete", { confirmation }),
  purgeWorkspace: (body: WorkspacePurgeRequest) => postJson<WorkspacePurgeResponse>("/api/system/purge-all", body),
};
