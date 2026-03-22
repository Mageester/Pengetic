import type {
  ApprovalCreateRequest,
  ApprovalView,
  DashboardView,
  LLMPlannerRequest,
  LLMPlannerResponse,
  PlanView,
  ReportResponse,
  RunCreateRequest,
  RunResumeRequest,
  RunView,
  ScopeSummary,
  ScopeUploadResponse,
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
  currentPlan: () => getJson<PlanView | null>("/api/plans/current"),
  runs: (limit = 12) => getJson<RunView[]>(`/api/runs?limit=${encodeURIComponent(String(limit))}`),
  run: (runId: string) => getJson<RunView>(`/api/runs/${encodeURIComponent(runId)}`),
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
};
