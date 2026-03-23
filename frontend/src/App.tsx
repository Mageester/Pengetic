import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  ArrowUpRight,
  Brain,
  Clock3,
  Database,
  FileDown,
  FileText,
  Gauge,
  LayoutDashboard,
  ListChecks,
  Radar,
  PlayCircle,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  Target,
  Upload,
  Trash2,
  Workflow,
  type LucideIcon,
} from "lucide-react";

import { api, apiUrl } from "./api";
import type {
  ApprovalCreateRequest,
  DashboardView,
  EnginePulseView,
  LLMPlannerResponse,
  ToolResultView,
  PlanActionView,
  PlanView,
  ReportResponse,
  RunActionView,
  RunView,
  OllamaModelView,
  ScopeUploadResponse,
  ScopeTemplateResponse,
} from "./types";
import {
  cx,
  formatShortTimestamp,
  formatTimestamp,
  riskLabel,
  riskTone,
  severityTone,
  shortList,
  stateTone,
  statusLabel,
  statusTone,
  summarizeTarget,
  titleCase,
} from "./lib";

type SectionId = "overview" | "scope" | "plan" | "run" | "approvals" | "reports" | "planner";

const sections: Array<{
  id: SectionId;
  label: string;
  description: string;
  icon: LucideIcon;
}> = [
  { id: "overview", label: "Assessment", description: "Target, mode, start", icon: LayoutDashboard },
  { id: "run", label: "Results", description: "Findings and evidence", icon: PlayCircle },
  { id: "approvals", label: "Approvals", description: "Queued actions", icon: Workflow },
  { id: "reports", label: "Report", description: "Export summary", icon: FileDown },
  { id: "planner", label: "Settings", description: "Model and reset", icon: Brain },
];

const workflowStages = [
  {
    id: "scope",
    title: "Target",
    description: "Pick or create the scope.",
  },
  {
    id: "plan",
    title: "Mode",
    description: "Choose what to run.",
  },
  {
    id: "run",
    title: "Start",
    description: "Launch the assessment.",
  },
  {
    id: "approvals",
    title: "Results",
    description: "Review findings and evidence.",
  },
  {
    id: "reports",
    title: "Report",
    description: "Export the final summary.",
  },
];

const liveStates = new Set(["running", "awaiting_approval"]);
const panelBase = "rounded-[28px] border border-white/10 bg-slate-950/75 shadow-panel backdrop-blur-xl";
const buttonBase =
  "inline-flex items-center justify-center gap-2 rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-red-500/30 hover:bg-white/10 hover:text-white";
const inputBase =
  "w-full rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 placeholder:text-slate-500 outline-none transition focus:border-red-500/40 focus:ring-2 focus:ring-red-500/20";
const textareaBase =
  "w-full rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 placeholder:text-slate-500 outline-none transition focus:border-red-500/40 focus:ring-2 focus:ring-red-500/20";
const selectBase =
  "w-full rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none transition focus:border-red-500/40 focus:ring-2 focus:ring-red-500/20";
const logoPath = "/pengetic-logo.png";

function normalizeError(error: unknown): string {
  return error instanceof Error ? error.message : "An unexpected error occurred.";
}

function formatCount(value: number | undefined): string {
  return typeof value === "number" ? value.toString() : "0";
}

function splitEntries(value: string): string[] {
  return value
    .split(/[\n,]/g)
    .map((item) => item.trim())
    .filter(Boolean);
}

function planActionSummary(actions: PlanActionView[]): string {
  const passive = actions.filter((action) => action.classification === "PASSIVE_SAFE").length;
  return `${passive} passive-safe and ${actions.length - passive} gated active action(s)`;
}

function Card({
  eyebrow,
  title,
  description,
  actions,
  children,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className={panelBase}>
      <div className="flex flex-col gap-4 border-b border-white/5 px-6 py-5 lg:flex-row lg:items-start lg:justify-between">
        <div className="space-y-1">
          {eyebrow ? (
            <p className="text-[0.72rem] font-semibold uppercase tracking-[0.28em] text-red-300/80">
              {eyebrow}
            </p>
          ) : null}
          <h2 className="text-xl font-semibold tracking-tight text-white">{title}</h2>
          {description ? <p className="max-w-3xl text-sm text-slate-400">{description}</p> : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      <div className="px-6 py-6">{children}</div>
    </section>
  );
}

function MetricCard({
  label,
  value,
  detail,
  tone = "text-white",
}: {
  label: string;
  value: string;
  detail?: string;
  tone?: string;
}) {
  return (
    <div className={cx(panelBase, "p-5")}>
      <p className="text-xs font-semibold uppercase tracking-[0.24em] text-slate-400">{label}</p>
      <div className={cx("mt-3 text-3xl font-semibold tracking-tight", tone)}>{value}</div>
      {detail ? <p className="mt-2 text-sm leading-6 text-slate-400">{detail}</p> : null}
    </div>
  );
}

function Badge({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.2em]",
        className,
      )}
    >
      {children}
    </span>
  );
}

function Label({ text, hint }: { text: string; hint?: string }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="text-sm font-medium text-slate-200">{text}</div>
      {hint ? <div className="text-xs text-slate-500">{hint}</div> : null}
    </div>
  );
}

function EmptyState({
  title,
  description,
  icon: Icon,
}: {
  title: string;
  description: string;
  icon?: LucideIcon;
}) {
  return (
    <div className="flex min-h-[180px] flex-col items-center justify-center rounded-3xl border border-dashed border-white/10 bg-white/[0.03] p-8 text-center">
      {Icon ? <Icon className="mb-4 h-7 w-7 text-red-300/80" /> : null}
      <h3 className="text-lg font-semibold text-white">{title}</h3>
      <p className="mt-2 max-w-lg text-sm leading-6 text-slate-400">{description}</p>
    </div>
  );
}

function SectionButton({
  active,
  item,
  onClick,
}: {
  active: boolean;
  item: (typeof sections)[number];
  onClick: () => void;
}) {
  const Icon = item.icon;
  return (
    <button
      type="button"
      onClick={onClick}
      className={cx(
        "group flex w-full items-start gap-3 rounded-2xl border px-4 py-3 text-left transition",
        active
          ? "border-red-400/30 bg-red-400/10 text-white"
          : "border-white/10 bg-white/[0.03] text-slate-300 hover:border-red-400/20 hover:bg-white/[0.06] hover:text-white",
      )}
    >
      <Icon className={cx("mt-0.5 h-5 w-5 shrink-0", active ? "text-red-300" : "text-slate-400")} />
      <div className="min-w-0">
        <div className="text-sm font-semibold">{item.label}</div>
        <div className="mt-0.5 text-xs leading-5 text-slate-500 group-hover:text-slate-400">{item.description}</div>
      </div>
    </button>
  );
}

function LabeledValue({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="space-y-1">
      <div className="text-xs font-semibold uppercase tracking-[0.22em] text-slate-500">{label}</div>
      <div className="text-sm leading-6 text-slate-200">{value}</div>
    </div>
  );
}

function BrandLogo({ className, alt = "Pengetic logo" }: { className?: string; alt?: string }) {
  return <img src={logoPath} alt={alt} className={cx("block h-auto w-full object-contain", className)} />;
}

type EvidenceTab = "parsed" | "raw";

function formatJsonValue(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function countNonEmpty(items: Array<unknown> | undefined | null): number {
  return Array.isArray(items) ? items.filter(Boolean).length : 0;
}

function ToolResultSummary({
  result,
  selected,
  onSelect,
}: {
  result: ToolResultView;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cx(
        "w-full rounded-2xl border p-4 text-left transition",
        selected
          ? "border-red-400/30 bg-red-400/10"
          : "border-white/10 bg-slate-950/70 hover:border-red-400/20 hover:bg-white/[0.04]",
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Badge className={statusTone(result.status)}>{statusLabel(result.status)}</Badge>
        <Badge className="border-white/10 bg-white/5 text-slate-200">{result.tool_id}</Badge>
        <span className="text-xs text-slate-500">{formatShortTimestamp(result.timestamp)}</span>
      </div>
      <div className="mt-3 text-sm font-semibold text-white">{result.summary || result.tool_id}</div>
      <div className="mt-2 text-xs text-slate-500">{summarizeTarget(result.target)}</div>
      <div className="mt-3 flex flex-wrap gap-2 text-[11px] uppercase tracking-[0.18em] text-slate-400">
        <span>{result.artifacts.length} artifacts</span>
        <span>{result.findings_candidates.length} findings</span>
        <span>{result.next_safe_checks.length} next checks</span>
      </div>
    </button>
  );
}

function EvidenceDetail({
  result,
  activeTab,
  onTabChange,
}: {
  result: ToolResultView | null;
  activeTab: EvidenceTab;
  onTabChange: (tab: EvidenceTab) => void;
}) {
  if (!result) {
    return (
      <EmptyState
        title="No tool evidence selected"
        description="Pick a normalized tool result to inspect the raw output, parsed fields, artifacts, and follow-up ideas."
        icon={FileText}
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge className="border-red-400/20 bg-red-500/10 text-red-100">{result.tool_id}</Badge>
        <Badge className={statusTone(result.status)}>{statusLabel(result.status)}</Badge>
        <Badge className="border-white/10 bg-white/5 text-slate-200">{result.artifacts.length} artifacts</Badge>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <LabeledValue label="Target" value={summarizeTarget(result.target)} />
        <LabeledValue label="Timestamp" value={formatTimestamp(result.timestamp)} />
      </div>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => onTabChange("parsed")}
          className={cx(
            buttonBase,
            activeTab === "parsed" ? "border-red-400/25 bg-red-400/10 text-red-50" : "text-slate-300",
          )}
        >
          Parsed
        </button>
        <button
          type="button"
          onClick={() => onTabChange("raw")}
          className={cx(
            buttonBase,
            activeTab === "raw" ? "border-red-400/25 bg-red-400/10 text-red-50" : "text-slate-300",
          )}
        >
          Raw
        </button>
      </div>
      <div className="rounded-3xl border border-white/10 bg-slate-950/70 p-4">
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-white">
          <TerminalSquare className="h-4 w-4 text-red-300/80" />
          {activeTab === "raw" ? "Raw output" : "Parsed output"}
        </div>
        <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap break-words text-xs leading-6 text-slate-300">
          {formatJsonValue(activeTab === "raw" ? result.raw_output : result.parsed_output)}
        </pre>
      </div>
      <details className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
        <summary className="cursor-pointer list-none text-sm font-semibold text-white">
          Advanced
        </summary>
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <LabeledValue label="Run ID" value={<span className="font-mono text-xs">{result.run_id}</span>} />
          <LabeledValue label="Scope ID" value={<span className="font-mono text-xs">{result.scope_id}</span>} />
        </div>
      </details>
      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
          <div className="mb-3 text-sm font-semibold text-white">Findings candidates</div>
          <div className="space-y-3">
            {result.findings_candidates.length > 0 ? (
              result.findings_candidates.map((candidate) => (
                <div key={`${candidate.title}-${candidate.source_action_id ?? result.id}`} className="rounded-2xl border border-white/10 bg-slate-950/70 p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge className={severityTone(candidate.severity)}>{titleCase(candidate.severity)}</Badge>
                    <span className="font-semibold text-white">{candidate.title}</span>
                  </div>
                  <p className="mt-2 text-sm leading-6 text-slate-300">{candidate.why_it_matters}</p>
                  <p className="mt-2 text-xs uppercase tracking-[0.18em] text-slate-500">
                    {candidate.safe_verification_status || "Preliminary"}
                  </p>
                </div>
              ))
            ) : (
              <EmptyState title="No candidates" description="This tool result did not produce preliminary issue observations." icon={ShieldCheck} />
            )}
          </div>
        </div>
        <div className="space-y-4">
          <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
            <div className="mb-3 text-sm font-semibold text-white">Next safe checks</div>
            <div className="space-y-2">
              {result.next_safe_checks.length > 0 ? (
                result.next_safe_checks.map((check) => (
                  <div key={check} className="rounded-2xl border border-white/10 bg-slate-950/70 p-3 text-sm leading-6 text-slate-300">
                    {check}
                  </div>
                ))
              ) : (
                <EmptyState
                  title="No follow-up suggestions"
                  description="The current tool result does not recommend additional diagnostic-only checks."
                  icon={Workflow}
                />
              )}
            </div>
          </div>
          <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
            <div className="mb-3 text-sm font-semibold text-white">Artifacts</div>
            <div className="space-y-2">
              {result.artifacts.length > 0 ? (
                result.artifacts.map((artifact) => (
                  <div key={`${artifact.kind}-${artifact.path}`} className="rounded-2xl border border-white/10 bg-slate-950/70 p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge className="border-white/10 bg-white/5 text-slate-200">{artifact.kind}</Badge>
                      <span className="text-sm text-slate-200">{artifact.description ?? "Evidence artifact"}</span>
                    </div>
                    <div className="mt-2 break-all font-mono text-xs text-slate-500">{artifact.path}</div>
                  </div>
                ))
              ) : (
                <EmptyState title="No artifacts" description="This tool result did not persist any files." icon={FileText} />
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function App() {
  const [section, setSection] = useState<SectionId>("overview");
  const [health, setHealth] = useState<{ status: string; service: string } | null>(null);
  const [enginePulse, setEnginePulse] = useState<EnginePulseView | null>(null);
  const [modelSettings, setModelSettings] = useState<OllamaModelView | null>(null);
  const [dashboard, setDashboard] = useState<DashboardView | null>(null);
  const [runs, setRuns] = useState<RunView[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [selectedRun, setSelectedRun] = useState<RunView | null>(null);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);
  const [evidenceTab, setEvidenceTab] = useState<EvidenceTab>("parsed");
  const [report, setReport] = useState<ReportResponse | null>(null);
  const [plannerResult, setPlannerResult] = useState<LLMPlannerResponse | null>(null);
  const [scopeUpload, setScopeUpload] = useState<ScopeUploadResponse | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scopeFile, setScopeFile] = useState<File | null>(null);
  const [scopeProfile, setScopeProfile] = useState("passive-only");
  const [scopeActivate, setScopeActivate] = useState(true);
  const [templateDraft, setTemplateDraft] = useState({
    template_id: "web-surface-mapping",
    scope_name: "",
    target_url: "",
    allowed_subdomains: "www, app",
    login_areas_allowed: "/login",
    apis_allowed: "/api",
    tool_allowlist: "",
    authorization_note: "Authorized by the site owner for defensive assessment only.",
    contacts: "",
    notes: "",
    profile: "passive-only",
    activate: true,
  });
  const [generatedTemplate, setGeneratedTemplate] = useState<ScopeTemplateResponse | null>(null);
  const [templateBusy, setTemplateBusy] = useState(false);
  const [runProfile, setRunProfile] = useState("passive-only");
  const [manualNotes, setManualNotes] = useState("");
  const [includeApprovedActive, setIncludeApprovedActive] = useState(false);
  const [plannerModel, setPlannerModel] = useState("");
  const [useBackendDefaultModel, setUseBackendDefaultModel] = useState(true);
  const [scopeResetConfirm, setScopeResetConfirm] = useState("");
  const [scopeRunsDeleteConfirm, setScopeRunsDeleteConfirm] = useState("");
  const [purgeOpen, setPurgeOpen] = useState(false);
  const [purgeConfirm, setPurgeConfirm] = useState("");
  const [purgeBusy, setPurgeBusy] = useState(false);
  const [approvalDrafts, setApprovalDrafts] = useState<
    Record<string, { approved_by: string; note: string }>
  >({});
  const liveReloadBusy = useRef(false);

  async function refreshSnapshot() {
    try {
      const [healthData, dashboardData, runList, modelData, pulseData] = await Promise.all([
        api.health(),
        api.dashboard(),
        api.runs(12),
        api.ollamaModel(),
        api.enginePulse(),
      ]);
      setHealth(healthData);
      setDashboard(dashboardData);
      setRuns(runList);
      setModelSettings(modelData);
      setPlannerModel((current) => current || modelData.selected_model);
      setEnginePulse(pulseData);
      const runIds = new Set(runList.map((run) => run.id));
      const scopedRuns = dashboardData.current_scope?.id
        ? runList.filter((run) => run.scope_id === dashboardData.current_scope?.id)
        : runList;
      const nextRunId = dashboardData.latest_run?.id ?? scopedRuns[0]?.id ?? runList[0]?.id ?? null;
      if (!selectedRunId || (selectedRunId && !runIds.has(selectedRunId))) {
        setSelectedRunId(nextRunId);
      }
    } catch (caught) {
      setError(normalizeError(caught));
    }
  }

  async function refreshSelectedRun(runId: string) {
    try {
      const [runData, reportData] = await Promise.all([api.run(runId), api.report(runId)]);
      setSelectedRun(runData);
      setReport(reportData);
    } catch (caught) {
      setError(normalizeError(caught));
    }
  }

  useEffect(() => {
    void refreshSnapshot();
    const timer = window.setInterval(() => {
      void refreshSnapshot();
    }, 12000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (selectedRunId) {
      void refreshSelectedRun(selectedRunId);
      return;
    }
    setSelectedRun(null);
    setReport(null);
  }, [selectedRunId]);

  useEffect(() => {
    if (!selectedRun || !selectedRunId || !liveStates.has(selectedRun.state)) {
      return;
    }
    const source = new EventSource(apiUrl(`/api/runs/${encodeURIComponent(selectedRunId)}/stream`));
    source.onmessage = () => {
      if (liveReloadBusy.current) {
        return;
      }
      liveReloadBusy.current = true;
      void refreshSelectedRun(selectedRunId).finally(() => {
        liveReloadBusy.current = false;
      });
      void refreshSnapshot();
    };
    source.onerror = () => source.close();
    return () => source.close();
  }, [selectedRun?.state, selectedRunId]);

  useEffect(() => {
    const activeScopeId = dashboard?.current_scope?.id ?? null;
    const scopedRunList = activeScopeId ? runs.filter((run) => run.scope_id === activeScopeId) : runs;
    const nextRun = dashboard?.latest_run?.id ?? scopedRunList[0]?.id ?? runs[0]?.id ?? null;
    if (!selectedRunId || !scopedRunList.some((run) => run.id === selectedRunId)) {
      if (nextRun !== selectedRunId) {
        setSelectedRunId(nextRun);
      }
    }
  }, [dashboard?.current_scope?.id, dashboard?.latest_run?.id, runs, selectedRunId]);

  useEffect(() => {
    if (useBackendDefaultModel && modelSettings?.selected_model) {
      setPlannerModel(modelSettings.selected_model);
    }
  }, [modelSettings, useBackendDefaultModel]);

  const currentScope = dashboard?.current_scope ?? null;
  const currentPlan = dashboard?.current_plan ?? scopeUpload?.plan ?? null;
  const currentRun = selectedRun ?? dashboard?.latest_run ?? null;
  const visibleRuns = currentScope ? runs.filter((run) => run.scope_id === currentScope.id) : runs;
  const scopedRuns = visibleRuns.length > 0 ? visibleRuns : runs;
  const currentEvidenceResults = currentRun?.tool_results ?? [];
  const currentEvidenceCorrelation = currentRun?.evidence_correlation ?? null;
  const selectedEvidenceResult =
    currentEvidenceResults.find((result) => String(result.id) === selectedEvidenceId) ?? currentEvidenceResults[0] ?? null;

  useEffect(() => {
    if (currentEvidenceResults.length === 0) {
      if (selectedEvidenceId !== null) {
        setSelectedEvidenceId(null);
      }
      return;
    }
    const nextEvidenceId = String(currentEvidenceResults[0].id);
    if (!selectedEvidenceId || !currentEvidenceResults.some((result) => String(result.id) === selectedEvidenceId)) {
      if (selectedEvidenceId !== nextEvidenceId) {
        setSelectedEvidenceId(nextEvidenceId);
      }
    }
  }, [currentRun?.id, currentEvidenceResults, selectedEvidenceId]);

  const approvalQueue = currentRun
    ? currentRun.actions.filter(
        (action) =>
          action.classification !== "PASSIVE_SAFE" && ["queued", "pending-approval"].includes(action.status),
      )
    : dashboard?.pending_approvals ?? [];
  const reportText = report?.report_text ?? currentRun?.report_text ?? "";
  const reportLink = currentRun ? api.reportUrl(currentRun.id) : null;
  const planSummary = currentPlan ? planActionSummary(currentPlan.actions) : "No validated scope is loaded yet.";
  const planCounts = currentPlan
    ? {
        passive: currentPlan.actions.filter((action) => action.classification === "PASSIVE_SAFE").length,
        active: currentPlan.actions.filter((action) => action.classification !== "PASSIVE_SAFE").length,
        allowed: currentPlan.actions.filter((action) => action.allowed_by_scope).length,
        blocked: currentPlan.actions.filter((action) => !action.allowed_by_scope).length,
      }
    : { passive: 0, active: 0, allowed: 0, blocked: 0 };

  async function handleScopeUpload() {
    if (!scopeFile) {
      setError("Choose a scope YAML file before uploading.");
      return;
    }
    setBusyAction("scope-upload");
    setError(null);
    try {
      const response = await api.uploadScope(scopeFile, scopeProfile, scopeActivate);
      setScopeUpload(response);
      setSection("scope");
      setSelectedRunId(null);
      await refreshSnapshot();
    } catch (caught) {
      setError(normalizeError(caught));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleTemplateGenerate() {
    if (!templateDraft.target_url.trim()) {
      setError("Enter a target URL before generating a scope template.");
      return;
    }
    setTemplateBusy(true);
    setError(null);
    try {
      const response = await api.generateScopeTemplate({
        template_id: templateDraft.template_id,
        scope_name: templateDraft.scope_name.trim(),
        target_url: templateDraft.target_url.trim(),
        allowed_subdomains: splitEntries(templateDraft.allowed_subdomains),
        login_areas_allowed: splitEntries(templateDraft.login_areas_allowed),
        apis_allowed: splitEntries(templateDraft.apis_allowed),
        tool_allowlist: splitEntries(templateDraft.tool_allowlist),
        authorization_note: templateDraft.authorization_note.trim(),
        contacts: splitEntries(templateDraft.contacts),
        notes: templateDraft.notes.trim() || null,
        profile: templateDraft.profile,
        activate: templateDraft.activate,
      });
      setGeneratedTemplate(response);
      setScopeUpload({
        scope: response.scope,
        plan: response.plan,
        validation_message: response.validation_message,
      });
      setSelectedRunId(null);
      setSection("scope");
      await refreshSnapshot();
    } catch (caught) {
      setError(normalizeError(caught));
    } finally {
      setTemplateBusy(false);
    }
  }

  async function handleStartRun() {
    setBusyAction("start-run");
    setError(null);
    try {
      const createdRun = await api.startRun({
        profile: runProfile,
        manual_notes: manualNotes || null,
        include_approved_active: includeApprovedActive,
      });
      setSelectedRunId(createdRun.id);
      setSection("run");
      await refreshSnapshot();
    } catch (caught) {
      setError(normalizeError(caught));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleSaveModel() {
    const model = plannerModel.trim();
    if (!model) {
      setError("Enter a model before saving it.");
      return;
    }
    setBusyAction("save-model");
    setError(null);
    try {
      const response = await api.setOllamaModel(model);
      setModelSettings(response);
      setPlannerModel(response.selected_model);
      setUseBackendDefaultModel(true);
      await refreshSnapshot();
    } catch (caught) {
      setError(normalizeError(caught));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleWorkspacePurge() {
    setPurgeBusy(true);
    setError(null);
    try {
      await api.purgeWorkspace({ confirmation: purgeConfirm });
      setPurgeConfirm("");
      setPurgeOpen(false);
      setSelectedRunId(null);
      setSelectedRun(null);
      setReport(null);
      setScopeUpload(null);
      setGeneratedTemplate(null);
      setPlannerResult(null);
      setSelectedEvidenceId(null);
      setEvidenceTab("parsed");
      setPlannerModel("");
      setUseBackendDefaultModel(true);
      await refreshSnapshot();
    } catch (caught) {
      setError(normalizeError(caught));
    } finally {
      setPurgeBusy(false);
    }
  }

  async function handleResetCurrentScope() {
    if (scopeResetConfirm.trim() !== "RESET_SCOPE") {
      setError("Type RESET_SCOPE to reset the current scope.");
      return;
    }
    setBusyAction("reset-scope");
    setError(null);
    try {
      await api.resetCurrentScope("RESET_SCOPE");
      setSelectedRunId(null);
      setSelectedRun(null);
      setReport(null);
      setPlannerResult(null);
      setSelectedEvidenceId(null);
      setEvidenceTab("parsed");
      setScopeResetConfirm("");
      await refreshSnapshot();
    } catch (caught) {
      setError(normalizeError(caught));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleDeleteCurrentScopeRuns() {
    if (scopeRunsDeleteConfirm.trim() !== "DELETE_RUNS") {
      setError("Type DELETE_RUNS to delete runs for the current scope.");
      return;
    }
    setBusyAction("delete-scope-runs");
    setError(null);
    try {
      await api.deleteCurrentScopeRuns("DELETE_RUNS");
      setSelectedRunId(null);
      setSelectedRun(null);
      setReport(null);
      setPlannerResult(null);
      setSelectedEvidenceId(null);
      setEvidenceTab("parsed");
      setScopeRunsDeleteConfirm("");
      await refreshSnapshot();
    } catch (caught) {
      setError(normalizeError(caught));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleApprove(action: RunActionView) {
    const draft = approvalDrafts[action.action_id] ?? {
      approved_by: "analyst",
      note: "Reviewed in the Pengetic GUI.",
    };
    const payload: ApprovalCreateRequest = {
      run_id: currentRun?.id ?? action.run_id,
      action_id: action.action_id,
      approved_by: draft.approved_by,
      note: draft.note,
    };
    setBusyAction(`approve-${action.action_id}`);
    setError(null);
    try {
      await api.approveAction(payload);
      await Promise.all([refreshSelectedRun(payload.run_id), refreshSnapshot()]);
    } catch (caught) {
      setError(normalizeError(caught));
    } finally {
      setBusyAction(null);
    }
  }

  async function handlePlanner(navigateToPlanner = true) {
    setBusyAction("planner");
    setError(null);
    try {
      const modelToUse = useBackendDefaultModel ? null : plannerModel.trim() || null;
      if (modelToUse) {
        await api.setOllamaModel(modelToUse);
      }
      const response = await api.planner({
        run_id: currentRun?.id ?? null,
        scope_id: currentScope?.id ?? null,
        model: modelToUse,
      });
      setPlannerResult(response);
      if (navigateToPlanner) {
        setSection("planner");
      }
    } catch (caught) {
      setError(normalizeError(caught));
    } finally {
      setBusyAction(null);
    }
  }

  const overviewMetrics = [
    {
      label: "Runs",
      value: formatCount(dashboard?.counts?.runs),
      detail: "Persisted assessment runs in the local SQLite store.",
      tone: "text-red-200",
    },
    {
      label: "Findings",
      value: formatCount(dashboard?.counts?.findings),
      detail: "Normalized findings with redacted evidence.",
      tone: "text-rose-200",
    },
    {
      label: "Pending approvals",
      value: formatCount(dashboard?.counts?.pending_approvals),
      detail: "Queued non-passive actions that still require a decision.",
      tone: "text-amber-200",
    },
    {
      label: "Approved active",
      value: formatCount(dashboard?.counts?.approved_actions),
      detail: "Active steps that have explicit approval on record.",
      tone: "text-red-100",
    },
    {
      label: "Engine pulse",
      value: enginePulse?.status ?? "unknown",
      detail: modelSettings?.selected_model
        ? `${modelSettings.selected_model} ${enginePulse?.selected_model_available ? "available" : "needs attention"}`
        : "LLM health is checked via the Ollama Tags API.",
      tone: enginePulse?.status === "ok" ? "text-red-100" : "text-amber-200",
    },
  ];

  const sidebarState = dashboard?.state ?? "idle";
  const selectedModelName = modelSettings?.selected_model ?? enginePulse?.selected_model ?? "Not set";
  const suggestedModel = enginePulse?.available_models.find((name) => name !== selectedModelName) ?? enginePulse?.available_models[0] ?? null;
  const modelUnavailable = enginePulse?.selected_model_available === false;
  const primaryAssessmentLabel = !currentScope
    ? "Create assessment"
    : currentRun
      ? currentRun.state === "awaiting_approval"
        ? "Review approvals"
        : currentRun.state === "completed"
          ? "View report"
          : "Continue assessment"
      : "Start assessment";
  const primaryAssessmentAction =
    !currentScope
      ? () => setSection("scope")
      : currentRun
        ? currentRun.state === "awaiting_approval"
          ? () => setSection("approvals")
          : currentRun.state === "completed"
            ? () => setSection("reports")
            : () => setSection("run")
        : () => void handleStartRun();
  const nextStepText = !currentScope
    ? "Create an assessment to begin."
    : currentRun
      ? currentRun.state === "awaiting_approval"
        ? "Review approvals to continue."
        : liveStates.has(currentRun.state)
          ? "Assessment is running. Watch progress in Results."
          : currentRun.state === "completed"
            ? "View the report."
            : "Continue the assessment."
      : "Start the assessment.";

  return (
    <div className="relative min-h-screen">
      <div className="relative mx-auto flex min-h-screen w-full max-w-[1800px] flex-col gap-6 px-4 py-4 lg:flex-row lg:px-6">
        <aside className="w-full lg:sticky lg:top-4 lg:h-[calc(100vh-2rem)] lg:w-[340px]">
          <div className={cx(panelBase, "flex h-full flex-col p-5")}>
            <div className="space-y-3 border-b border-white/5 pb-5">
              <div className="space-y-3">
                <BrandLogo className="max-w-[220px] drop-shadow-[0_0_28px_rgba(215,0,0,0.45)]" />
                <div>
                  <div className="text-lg font-semibold tracking-tight text-white">Pengetic</div>
                  <div className="text-sm text-slate-400">Local-first defensive web assessment platform</div>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <Badge className={stateTone(sidebarState)}>{titleCase(sidebarState)}</Badge>
                <Badge className="border-white/10 bg-white/5 text-slate-200">
                  {health ? `${health.service} ${health.status}` : "Backend offline"}
                </Badge>
              </div>
            </div>

            <nav className="mt-5 space-y-2">
              {sections.map((item) => (
                <SectionButton
                  key={item.id}
                  item={item}
                  active={section === item.id}
                  onClick={() => setSection(item.id)}
                />
              ))}
            </nav>

            <div className="mt-6 grid gap-3 rounded-3xl border border-red-400/10 bg-red-400/5 p-4">
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.24em] text-red-300/80">
                <ShieldCheck className="h-4 w-4" />
                Safety model
              </div>
              <div className="space-y-2 text-sm leading-6 text-slate-300">
                <p>Scope-bound execution only.</p>
                <p>Passive-safe actions run automatically.</p>
                <p>Active actions require explicit approval.</p>
                <p>No unrestricted shell or autonomous exploitation.</p>
              </div>
            </div>

            <div className="mt-auto space-y-3 border-t border-white/5 pt-5 text-xs text-slate-500">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-red-300/70" />
                Stored runs, approvals, findings, and evidence.
              </div>
              <div className="flex items-center gap-2">
                <TerminalSquare className="h-4 w-4 text-red-300/70" />
                Guidance uses Ollama through the OpenAI-compatible API.
              </div>
            </div>
          </div>
        </aside>

        <main className="min-w-0 flex-1 space-y-6">
          <header className={panelBase}>
            <div className="flex flex-col gap-6 p-6 lg:flex-row lg:items-start lg:justify-between">
              <div className="max-w-4xl space-y-4">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge className={stateTone(sidebarState)}>{titleCase(sidebarState)}</Badge>
                  <Badge className="border-red-400/20 bg-red-400/10 text-red-200">
                    {currentScope ? currentScope.name : "No validated scope loaded"}
                  </Badge>
                  <Badge className="border-white/10 bg-white/5 text-slate-200">
                    {currentRun ? "Latest run loaded" : "No run selected"}
                  </Badge>
                </div>
                <div className="space-y-2">
                  <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">
                    Pengetic assessment console
                  </h1>
                  <p className="max-w-3xl text-sm leading-7 text-slate-400 sm:text-base">
                    Target, mode, start. Review results, approve gated steps, and export the report.
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-3 text-sm text-slate-400">
                  <span className="flex items-center gap-2">
                    <Clock3 className="h-4 w-4 text-red-300/70" />
                    {health ? `Connected to ${health.service}` : "Awaiting backend health"}
                  </span>
                  <span className="flex items-center gap-2">
                    <ArrowUpRight className="h-4 w-4 text-red-300/70" />
                    Local-first, scope-bound, approval-gated
                  </span>
                </div>
              </div>

              <div className="flex flex-wrap gap-2">
                <button type="button" onClick={() => void refreshSnapshot()} className={buttonBase}>
                  <RefreshCw className="h-4 w-4" />
                  Refresh
                </button>
                <button
                  type="button"
                  onClick={() => setSection("planner")}
                  className={cx(buttonBase, "border-red-400/20 bg-red-500/10 text-red-100")}
                >
                  <Brain className="h-4 w-4" />
                  Settings
                </button>
              </div>
            </div>
            {error ? (
              <div className="border-t border-rose-400/10 bg-rose-400/10 px-6 py-4 text-sm text-rose-200">
                {error}
              </div>
            ) : null}
          </header>

          {dashboard ? (
            <>
              {section === "overview" ? (
                <div className="space-y-6">
                  <div className={cx(panelBase, "p-6")}>
                    <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
                      <div className="max-w-3xl space-y-3">
                        <p className="text-[0.72rem] font-semibold uppercase tracking-[0.28em] text-red-300/80">
                          Assessment
                        </p>
                        <h2 className="text-2xl font-semibold tracking-tight text-white sm:text-3xl">
                          {currentScope ? currentScope.name : "Create an assessment to begin"}
                        </h2>
                        <p className="text-sm leading-6 text-slate-400">
                          {currentScope
                            ? "Confirm the target, choose a scan mode, and continue the active assessment."
                            : "Create an assessment, choose a target, and Pengetic will guide the next step."}
                        </p>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <button type="button" onClick={() => setSection("scope")} className={buttonBase}>
                          <Upload className="h-4 w-4" />
                          {currentScope ? "Change target" : "Choose target"}
                        </button>
                        <button
                          type="button"
                          onClick={primaryAssessmentAction}
                          className={cx(buttonBase, "border-red-400/20 bg-red-500/10 text-red-100")}
                          disabled={primaryAssessmentLabel === "Start assessment" ? busyAction === "start-run" : false}
                        >
                          {busyAction === "start-run" ? <RefreshCw className="h-4 w-4 animate-spin" /> : currentRun ? <PlayCircle className="h-4 w-4" /> : <Upload className="h-4 w-4" />}
                          {primaryAssessmentLabel}
                        </button>
                      </div>
                    </div>

                    <div className="mt-6 grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
                      <div className="grid gap-4">
                        <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-5">
                          <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
                            <Target className="h-4 w-4 text-red-300/80" />
                            Current target
                          </div>
                          {currentScope ? (
                            <div className="grid gap-3">
                              <LabeledValue label="Target" value={currentScope.name} />
                              <LabeledValue label="Address" value={currentScope.base_url} />
                              <details className="rounded-3xl border border-white/10 bg-slate-950/70 p-4">
                                <summary className="cursor-pointer list-none text-sm font-semibold text-white">Advanced</summary>
                                <div className="mt-4 grid gap-3">
                                  <LabeledValue label="Hosts" value={shortList(currentScope.authorized_hosts)} />
                                  <LabeledValue label="Routes" value={shortList([...currentScope.login_areas_allowed, ...currentScope.apis_allowed])} />
                                  <LabeledValue label="Tools" value={shortList(currentScope.tool_allowlist)} />
                                </div>
                              </details>
                            </div>
                          ) : (
                            <EmptyState title="No assessment yet" description="Create one to begin." icon={Upload} />
                          )}
                        </div>

                        <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-5">
                          <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
                            <Radar className="h-4 w-4 text-red-300/80" />
                            Current step
                          </div>
                          <div className="grid gap-4 md:grid-cols-2">
                            <div className="space-y-2">
                              <Label text="Scan mode" hint="Choose the run profile" />
                              <select value={runProfile} onChange={(event) => setRunProfile(event.target.value)} className={selectBase}>
                                <option value="passive-only">Passive</option>
                                <option value="report-only">Report only</option>
                                <option value="lab-safe">Lab safe</option>
                              </select>
                            </div>
                            <div className="space-y-2">
                              <Label text="Approved active" hint="Allow approved active steps" />
                              <label className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-slate-200">
                                <input
                                  type="checkbox"
                                  checked={includeApprovedActive}
                                  onChange={(event) => setIncludeApprovedActive(event.target.checked)}
                                  className="h-4 w-4 rounded border-slate-600 bg-slate-950 text-red-500 focus:ring-red-400/30"
                                />
                                Approved active steps
                              </label>
                            </div>
                          </div>
                          <details className="mt-4 rounded-3xl border border-white/10 bg-slate-950/70 p-4">
                            <summary className="cursor-pointer list-none text-sm font-semibold text-white">Advanced</summary>
                            <div className="mt-4 space-y-2">
                              <Label text="Manual notes" hint="Stored with the run and redacted on write" />
                              <textarea
                                value={manualNotes}
                                onChange={(event) => setManualNotes(event.target.value)}
                                rows={3}
                                className={textareaBase}
                                placeholder="Optional analyst notes."
                              />
                            </div>
                          </details>
                        </div>
                      </div>

                      <div className="grid gap-4">
                        <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-5">
                          <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
                            <Gauge className="h-4 w-4 text-red-300/80" />
                            Next step
                          </div>
                          <div className="rounded-2xl border border-red-400/20 bg-red-500/10 p-4 text-sm leading-6 text-red-50">
                            {nextStepText}
                          </div>
                          <div className="mt-4 flex flex-col gap-2">
                            <button
                              type="button"
                              onClick={primaryAssessmentAction}
                              className={cx(buttonBase, "w-full border-red-400/20 bg-red-400/15 text-red-50 hover:bg-red-400/20")}
                              disabled={primaryAssessmentLabel === "Start assessment" ? busyAction === "start-run" : false}
                            >
                              {busyAction === "start-run" ? (
                                <RefreshCw className="h-4 w-4 animate-spin" />
                              ) : currentRun ? (
                                <PlayCircle className="h-4 w-4" />
                              ) : (
                                <Upload className="h-4 w-4" />
                              )}
                              {primaryAssessmentLabel}
                            </button>
                            <button type="button" onClick={() => setSection("run")} className={buttonBase}>
                              <FileText className="h-4 w-4" />
                              View results
                            </button>
                          </div>
                        </div>

                        <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-5">
                          <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
                            <Clock3 className="h-4 w-4 text-red-300/80" />
                            Current status
                          </div>
                          <div className="grid gap-3">
                            <LabeledValue label="Status" value={titleCase(dashboard.state)} />
                            <LabeledValue
                              label="AI"
                              value={enginePulse?.selected_model ? `${enginePulse.selected_model}${enginePulse.selected_model_available === false ? " unavailable" : " ready"}` : "AI unavailable"}
                            />
                            <LabeledValue label="Progress" value={currentRun ? titleCase(currentRun.state) : "Start"} />
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : null}
              {section === "scope" ? (
                <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
                  <div className="space-y-6">
                  <Card eyebrow="Upload" title="Scope upload and validation">
                    <div className="space-y-5">
                      <div className="space-y-2">
                        <Label text="Scope file" hint="YAML package from the site owner" />
                        <input
                          type="file"
                          accept=".yaml,.yml,text/yaml,text/plain"
                          onChange={(event) => setScopeFile(event.target.files?.[0] ?? null)}
                          className="block w-full cursor-pointer rounded-2xl border border-dashed border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-slate-300 file:mr-4 file:rounded-full file:border-0 file:bg-red-400/15 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-red-100 hover:border-red-400/20"
                        />
                        {scopeFile ? <p className="text-xs text-slate-500">Selected: {scopeFile.name}</p> : null}
                      </div>

                      <div className="grid gap-4 md:grid-cols-2">
                        <div className="space-y-2">
                          <Label text="Profile" hint="Generates the plan with the same gate" />
                          <select
                            value={scopeProfile}
                            onChange={(event) => setScopeProfile(event.target.value)}
                            className={selectBase}
                          >
                            <option value="passive-only">passive-only</option>
                            <option value="report-only">report-only</option>
                            <option value="lab-safe">lab-safe</option>
                          </select>
                        </div>
                        <div className="space-y-2">
                          <Label text="Activate plan" hint="Store as current plan" />
                          <label className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-slate-200">
                            <input
                              type="checkbox"
                              checked={scopeActivate}
                              onChange={(event) => setScopeActivate(event.target.checked)}
                              className="h-4 w-4 rounded border-slate-600 bg-slate-950 text-red-500 focus:ring-red-400/30"
                            />
                            Activate generated plan
                          </label>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={handleScopeUpload}
                        className={cx(buttonBase, "w-full border-red-400/20 bg-red-400/15 text-red-50")}
                        disabled={busyAction === "scope-upload"}
                      >
                        {busyAction === "scope-upload" ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
                        Upload and validate scope
                      </button>

                      {scopeUpload ? (
                        <div className="grid gap-4 rounded-3xl border border-emerald-400/15 bg-emerald-400/5 p-5">
                          <div className="flex items-center gap-2 text-sm font-semibold text-emerald-200">
                            <ShieldCheck className="h-4 w-4" />
                            {scopeUpload.validation_message}
                          </div>
                          <div className="grid gap-4 md:grid-cols-2">
                            <LabeledValue label="Scope" value={scopeUpload.scope.name} />
                            <LabeledValue label="Plan" value={scopeUpload.plan.id} />
                          </div>
                          <LabeledValue label="Generated actions" value={scopeUpload.plan.actions.length} />
                        </div>
                      ) : null}
                    </div>
                  </Card>
                  <Card eyebrow="Templates" title="One-click scope generation">
                    <div className="space-y-5">
                      <div className="grid gap-4 md:grid-cols-2">
                        <div className="space-y-2">
                          <Label text="Template" hint="Pre-populates the validated scope" />
                          <select
                            value={templateDraft.template_id}
                            onChange={(event) =>
                              setTemplateDraft((current) => ({
                                ...current,
                                template_id: event.target.value,
                                tool_allowlist:
                                  event.target.value === "api-surface-mapping"
                                    ? "header-review, tls-review, robots-fetch, sitemap-fetch, route-inventory, tech-fingerprint, manual-review, nmap-service-discovery, approved-api-surface-probe"
                                    : event.target.value === "internal-audit"
                                      ? "header-review, tls-review, robots-fetch, sitemap-fetch, route-inventory, tech-fingerprint, manual-review, nmap-service-discovery, approved-login-surface-probe, approved-api-surface-probe"
                                      : "header-review, tls-review, robots-fetch, sitemap-fetch, route-inventory, tech-fingerprint, manual-review, nmap-service-discovery",
                              }))
                            }
                            className={selectBase}
                          >
                            <option value="web-surface-mapping">Web Surface Mapping</option>
                            <option value="internal-audit">Internal Audit</option>
                            <option value="api-surface-mapping">API Surface Mapping</option>
                          </select>
                        </div>
                        <div className="space-y-2">
                          <Label text="Scope name" hint="Stored in SQLite and the report" />
                          <input
                            value={templateDraft.scope_name}
                            onChange={(event) =>
                              setTemplateDraft((current) => ({ ...current, scope_name: event.target.value }))
                            }
                            className={inputBase}
                            placeholder="Pengetic assessment"
                          />
                        </div>
                      </div>

                      <div className="grid gap-4 md:grid-cols-2">
                        <div className="space-y-2">
                          <Label text="Target URL" hint="Root URL for the generated scope" />
                          <input
                            value={templateDraft.target_url}
                            onChange={(event) =>
                              setTemplateDraft((current) => ({ ...current, target_url: event.target.value }))
                            }
                            className={inputBase}
                            placeholder="https://example.com"
                          />
                        </div>
                        <div className="space-y-2">
                          <Label text="Contacts" hint="Comma-separated authorization contacts" />
                          <input
                            value={templateDraft.contacts}
                            onChange={(event) =>
                              setTemplateDraft((current) => ({ ...current, contacts: event.target.value }))
                            }
                            className={inputBase}
                            placeholder="security@example.com, ops@example.com"
                          />
                        </div>
                      </div>

                      <div className="grid gap-4 md:grid-cols-3">
                        <div className="space-y-2">
                          <Label text="Allowed subdomains" hint="Comma-separated" />
                          <input
                            value={templateDraft.allowed_subdomains}
                            onChange={(event) =>
                              setTemplateDraft((current) => ({ ...current, allowed_subdomains: event.target.value }))
                            }
                            className={inputBase}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label text="Login areas" hint="Comma-separated paths" />
                          <input
                            value={templateDraft.login_areas_allowed}
                            onChange={(event) =>
                              setTemplateDraft((current) => ({ ...current, login_areas_allowed: event.target.value }))
                            }
                            className={inputBase}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label text="API routes" hint="Comma-separated paths" />
                          <input
                            value={templateDraft.apis_allowed}
                            onChange={(event) =>
                              setTemplateDraft((current) => ({ ...current, apis_allowed: event.target.value }))
                            }
                            className={inputBase}
                          />
                        </div>
                      </div>

                      <div className="space-y-2">
                        <Label text="Authorization note" hint="Required for the generated scope" />
                        <textarea
                          value={templateDraft.authorization_note}
                          onChange={(event) =>
                            setTemplateDraft((current) => ({ ...current, authorization_note: event.target.value }))
                          }
                          rows={3}
                          className={textareaBase}
                        />
                      </div>

                      <div className="space-y-2">
                        <Label text="Tool allowlist" hint="Leave blank to use the template defaults" />
                        <textarea
                          value={templateDraft.tool_allowlist}
                          onChange={(event) =>
                            setTemplateDraft((current) => ({ ...current, tool_allowlist: event.target.value }))
                          }
                          rows={3}
                          className={textareaBase}
                        />
                      </div>

                      <div className="space-y-2">
                        <Label text="Notes" hint="Optional analyst note or context" />
                        <textarea
                          value={templateDraft.notes}
                          onChange={(event) =>
                            setTemplateDraft((current) => ({ ...current, notes: event.target.value }))
                          }
                          rows={3}
                          className={textareaBase}
                        />
                      </div>

                      <div className="grid gap-4 md:grid-cols-2">
                        <div className="space-y-2">
                          <Label text="Profile" hint="Matches the generated plan" />
                          <select
                            value={templateDraft.profile}
                            onChange={(event) =>
                              setTemplateDraft((current) => ({ ...current, profile: event.target.value }))
                            }
                            className={selectBase}
                          >
                            <option value="passive-only">passive-only</option>
                            <option value="report-only">report-only</option>
                            <option value="lab-safe">lab-safe</option>
                          </select>
                        </div>
                        <div className="space-y-2">
                          <Label text="Activate" hint="Store as the current scope and plan" />
                          <label className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-slate-200">
                            <input
                              type="checkbox"
                              checked={templateDraft.activate}
                              onChange={(event) =>
                                setTemplateDraft((current) => ({ ...current, activate: event.target.checked }))
                              }
                              className="h-4 w-4 rounded border-slate-600 bg-slate-950 text-red-500 focus:ring-red-400/30"
                            />
                            Activate generated scope and plan
                          </label>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={handleTemplateGenerate}
                        className={cx(buttonBase, "w-full border-red-400/20 bg-red-500/15 text-red-50")}
                        disabled={templateBusy}
                      >
                        {templateBusy ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                        Generate scope template
                      </button>

                      {generatedTemplate ? (
                        <div className="space-y-4 rounded-3xl border border-red-400/15 bg-red-500/5 p-5">
                          <div className="flex flex-wrap items-center gap-2 text-sm font-semibold text-red-100">
                            <ShieldCheck className="h-4 w-4" />
                            {generatedTemplate.validation_message}
                          </div>
                          <div className="grid gap-4 md:grid-cols-2">
                            <LabeledValue label="Scope" value={generatedTemplate.scope.name} />
                            <LabeledValue label="Plan" value={generatedTemplate.plan.id} />
                            <LabeledValue label="Actions" value={generatedTemplate.plan.actions.length} />
                            <LabeledValue label="Template" value={generatedTemplate.template_id} />
                          </div>
                          <div className="rounded-2xl border border-white/10 bg-slate-950/80 p-4">
                            <div className="mb-2 text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">
                              Generated YAML
                            </div>
                            <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words text-xs leading-6 text-slate-200">
                              {generatedTemplate.generated_yaml}
                            </pre>
                          </div>
                        </div>
                      ) : null}
                    </div>
                  </Card>
                  </div>

                  <Card eyebrow="Validated boundary" title="Current scope record">
                    {currentScope ? (
                      <div className="grid gap-5">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge className={stateTone(dashboard.state)}>{titleCase(dashboard.state)}</Badge>
                          <Badge className="border-white/10 bg-white/5 text-slate-200">
                            Updated {formatTimestamp(currentScope.updated_at)}
                          </Badge>
                        </div>
                        <div className="grid gap-4 md:grid-cols-2">
                          <LabeledValue label="Name" value={currentScope.name} />
                          <LabeledValue label="Primary domain" value={currentScope.primary_domain} />
                          <LabeledValue label="Base URL" value={currentScope.base_url} />
                          <LabeledValue label="Authorization" value={currentScope.authorization_note} />
                          <LabeledValue label="Authorized hosts" value={shortList(currentScope.authorized_hosts)} />
                          <LabeledValue label="Allowed URLs" value={shortList(currentScope.allowed_urls)} />
                          <LabeledValue label="Login areas" value={shortList(currentScope.login_areas_allowed)} />
                          <LabeledValue label="APIs" value={shortList(currentScope.apis_allowed)} />
                          <LabeledValue label="Tool allowlist" value={shortList(currentScope.tool_allowlist)} />
                        </div>
                        {currentScope.notes ? (
                          <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-4 text-sm leading-6 text-slate-300">
                            {currentScope.notes}
                          </div>
                        ) : null}
                      </div>
                    ) : (
                      <EmptyState
                        title="No scope loaded"
                        description="Once a YAML scope is uploaded, this panel will show the validated boundary."
                        icon={Upload}
                      />
                    )}
                  </Card>
                </div>
              ) : null}
              {section === "plan" ? (
                <Card
                  eyebrow="Discovery"
                  title="Automated discovery plan"
                  description={currentPlan ? planSummary : "Upload or generate a scope to build the current discovery plan."}
                >
                  {currentPlan ? (
                    <div className="grid gap-5">
                      <div className="grid gap-4 md:grid-cols-4">
                        <MetricCard
                          label="Passive"
                          value={String(planCounts.passive)}
                          detail="Read-only checks."
                          tone="text-emerald-200"
                        />
                        <MetricCard label="Active" value={String(planCounts.active)} detail="Gated actions." tone="text-amber-200" />
                        <MetricCard
                          label="Allowed"
                          value={String(planCounts.allowed)}
                          detail="Present in allowlist."
                          tone="text-red-200"
                        />
                        <MetricCard
                          label="Blocked"
                          value={String(planCounts.blocked)}
                          detail="Excluded by scope."
                          tone="text-rose-200"
                        />
                      </div>

                      <div className="overflow-hidden rounded-3xl border border-white/10">
                        <div className="grid grid-cols-[1.2fr_0.7fr_0.8fr_0.9fr] gap-4 border-b border-white/10 bg-white/[0.03] px-5 py-3 text-[11px] font-semibold uppercase tracking-[0.24em] text-slate-400">
                          <div>Action</div>
                          <div>Risk</div>
                          <div>Scope</div>
                          <div>Evidence</div>
                        </div>
                        <div className="divide-y divide-white/5">
                          {currentPlan.actions.map((action) => (
                            <div
                              key={action.action_id}
                              className="grid gap-4 px-5 py-4 lg:grid-cols-[1.2fr_0.7fr_0.8fr_0.9fr]"
                            >
                              <div className="space-y-2">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span className="font-semibold text-white">{action.title}</span>
                                  <Badge className={riskTone(action.classification)}>{riskLabel(action.classification)}</Badge>
                                </div>
                                <p className="text-sm leading-6 text-slate-400">{action.objective}</p>
                                <div className="text-xs text-slate-500">Tool: {action.tool_id}</div>
                              </div>
                              <div className="space-y-2">
                                <Badge className={riskTone(action.classification)}>{riskLabel(action.classification)}</Badge>
                                <div className="text-xs text-slate-500">
                                  Approval {action.approval_required ? "required" : "not required"}
                                </div>
                              </div>
                              <div className="space-y-2">
                                <Badge
                                  className={cx(
                                    action.allowed_by_scope
                                      ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-200"
                                      : "border-rose-400/20 bg-rose-400/10 text-rose-200",
                                  )}
                                >
                                  {action.allowed_by_scope ? "Allowed" : "Blocked"}
                                </Badge>
                                <div className="text-xs text-slate-500">{summarizeTarget(action.target)}</div>
                              </div>
                              <div className="flex flex-wrap gap-2">
                                {action.expected_evidence.map((item) => (
                                  <Badge key={item} className="border-white/10 bg-white/5 text-slate-200">
                                    {item}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <EmptyState
                      title="No current plan"
                      description="Upload a scope package to generate a plan with risk labels and execution metadata."
                      icon={ListChecks}
                    />
                  )}
                </Card>
              ) : null}
              {section === "run" ? (
                <Card
                  eyebrow="Analysis"
                  title="State analysis and evidence"
                  description="Inspect the latest run, follow the event stream, and review findings, artifacts, and service analysis."
                  actions={
                    <div className="flex flex-wrap items-center gap-2">
                      <select
                        value={selectedRunId ?? ""}
                        onChange={(event) => setSelectedRunId(event.target.value || null)}
                        className={cx(selectBase, "max-w-[16rem]")}
                      >
                        <option value="">Select a run</option>
                        {scopedRuns.map((run) => (
                          <option key={run.id} value={run.id}>
                            {run.scope_name} | {run.profile} | {formatShortTimestamp(run.started_at)}
                          </option>
                        ))}
                      </select>
                      <button
                        type="button"
                        onClick={() => {
                          if (selectedRunId) {
                            void refreshSelectedRun(selectedRunId);
                          }
                          void refreshSnapshot();
                        }}
                        className={buttonBase}
                      >
                        <RefreshCw className="h-4 w-4" />
                        Refresh run
                      </button>
                    </div>
                  }
                >
                  {currentRun ? (
                    <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
                      <div className="space-y-4">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge className={stateTone(currentRun.state)}>{titleCase(currentRun.state)}</Badge>
                          <Badge className={statusTone(currentRun.status)}>{statusLabel(currentRun.status)}</Badge>
                          <Badge className="border-white/10 bg-white/5 text-slate-200">{currentRun.profile}</Badge>
                          <Badge className="border-white/10 bg-white/5 text-slate-200">{currentRun.actions.length} actions</Badge>
                          <Badge className="border-red-400/20 bg-red-500/10 text-red-100">
                            {currentRun.scope_name}
                          </Badge>
                        </div>
                        <details className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
                          <summary className="cursor-pointer list-none text-sm font-semibold text-white">Advanced</summary>
                          <div className="mt-4 grid gap-4 md:grid-cols-2">
                            <LabeledValue label="Run ID" value={<span className="font-mono text-xs">{currentRun.id}</span>} />
                            <LabeledValue label="Scope fingerprint" value={<span className="font-mono text-xs">{currentRun.scope_fingerprint}</span>} />
                            <LabeledValue label="Started" value={formatTimestamp(currentRun.started_at)} />
                            <LabeledValue label="Finished" value={formatTimestamp(currentRun.finished_at)} />
                          </div>
                        </details>

                        <div className="grid gap-4 lg:grid-cols-2">
                          <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
                            <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
                              <TerminalSquare className="h-4 w-4 text-red-300/80" />
                              Event log
                            </div>
                            <div className="max-h-[560px] space-y-3 overflow-auto pr-1">
                              {currentRun.events.length > 0 ? (
                                currentRun.events.map((event) => (
                                  <div key={event.id} className="rounded-2xl border border-white/10 bg-slate-950/70 p-4">
                                    <div className="flex flex-wrap items-center gap-2">
                                      <Badge className={statusTone(event.level)}>{event.level}</Badge>
                                      <span className="text-xs uppercase tracking-[0.22em] text-slate-500">
                                        {event.event_type}
                                      </span>
                                      <span className="text-xs text-slate-500">{formatTimestamp(event.created_at)}</span>
                                    </div>
                                    <div className="mt-3 text-sm leading-6 text-slate-200">{event.message}</div>
                                    {event.action_id ? (
                                      <div className="mt-2 text-xs text-slate-500">Action {event.action_id}</div>
                                    ) : null}
                                  </div>
                                ))
                          ) : (
                                <EmptyState title="No events yet" description="Events appear as the run executes." icon={TerminalSquare} />
                              )}
                            </div>
                          </div>

                          <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
                            <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
                              <Database className="h-4 w-4 text-red-300/80" />
                              Structured evidence
                            </div>
                            <div className="grid gap-4 md:grid-cols-3">
                              <MetricCard
                                label="Tools"
                                value={String(currentEvidenceCorrelation?.tool_ids.length ?? currentEvidenceResults.length)}
                                detail="Normalized tool results correlated for this run."
                                tone="text-red-100"
                              />
                              <MetricCard
                                label="Services"
                                value={String(currentEvidenceCorrelation?.service_inventory.length ?? 0)}
                                detail="Service inventory merged from diagnostic modules."
                                tone="text-white"
                              />
                              <MetricCard
                                label="Observations"
                                value={String(currentEvidenceCorrelation?.observations.length ?? 0)}
                                detail="Cross-tool summary points for planner ingestion."
                                tone="text-amber-100"
                              />
                            </div>

                            <div className="mt-4 grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
                              <div className="rounded-2xl border border-white/10 bg-slate-950/70 p-4">
                                <div className="mb-3 text-sm font-semibold text-white">Service inventory</div>
                                <div className="space-y-3">
                                  {(currentEvidenceCorrelation?.service_inventory ?? []).length > 0 ? (
                                    currentEvidenceCorrelation!.service_inventory.map((service, index) => {
                                      const record = service as Record<string, unknown>;
                                      const host = String(record.host ?? record.ip ?? record.address ?? currentRun.scope_name);
                                      const port = String(record.port ?? record.portid ?? record.service_port ?? "n/a");
                                      const serviceName = String(record.service ?? record.name ?? record.protocol ?? "service");
                                      const product = [record.product, record.version].filter(Boolean).join(" ").trim();
                                      return (
                                        <div key={`${host}-${port}-${serviceName}-${index}`} className="rounded-2xl border border-white/10 bg-white/[0.03] p-3">
                                          <div className="flex flex-wrap items-center gap-2">
                                            <Badge className="border-red-400/20 bg-red-500/10 text-red-100">{host}</Badge>
                                            <Badge className="border-white/10 bg-white/5 text-slate-200">{port}</Badge>
                                            <span className="font-semibold text-white">{serviceName}</span>
                                          </div>
                                          <div className="mt-2 text-xs text-slate-400">
                                            {product || "No version hint captured"}
                                            {record.protocol ? ` · ${String(record.protocol)}` : ""}
                                          </div>
                                          <pre className="mt-2 overflow-auto whitespace-pre-wrap break-words text-xs leading-6 text-slate-300">
                                            {formatJsonValue(record)}
                                          </pre>
                                        </div>
                                      );
                                    })
                                  ) : (
                                    <EmptyState
                                      title="No service inventory"
                                      description="Run Nmap or another approved discovery module to populate correlated service data."
                                      icon={Database}
                                    />
                                  )}
                                </div>
                              </div>

                              <div className="rounded-2xl border border-white/10 bg-slate-950/70 p-4">
                                <div className="mb-3 text-sm font-semibold text-white">Correlation notes</div>
                                <div className="space-y-2">
                                  {(currentEvidenceCorrelation?.observations ?? []).length > 0 ? (
                                    currentEvidenceCorrelation!.observations.map((observation) => (
                                      <div key={observation} className="rounded-2xl border border-white/10 bg-white/[0.03] p-3 text-sm leading-6 text-slate-300">
                                        {observation}
                                      </div>
                                    ))
                                  ) : (
                                    <EmptyState
                                      title="No cross-tool observations"
                                      description="Structured correlation will appear once multiple modules contribute evidence."
                                      icon={Workflow}
                                    />
                                  )}
                                </div>
                              </div>
                            </div>
                          </div>

                          <div className="space-y-4">
                            <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
                              <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
                                <ShieldCheck className="h-4 w-4 text-emerald-300/80" />
                                Findings
                              </div>
                              <div className="space-y-3">
                                {currentRun.findings.length > 0 ? (
                                  currentRun.findings.map((finding) => (
                                    <div
                                      key={`${finding.title}-${finding.created_at}`}
                                      className="rounded-2xl border border-white/10 bg-slate-950/70 p-4"
                                    >
                                      <div className="flex flex-wrap items-center gap-2">
                                        <Badge className={severityTone(finding.severity)}>{titleCase(finding.severity)}</Badge>
                                        <span className="font-semibold text-white">{finding.title}</span>
                                      </div>
                                      <p className="mt-2 text-sm leading-6 text-slate-300">{finding.why_it_matters}</p>
                                      <p className="mt-2 text-sm leading-6 text-slate-400">{finding.remediation}</p>
                                    </div>
                                  ))
                                ) : (
                                  <EmptyState
                                    title="No findings confirmed"
                                    description="Passive-safe checks and approved actions did not confirm findings yet."
                                    icon={ShieldCheck}
                                  />
                                )}
                              </div>
                            </div>

                            <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
                              <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
                                <FileText className="h-4 w-4 text-red-300/80" />
                                Evidence artifacts
                              </div>
                              <div className="space-y-3">
                                {currentRun.artifacts.length > 0 ? (
                                  currentRun.artifacts.map((artifact) => (
                                    <div
                                      key={artifact.id}
                                      className="rounded-2xl border border-white/10 bg-slate-950/70 p-4"
                                    >
                                      <div className="flex flex-wrap items-center gap-2">
                                        <Badge className="border-white/10 bg-white/5 text-slate-200">{artifact.kind}</Badge>
                                        <span className="font-semibold text-white">{artifact.description ?? "Artifact"}</span>
                                      </div>
                                      <div className="mt-2 break-all font-mono text-xs text-slate-400">{artifact.path}</div>
                                    </div>
                                  ))
                                ) : (
                                  <EmptyState
                                    title="No artifacts recorded"
                                    description="Evidence and report files appear here after execution."
                                    icon={FileText}
                                  />
                                )}
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="space-y-4">
                        <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
                          <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
                            <Workflow className="h-4 w-4 text-amber-300/80" />
                            Action status
                          </div>
                          <div className="space-y-3">
                      {currentRun.actions.map((action) => (
                              <div key={action.action_id} className="rounded-2xl border border-white/10 bg-slate-950/70 p-4">
                                <div className="flex flex-wrap items-center gap-2">
                                  <Badge className={statusTone(action.status)}>{statusLabel(action.status)}</Badge>
                                  <Badge className={riskTone(action.classification)}>{riskLabel(action.classification)}</Badge>
                                </div>
                                <div className="mt-3 font-semibold text-white">{action.title}</div>
                                <p className="mt-2 text-sm leading-6 text-slate-400">{action.objective}</p>
                                <div className="mt-3 text-xs text-slate-500">Tool: {action.tool_id}</div>
                                <div className="mt-1 text-xs text-slate-500">Target: {summarizeTarget(action.target)}</div>
                              </div>
                            ))}
                          </div>
                        </div>

                        <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
                          <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
                            <FileText className="h-4 w-4 text-red-300/80" />
                            Tool intelligence
                          </div>
                          <div className="grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
                            <div className="space-y-3">
                              {currentEvidenceResults.length > 0 ? (
                                currentEvidenceResults.map((result) => (
                                  <ToolResultSummary
                                    key={result.id}
                                    result={result}
                                    selected={String(result.id) === selectedEvidenceId}
                                    onSelect={() => setSelectedEvidenceId(String(result.id))}
                                  />
                                ))
                              ) : (
                                <EmptyState
                                  title="No tool results yet"
                                  description="Normalized tool results will appear here after approved diagnostics run."
                                  icon={FileText}
                                />
                              )}
                            </div>
                            <EvidenceDetail
                              result={selectedEvidenceResult}
                              activeTab={evidenceTab}
                              onTabChange={setEvidenceTab}
                            />
                          </div>
                        </div>

                      <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
                        <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
                          <Sparkles className="h-4 w-4 text-red-300/80" />
                            Planner guidance
                        </div>
                          {plannerResult ? (
                            <div className="space-y-4">
                              <div className="grid gap-4 md:grid-cols-2">
                                <LabeledValue label="What I found" value={plannerResult.summary} />
                                <LabeledValue label="What I recommend next" value={plannerResult.next_allowed_step} />
                              </div>
                              <div className="grid gap-4 md:grid-cols-2">
                                <LabeledValue label="Approval required" value={plannerResult.approval_required ? "Yes" : "No"} />
                                <LabeledValue label="Why this matters" value={plannerResult.rationale} />
                              </div>
                              <details className="rounded-3xl border border-white/10 bg-slate-950/70 p-4">
                                <summary className="cursor-pointer list-none text-sm font-semibold text-white">
                                  Advanced
                                </summary>
                                <div className="mt-4 grid gap-4">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <Badge className="border-red-400/20 bg-red-400/10 text-red-200">{plannerResult.source}</Badge>
                                    <Badge className="border-white/10 bg-white/5 text-slate-200">{plannerResult.model}</Badge>
                                    <Badge className={stateTone(currentRun.state)}>{titleCase(currentRun.state)}</Badge>
                                  </div>
                                  <div className="grid gap-4 md:grid-cols-2">
                                    <LabeledValue label="Recommended action" value={plannerResult.recommended_action_id ?? "None"} />
                                    <LabeledValue
                                      label="Likely concerns"
                                      value={plannerResult.likely_areas_of_concern.length > 0 ? plannerResult.likely_areas_of_concern.join(" / ") : "None"}
                                    />
                                  </div>
                                  <div className="grid gap-4 md:grid-cols-2">
                                    <LabeledValue
                                      label="Evidence refs"
                                      value={plannerResult.evidence_references.length > 0 ? plannerResult.evidence_references.join(" / ") : "None"}
                                    />
                                    <LabeledValue label="Confidence" value={plannerResult.confidence} />
                                  </div>
                                  <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
                                    <div className="mb-2 text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">
                                      Raw response
                                    </div>
                                    <pre className="overflow-auto whitespace-pre-wrap break-words text-xs leading-6 text-slate-300">
                                      {JSON.stringify(plannerResult.raw, null, 2)}
                                    </pre>
                                  </div>
                                </div>
                              </details>
                            </div>
                          ) : (
                            <div className="space-y-4">
                              <EmptyState
                                title="No planner guidance yet"
                                description="Ask the planner to summarize the current run and propose the next allowed step."
                                icon={Sparkles}
                              />
                              <button
                                type="button"
                                onClick={() => void handlePlanner(false)}
                                className={cx(buttonBase, "w-full border-red-400/20 bg-red-500/10 text-red-100")}
                                disabled={busyAction === "planner"}
                              >
                                {busyAction === "planner" ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Brain className="h-4 w-4" />}
                                Generate planner guidance
                              </button>
                            </div>
                          )}
                        </div>

                        <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
                          <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
                            <Sparkles className="h-4 w-4 text-red-300/80" />
                            Run summary
                          </div>
                          <div className="grid gap-4">
                            <LabeledValue label="Report" value={currentRun.report_path ?? "Pending"} />
                            <LabeledValue label="Manual notes" value={currentRun.manual_notes ?? "None"} />
                            <LabeledValue label="State" value={titleCase(currentRun.state)} />
                          </div>
                          <details className="mt-4 rounded-3xl border border-white/10 bg-slate-950/70 p-4">
                            <summary className="cursor-pointer list-none text-sm font-semibold text-white">Advanced</summary>
                            <div className="mt-4">
                              <LabeledValue label="Plan ID" value={currentRun.plan_id ?? "N/A"} />
                            </div>
                          </details>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <EmptyState title="No run selected" description="Pick a run from the selector or start a new assessment." icon={PlayCircle} />
                  )}
                </Card>
              ) : null}
              {section === "approvals" ? (
                <Card eyebrow="Evidence aggregation" title="Non-passive actions awaiting explicit approval">
                  {approvalQueue.length > 0 ? (
                    <div className="space-y-4">
                      {approvalQueue.map((action) => {
                        const draft = approvalDrafts[action.action_id] ?? {
                          approved_by: "analyst",
                          note: "Reviewed in the Pengetic GUI.",
                        };
                        return (
                          <div
                            key={action.action_id}
                            className="grid gap-4 rounded-3xl border border-white/10 bg-white/[0.03] p-5 xl:grid-cols-[1.3fr_0.9fr]"
                          >
                            <div className="space-y-3">
                              <div className="flex flex-wrap items-center gap-2">
                                <Badge className={riskTone(action.classification)}>{riskLabel(action.classification)}</Badge>
                                <Badge className={statusTone(action.status)}>{statusLabel(action.status)}</Badge>
                                <Badge className="border-white/10 bg-white/5 text-slate-200">{action.tool_id}</Badge>
                              </div>
                              <div className="text-lg font-semibold text-white">{action.title}</div>
                              <p className="text-sm leading-6 text-slate-400">{action.objective}</p>
                              <div className="grid gap-4 md:grid-cols-2">
                                <LabeledValue label="Target" value={summarizeTarget(action.target)} />
                                <LabeledValue label="Expected evidence" value={action.expected_evidence.join(" / ") || "N/A"} />
                              </div>
                            </div>

                            <div className="space-y-4 rounded-3xl border border-white/10 bg-slate-950/60 p-4">
                              <div className="space-y-2">
                                <Label text="Approver" hint="Stored with the approval event" />
                                <input
                                  value={draft.approved_by}
                                  onChange={(event) =>
                                    setApprovalDrafts((current) => ({
                                      ...current,
                                      [action.action_id]: { ...draft, approved_by: event.target.value },
                                    }))
                                  }
                                  className={inputBase}
                                />
                              </div>
                              <div className="space-y-2">
                                <Label text="Note" hint="Short rationale for the approval decision" />
                                <textarea
                                  rows={4}
                                  value={draft.note}
                                  onChange={(event) =>
                                    setApprovalDrafts((current) => ({
                                      ...current,
                                      [action.action_id]: { ...draft, note: event.target.value },
                                    }))
                                  }
                                  className={textareaBase}
                                />
                              </div>
                              <button
                                type="button"
                                onClick={() => void handleApprove(action as RunActionView)}
                                className={cx(buttonBase, "w-full border-red-400/20 bg-red-400/15 text-red-50")}
                                disabled={busyAction === `approve-${action.action_id}`}
                              >
                                {busyAction === `approve-${action.action_id}` ? (
                                  <RefreshCw className="h-4 w-4 animate-spin" />
                                ) : (
                                  <ShieldCheck className="h-4 w-4" />
                                )}
                                Record approval
                              </button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <EmptyState title="Approval queue empty" description="No gated actions are waiting on approval right now." icon={ShieldCheck} />
                  )}
                </Card>
              ) : null}
              {section === "reports" ? (
                <Card
                  eyebrow="Reporting"
                  title="Rendered Markdown report"
                  description="The assessment report is generated locally and can be exported as Markdown."
                  actions={
                    currentRun && reportLink ? (
                      <a href={reportLink} className={cx(buttonBase, "border-red-400/20 bg-red-400/15 text-red-50")}>
                        <FileDown className="h-4 w-4" />
                        Export markdown
                      </a>
                    ) : null
                  }
                >
                  {currentRun ? (
                    <div className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
                      <div className="space-y-4">
                        <div className="grid gap-4 md:grid-cols-2">
                          <LabeledValue label="Generated" value={formatTimestamp(currentRun.finished_at)} />
                          <LabeledValue label="Report path" value={currentRun.report_path ?? "Pending"} />
                          <LabeledValue label="State" value={titleCase(currentRun.state)} />
                        </div>
                        <details className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
                          <summary className="cursor-pointer list-none text-sm font-semibold text-white">Advanced</summary>
                          <div className="mt-4">
                            <LabeledValue label="Run ID" value={<span className="font-mono text-xs">{currentRun.id}</span>} />
                          </div>
                        </details>
                        <div className="rounded-3xl border border-white/10 bg-slate-950/70 p-5">
                          <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-white">
                            <FileText className="h-4 w-4 text-red-300/80" />
                            Markdown output
                          </div>
                          <pre className="max-h-[700px] overflow-auto whitespace-pre-wrap break-words rounded-2xl bg-slate-950/80 p-4 text-sm leading-7 text-slate-200">
                            {reportText || "The report is not available yet."}
                          </pre>
                        </div>
                      </div>

                      <div className="space-y-4">
                        <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-5">
                          <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
                            <Sparkles className="h-4 w-4 text-red-300/80" />
                            Report summary
                          </div>
                          <div className="grid gap-4">
                            <LabeledValue label="Scope" value={currentRun.scope_name} />
                            <LabeledValue label="Profile" value={currentRun.profile} />
                            <LabeledValue label="Findings" value={String(currentRun.findings.length)} />
                            <LabeledValue label="Artifacts" value={String(currentRun.artifacts.length)} />
                          </div>
                        </div>

                        <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-5">
                          <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
                            <FileDown className="h-4 w-4 text-red-300/80" />
                            Export notes
                          </div>
                          <p className="text-sm leading-6 text-slate-400">
                            Export uses the persisted Markdown report on disk. The file is generated from the current
                            run summary and redacted before storage.
                          </p>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <EmptyState
                      title="No report yet"
                      description="Run an assessment to generate the Markdown report and view it here."
                      icon={FileDown}
                    />
                  )}
                </Card>
              ) : null}
              {section === "planner" ? (
                <div className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
                  <Card eyebrow="Settings" title="Model and reset">
                    <div className="space-y-5">
                      {modelUnavailable ? (
                        <div className="rounded-3xl border border-amber-400/20 bg-amber-500/10 p-4 text-sm leading-6 text-amber-100">
                          <div className="font-semibold text-white">Saved model unavailable</div>
                          <div className="mt-1">
                            {selectedModelName} is not ready right now.
                            {suggestedModel ? ` Try ${suggestedModel}.` : " Pick another available model in Settings."}
                          </div>
                        </div>
                      ) : null}
                      <label className="flex items-center justify-between gap-4 rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-slate-200">
                        <span>
                          <span className="block font-semibold text-white">Use saved model</span>
                          <span className="block text-xs text-slate-500">Use the stored model unless you want a temporary override.</span>
                        </span>
                        <input
                          type="checkbox"
                          checked={useBackendDefaultModel}
                          onChange={(event) => setUseBackendDefaultModel(event.target.checked)}
                          className="h-4 w-4 rounded border-slate-600 bg-slate-950 text-red-500 focus:ring-red-400/30"
                        />
                      </label>
                      <div className="space-y-2">
                        <Label text="Model" hint={modelSettings ? `Saved: ${modelSettings.selected_model}` : "Uses backend default"} />
                        <input
                          value={plannerModel}
                          onChange={(event) => setPlannerModel(event.target.value)}
                          className={inputBase}
                          placeholder={modelSettings?.selected_model ?? "qwen2.5-coder:14b"}
                          disabled={useBackendDefaultModel}
                        />
                      </div>
                      <div className="grid gap-4 md:grid-cols-2">
                        <LabeledValue label="Current scope" value={currentScope?.name ?? "No scope"} />
                        <LabeledValue label="Current run" value={currentRun ? titleCase(currentRun.state) : "No run"} />
                        <LabeledValue label="Selected model" value={selectedModelName} />
                        <LabeledValue
                          label="Engine pulse"
                          value={enginePulse?.status ? `${enginePulse.status}${enginePulse.selected_model_available === false ? " (attention)" : ""}` : "Unknown"}
                        />
                      </div>
                      <button
                        type="button"
                        onClick={handleSaveModel}
                        className={cx(buttonBase, "w-full border-red-400/20 bg-red-500/10 text-red-100")}
                        disabled={busyAction === "save-model" || useBackendDefaultModel}
                      >
                        {busyAction === "save-model" ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Database className="h-4 w-4" />}
                        Save model
                      </button>
                      <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
                        <div className="mb-3 text-sm font-semibold text-white">Scope reset</div>
                        <div className="space-y-3">
                          <div className="space-y-2">
                            <Label text="Type RESET_SCOPE" hint="Clears the current scope link and active plan." />
                            <input value={scopeResetConfirm} onChange={(event) => setScopeResetConfirm(event.target.value)} className={inputBase} placeholder="RESET_SCOPE" />
                          </div>
                          <button
                            type="button"
                            onClick={() => void handleResetCurrentScope()}
                            className={cx(buttonBase, "w-full border-amber-400/20 bg-amber-500/10 text-amber-50")}
                            disabled={busyAction === "reset-scope" || scopeResetConfirm.trim() !== "RESET_SCOPE"}
                          >
                            {busyAction === "reset-scope" ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Workflow className="h-4 w-4" />}
                            Reset current scope
                          </button>
                          <div className="space-y-2">
                            <Label text="Type DELETE_RUNS" hint="Deletes runs for the current scope only." />
                            <input value={scopeRunsDeleteConfirm} onChange={(event) => setScopeRunsDeleteConfirm(event.target.value)} className={inputBase} placeholder="DELETE_RUNS" />
                          </div>
                          <button
                            type="button"
                            onClick={() => void handleDeleteCurrentScopeRuns()}
                            className={cx(buttonBase, "w-full border-rose-400/20 bg-rose-500/10 text-rose-50")}
                            disabled={busyAction === "delete-scope-runs" || scopeRunsDeleteConfirm.trim() !== "DELETE_RUNS"}
                          >
                            {busyAction === "delete-scope-runs" ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                            Delete current scope runs
                          </button>
                          <button
                            type="button"
                            onClick={() => setPurgeOpen(true)}
                            className={cx(buttonBase, "w-full border-red-400/20 bg-red-500/10 text-red-50")}
                          >
                            <Trash2 className="h-4 w-4" />
                            Factory reset workspace
                          </button>
                        </div>
                      </div>
                    </div>
                  </Card>

                  <Card eyebrow="Planner" title="Plain-English guidance" description="Short summary, recommended step, and approval state first.">
                    {plannerResult ? (
                      <div className="grid gap-5">
                        <div className="grid gap-4 md:grid-cols-2">
                          <LabeledValue label="What I found" value={plannerResult.summary} />
                          <LabeledValue label="What I recommend next" value={plannerResult.next_allowed_step} />
                        </div>
                        <div className="grid gap-4 md:grid-cols-2">
                          <LabeledValue label="Approval required" value={plannerResult.approval_required ? "Yes" : "No"} />
                          <LabeledValue label="Why this matters" value={plannerResult.rationale} />
                        </div>
                        <button
                          type="button"
                          onClick={() => void handlePlanner()}
                          className={cx(buttonBase, "w-full border-red-400/20 bg-red-500/15 text-red-50")}
                          disabled={busyAction === "planner"}
                        >
                          {busyAction === "planner" ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Brain className="h-4 w-4" />}
                          Refresh guidance
                        </button>
                        <details className="rounded-3xl border border-white/10 bg-slate-950/70 p-4">
                          <summary className="cursor-pointer list-none text-sm font-semibold text-white">Advanced</summary>
                          <div className="mt-4 grid gap-4">
                            <div className="flex flex-wrap items-center gap-2">
                              <Badge className="border-red-400/20 bg-red-400/10 text-red-200">{plannerResult.source}</Badge>
                              <Badge className="border-white/10 bg-white/5 text-slate-200">{plannerResult.model}</Badge>
                              <Badge className={stateTone(currentRun?.state ?? dashboard.state)}>
                                {titleCase(currentRun?.state ?? dashboard.state)}
                              </Badge>
                            </div>
                            <div className="grid gap-4 md:grid-cols-2">
                              <LabeledValue label="Recommended action" value={plannerResult.recommended_action_id ?? "None"} />
                              <LabeledValue label="Confidence" value={plannerResult.confidence} />
                            </div>
                            <div className="grid gap-4 md:grid-cols-2">
                              <LabeledValue
                                label="Likely concerns"
                                value={plannerResult.likely_areas_of_concern.length > 0 ? plannerResult.likely_areas_of_concern.join(" / ") : "None"}
                              />
                              <LabeledValue
                                label="Evidence refs"
                                value={plannerResult.evidence_references.length > 0 ? plannerResult.evidence_references.join(" / ") : "None"}
                              />
                            </div>
                            <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
                              <div className="mb-2 text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">Raw response</div>
                              <pre className="overflow-auto whitespace-pre-wrap break-words text-xs leading-6 text-slate-300">
                                {JSON.stringify(plannerResult.raw, null, 2)}
                              </pre>
                            </div>
                          </div>
                        </details>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        <EmptyState
                          title="No guidance yet"
                          description="Ask the planner to summarize the current run and suggest the next safe step."
                          icon={Brain}
                        />
                        <button
                          type="button"
                          onClick={() => void handlePlanner(false)}
                          className={cx(buttonBase, "w-full border-red-400/20 bg-red-500/10 text-red-100")}
                          disabled={busyAction === "planner"}
                        >
                          {busyAction === "planner" ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Brain className="h-4 w-4" />}
                          Generate guidance
                        </button>
                      </div>
                    )}
                  </Card>
                </div>
              ) : null}
            </>
          ) : (
            <div className="grid min-h-[60vh] place-items-center">
              <div className={cx(panelBase, "max-w-2xl p-8 text-center")}>
                <BrandLogo className="mx-auto mb-4 max-w-[280px] drop-shadow-[0_0_32px_rgba(215,0,0,0.5)]" />
                <h2 className="text-2xl font-semibold tracking-tight text-white">Bootstrapping Pengetic</h2>
                <p className="mt-3 text-sm leading-7 text-slate-400">
                  Loading the local API, SQLite store, and current assessment state. This console stays
                  scope-bound and approval-gated from the first page load.
                </p>
                <div className="mt-6 flex items-center justify-center gap-2 text-sm text-slate-400">
                  <RefreshCw className="h-4 w-4 animate-spin text-red-300/80" />
                  Waiting for dashboard data
                </div>
              </div>
            </div>
          )}

          <footer className="grid gap-4 border-t border-white/5 px-2 pb-4 pt-1 text-xs text-slate-500 lg:grid-cols-4">
            <div>Pengetic keeps all actions within validated scope boundaries.</div>
            <div>Active steps require an explicit approval record before execution.</div>
            <div className="flex items-center gap-2">
              <span>Engine pulse:</span>
              <Badge
                className={cx(
                  enginePulse?.status === "ok"
                    ? "border-red-400/20 bg-red-500/10 text-red-100"
                    : "border-amber-400/20 bg-amber-500/10 text-amber-100",
                )}
              >
                {enginePulse?.selected_model ?? modelSettings?.selected_model ?? "unknown"}
                {enginePulse?.selected_model_available === false ? " offline" : ` ${enginePulse?.status ?? "unknown"}`}
              </Badge>
            </div>
            <div>LLM planning is local and constrained to the current plan context.</div>
          </footer>

          {purgeOpen ? (
            <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/80 px-4 backdrop-blur-sm">
              <div className={cx(panelBase, "w-full max-w-2xl p-6")}>
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-[0.72rem] font-semibold uppercase tracking-[0.28em] text-red-300/80">
                      Administrative purge
                    </p>
                    <h3 className="mt-1 text-2xl font-semibold tracking-tight text-white">Clear local Pengetic state</h3>
                    <p className="mt-2 text-sm leading-6 text-slate-400">
                      This removes the SQLite database, session data, run artifacts, and generated reports from the
                      local workspace. It cannot be undone.
                    </p>
                  </div>
                  <button type="button" onClick={() => setPurgeOpen(false)} className={buttonBase}>
                    Close
                  </button>
                </div>
                <div className="mt-6 space-y-4">
                  <div className="space-y-2">
                    <Label text="Type CONFIRM_PURGE to continue" hint="Required for the reset call" />
                    <input
                      value={purgeConfirm}
                      onChange={(event) => setPurgeConfirm(event.target.value)}
                      className={inputBase}
                      placeholder="CONFIRM_PURGE"
                    />
                  </div>
                  <div className="flex flex-wrap justify-end gap-2">
                    <button type="button" onClick={() => setPurgeOpen(false)} className={buttonBase}>
                      Cancel
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleWorkspacePurge()}
                      className={cx(buttonBase, "border-red-400/20 bg-red-500/15 text-red-50")}
                      disabled={purgeBusy || purgeConfirm.trim() !== "CONFIRM_PURGE"}
                    >
                      {purgeBusy ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                      Purge workspace
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ) : null}
        </main>
      </div>
    </div>
  );
}

export default App;


