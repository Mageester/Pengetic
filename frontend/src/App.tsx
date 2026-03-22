import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  ArrowUpRight,
  Brain,
  Clock3,
  Database,
  FileDown,
  FileText,
  LayoutDashboard,
  ListChecks,
  PlayCircle,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  Upload,
  Workflow,
  type LucideIcon,
} from "lucide-react";

import { api, apiUrl } from "./api";
import type {
  ApprovalCreateRequest,
  DashboardView,
  LLMPlannerResponse,
  PlanActionView,
  PlanView,
  ReportResponse,
  RunActionView,
  RunView,
  ScopeUploadResponse,
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
  { id: "overview", label: "Overview", description: "Workspace posture", icon: LayoutDashboard },
  { id: "scope", label: "Scope", description: "Upload and validate", icon: Upload },
  { id: "plan", label: "Plan", description: "Risk-labelled actions", icon: ListChecks },
  { id: "run", label: "Run", description: "Logs, evidence, findings", icon: PlayCircle },
  { id: "approvals", label: "Approvals", description: "Non-passive queue", icon: Workflow },
  { id: "reports", label: "Reports", description: "Markdown export", icon: FileDown },
  { id: "planner", label: "Planner", description: "Local Ollama summary", icon: Brain },
];

const liveStates = new Set(["running", "awaiting_approval"]);
const panelBase = "rounded-[28px] border border-white/10 bg-slate-950/75 shadow-panel backdrop-blur-xl";
const buttonBase =
  "inline-flex items-center justify-center gap-2 rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm font-medium text-slate-100 transition hover:border-cyan-400/30 hover:bg-white/10 hover:text-white";
const inputBase =
  "w-full rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 placeholder:text-slate-500 outline-none transition focus:border-cyan-400/40 focus:ring-2 focus:ring-cyan-400/20";
const textareaBase =
  "w-full rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 placeholder:text-slate-500 outline-none transition focus:border-cyan-400/40 focus:ring-2 focus:ring-cyan-400/20";
const selectBase =
  "w-full rounded-2xl border border-white/10 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none transition focus:border-cyan-400/40 focus:ring-2 focus:ring-cyan-400/20";

function normalizeError(error: unknown): string {
  return error instanceof Error ? error.message : "An unexpected error occurred.";
}

function formatCount(value: number | undefined): string {
  return typeof value === "number" ? value.toString() : "0";
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
            <p className="text-[0.72rem] font-semibold uppercase tracking-[0.28em] text-cyan-300/80">
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
      {Icon ? <Icon className="mb-4 h-7 w-7 text-cyan-300/80" /> : null}
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
          ? "border-cyan-400/30 bg-cyan-400/10 text-white"
          : "border-white/10 bg-white/[0.03] text-slate-300 hover:border-cyan-400/20 hover:bg-white/[0.06] hover:text-white",
      )}
    >
      <Icon className={cx("mt-0.5 h-5 w-5 shrink-0", active ? "text-cyan-300" : "text-slate-400")} />
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

function App() {
  const [section, setSection] = useState<SectionId>("overview");
  const [health, setHealth] = useState<{ status: string; service: string } | null>(null);
  const [dashboard, setDashboard] = useState<DashboardView | null>(null);
  const [runs, setRuns] = useState<RunView[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [selectedRun, setSelectedRun] = useState<RunView | null>(null);
  const [report, setReport] = useState<ReportResponse | null>(null);
  const [plannerResult, setPlannerResult] = useState<LLMPlannerResponse | null>(null);
  const [scopeUpload, setScopeUpload] = useState<ScopeUploadResponse | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scopeFile, setScopeFile] = useState<File | null>(null);
  const [scopeProfile, setScopeProfile] = useState("passive-only");
  const [scopeActivate, setScopeActivate] = useState(true);
  const [runProfile, setRunProfile] = useState("passive-only");
  const [manualNotes, setManualNotes] = useState("");
  const [includeApprovedActive, setIncludeApprovedActive] = useState(false);
  const [plannerModel, setPlannerModel] = useState("");
  const [approvalDrafts, setApprovalDrafts] = useState<
    Record<string, { approved_by: string; note: string }>
  >({});
  const liveReloadBusy = useRef(false);

  async function refreshSnapshot() {
    try {
      const [healthData, dashboardData, runList] = await Promise.all([
        api.health(),
        api.dashboard(),
        api.runs(12),
      ]);
      setHealth(healthData);
      setDashboard(dashboardData);
      setRuns(runList);
      if (!selectedRunId) {
        setSelectedRunId(dashboardData.latest_run?.id ?? runList[0]?.id ?? null);
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
    if (!selectedRunId) {
      const nextRun = dashboard?.latest_run?.id ?? runs[0]?.id ?? null;
      if (nextRun) {
        setSelectedRunId(nextRun);
      }
    }
  }, [dashboard, runs, selectedRunId]);

  const currentScope = dashboard?.current_scope ?? null;
  const currentPlan = dashboard?.current_plan ?? scopeUpload?.plan ?? null;
  const currentRun = selectedRun ?? dashboard?.latest_run ?? null;
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

  async function handlePlanner() {
    setBusyAction("planner");
    setError(null);
    try {
      const response = await api.planner({
        run_id: currentRun?.id ?? null,
        scope_id: currentScope?.id ?? null,
        model: plannerModel || null,
      });
      setPlannerResult(response);
      setSection("planner");
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
      tone: "text-cyan-200",
    },
    {
      label: "Findings",
      value: formatCount(dashboard?.counts?.findings),
      detail: "Normalized findings with redacted evidence.",
      tone: "text-emerald-200",
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
      tone: "text-sky-200",
    },
  ];

  const sidebarState = dashboard?.state ?? "idle";

  return (
    <div className="relative min-h-screen">
      <div className="relative mx-auto flex min-h-screen w-full max-w-[1800px] flex-col gap-6 px-4 py-4 lg:flex-row lg:px-6">
        <aside className="w-full lg:sticky lg:top-4 lg:h-[calc(100vh-2rem)] lg:w-[340px]">
          <div className={cx(panelBase, "flex h-full flex-col p-5")}>
            <div className="space-y-3 border-b border-white/5 pb-5">
              <div className="flex items-center gap-3">
                <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-400 via-sky-500 to-indigo-500 text-lg font-bold text-slate-950 shadow-lg shadow-cyan-950/30">
                  P
                </div>
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

            <div className="mt-6 grid gap-3 rounded-3xl border border-cyan-400/10 bg-cyan-400/5 p-4">
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.24em] text-cyan-300/80">
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
                <Database className="h-4 w-4 text-cyan-300/70" />
                SQLite-backed runs, approvals, findings, and artifacts.
              </div>
              <div className="flex items-center gap-2">
                <TerminalSquare className="h-4 w-4 text-cyan-300/70" />
                LLM planner uses Ollama through the OpenAI-compatible API.
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
                  <Badge className="border-cyan-400/20 bg-cyan-400/10 text-cyan-200">
                    {currentScope ? currentScope.name : "No validated scope loaded"}
                  </Badge>
                  <Badge className="border-white/10 bg-white/5 text-slate-200">
                    {currentRun ? `Run ${currentRun.id.slice(0, 8)}` : "No run selected"}
                  </Badge>
                </div>
                <div className="space-y-2">
                  <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-4xl">
                    Pengetic operations console
                  </h1>
                  <p className="max-w-3xl text-sm leading-7 text-slate-400 sm:text-base">
                    Upload an authorized scope, inspect the risk-labelled plan, launch a local-first run,
                    approve non-passive steps, and export a report without giving the planner unrestricted
                    execution power.
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-3 text-sm text-slate-400">
                  <span className="flex items-center gap-2">
                    <Clock3 className="h-4 w-4 text-cyan-300/70" />
                    {health ? `Connected to ${health.service}` : "Awaiting backend health"}
                  </span>
                  <span className="flex items-center gap-2">
                    <ArrowUpRight className="h-4 w-4 text-cyan-300/70" />
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
                  onClick={handlePlanner}
                  className={cx(buttonBase, "border-cyan-400/20 bg-cyan-400/10 text-cyan-100")}
                >
                  <Sparkles className="h-4 w-4" />
                  Ask planner
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
                  <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
                    {overviewMetrics.map((metric) => (
                      <MetricCard
                        key={metric.label}
                        label={metric.label}
                        value={metric.value}
                        detail={metric.detail}
                        tone={metric.tone}
                      />
                    ))}
                  </div>

                  <div className="grid gap-6 xl:grid-cols-3">
                    <Card eyebrow="Assessment" title="Start a run">
                      <div className="grid gap-4">
                        <div className="grid gap-3 md:grid-cols-2">
                          <div className="space-y-2">
                            <Label text="Profile" hint="Controls passive/approved execution" />
                            <select
                              value={runProfile}
                              onChange={(event) => setRunProfile(event.target.value)}
                              className={selectBase}
                            >
                              <option value="passive-only">passive-only</option>
                              <option value="report-only">report-only</option>
                              <option value="lab-safe">lab-safe</option>
                            </select>
                          </div>
                          <div className="space-y-2">
                            <Label text="Approved active" hint="Allow approved active steps" />
                            <label className="flex items-center gap-3 rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-slate-200">
                              <input
                                type="checkbox"
                                checked={includeApprovedActive}
                                onChange={(event) => setIncludeApprovedActive(event.target.checked)}
                                className="h-4 w-4 rounded border-slate-600 bg-slate-950 text-cyan-500 focus:ring-cyan-400/30"
                              />
                              Execute approved active steps
                            </label>
                          </div>
                        </div>
                        <div className="space-y-2">
                          <Label text="Manual notes" hint="Stored with the run and redacted on write" />
                          <textarea
                            value={manualNotes}
                            onChange={(event) => setManualNotes(event.target.value)}
                            rows={4}
                            className={textareaBase}
                            placeholder="Optional analyst context, target notes, or review references."
                          />
                        </div>
                        <button
                          type="button"
                          onClick={handleStartRun}
                          className={cx(
                            buttonBase,
                            "w-full border-cyan-400/20 bg-cyan-400/15 text-cyan-50 hover:bg-cyan-400/20",
                          )}
                          disabled={busyAction === "start-run"}
                        >
                          {busyAction === "start-run" ? (
                            <RefreshCw className="h-4 w-4 animate-spin" />
                          ) : (
                            <PlayCircle className="h-4 w-4" />
                          )}
                          Start assessment
                        </button>
                      </div>
                    </Card>

                    <Card eyebrow="Boundary" title="Current scope">
                      {currentScope ? (
                        <div className="grid gap-4">
                          <LabeledValue label="Name" value={currentScope.name} />
                          <LabeledValue label="Base URL" value={currentScope.base_url} />
                          <LabeledValue label="Authorized hosts" value={shortList(currentScope.authorized_hosts)} />
                          <LabeledValue
                            label="Allowed routes"
                            value={shortList([...currentScope.login_areas_allowed, ...currentScope.apis_allowed])}
                          />
                          <LabeledValue label="Tool allowlist" value={shortList(currentScope.tool_allowlist)} />
                        </div>
                      ) : (
                        <EmptyState
                          title="No validated scope"
                          description="Upload a signed-off scope package to unlock plan generation and execution."
                          icon={Upload}
                        />
                      )}
                    </Card>

                    <Card eyebrow="Recent run" title="Latest assessment">
                      {currentRun ? (
                        <div className="grid gap-4">
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge className={stateTone(currentRun.state)}>{titleCase(currentRun.state)}</Badge>
                            <Badge className={statusTone(currentRun.status)}>{statusLabel(currentRun.status)}</Badge>
                          </div>
                          <LabeledValue label="Run ID" value={<span className="font-mono text-xs">{currentRun.id}</span>} />
                          <LabeledValue label="Scope" value={currentRun.scope_name} />
                          <LabeledValue label="Profile" value={currentRun.profile} />
                          <LabeledValue label="Started" value={formatTimestamp(currentRun.started_at)} />
                          <LabeledValue label="Finished" value={formatTimestamp(currentRun.finished_at)} />
                          <LabeledValue label="Report" value={currentRun.report_path ?? "Pending"} />
                        </div>
                      ) : (
                        <EmptyState title="No run yet" description="Start the first assessment after upload." icon={PlayCircle} />
                      )}
                    </Card>
                  </div>

                  <div className="grid gap-6 xl:grid-cols-2">
                    <Card eyebrow="Telemetry" title="Recent findings">
                      {dashboard.recent_findings.length > 0 ? (
                        <div className="space-y-4">
                          {dashboard.recent_findings.map((finding) => (
                            <div
                              key={`${finding.title}-${finding.created_at}`}
                              className="rounded-2xl border border-white/10 bg-white/[0.03] p-4"
                            >
                              <div className="flex flex-wrap items-center gap-2">
                                <Badge className={severityTone(finding.severity)}>{titleCase(finding.severity)}</Badge>
                                <span className="text-sm font-semibold text-white">{finding.title}</span>
                              </div>
                              <p className="mt-3 text-sm leading-6 text-slate-300">{finding.why_it_matters}</p>
                              <p className="mt-2 text-sm leading-6 text-slate-400">{finding.remediation}</p>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <EmptyState
                          title="No findings yet"
                          description="Passive checks have not produced any confirmed findings."
                          icon={ShieldCheck}
                        />
                      )}
                    </Card>

                    <Card eyebrow="History" title="Recent runs">
                      {dashboard.recent_runs.length > 0 ? (
                        <div className="space-y-3">
                          {dashboard.recent_runs.map((run) => (
                            <button
                              key={run.id}
                              type="button"
                              onClick={() => setSelectedRunId(run.id)}
                              className={cx(
                                "flex w-full items-start justify-between gap-4 rounded-2xl border px-4 py-3 text-left transition",
                                selectedRunId === run.id
                                  ? "border-cyan-400/30 bg-cyan-400/10"
                                  : "border-white/10 bg-white/[0.03] hover:border-white/20 hover:bg-white/[0.06]",
                              )}
                            >
                              <div className="min-w-0">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span className="font-semibold text-white">{run.scope_name}</span>
                                  <Badge className={stateTone(run.state)}>{titleCase(run.state)}</Badge>
                                </div>
                                <div className="mt-1 text-xs text-slate-500">
                                  {run.profile} | {formatShortTimestamp(run.started_at)} | {run.id.slice(0, 8)}
                                </div>
                              </div>
                              <ArrowUpRight className="mt-1 h-4 w-4 text-slate-500" />
                            </button>
                          ))}
                        </div>
                      ) : (
                        <EmptyState
                          title="No runs stored"
                          description="The local SQLite store does not yet contain a run."
                          icon={Database}
                        />
                      )}
                    </Card>
                  </div>
                </div>
              ) : null}
              {section === "scope" ? (
                <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
                  <Card eyebrow="Upload" title="Scope upload and validation">
                    <div className="space-y-5">
                      <div className="space-y-2">
                        <Label text="Scope file" hint="YAML package from the site owner" />
                        <input
                          type="file"
                          accept=".yaml,.yml,text/yaml,text/plain"
                          onChange={(event) => setScopeFile(event.target.files?.[0] ?? null)}
                          className="block w-full cursor-pointer rounded-2xl border border-dashed border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-slate-300 file:mr-4 file:rounded-full file:border-0 file:bg-cyan-400/15 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-cyan-100 hover:border-cyan-400/20"
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
                              className="h-4 w-4 rounded border-slate-600 bg-slate-950 text-cyan-500 focus:ring-cyan-400/30"
                            />
                            Activate generated plan
                          </label>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={handleScopeUpload}
                        className={cx(buttonBase, "w-full border-cyan-400/20 bg-cyan-400/15 text-cyan-50")}
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
                  eyebrow="Plan viewer"
                  title="Risk-labelled assessment plan"
                  description={currentPlan ? planSummary : "Upload a scope to generate the current plan."}
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
                          tone="text-cyan-200"
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
                  eyebrow="Run control"
                  title="Live assessment view"
                  description="Inspect the latest run, follow the event stream, and review findings and artifacts."
                  actions={
                    <div className="flex flex-wrap items-center gap-2">
                      <select
                        value={selectedRunId ?? ""}
                        onChange={(event) => setSelectedRunId(event.target.value || null)}
                        className={cx(selectBase, "max-w-[16rem]")}
                      >
                        <option value="">Select a run</option>
                        {runs.map((run) => (
                          <option key={run.id} value={run.id}>
                            {run.scope_name} | {run.profile} | {run.id.slice(0, 8)}
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
                        </div>

                        <div className="grid gap-4 md:grid-cols-2">
                          <LabeledValue label="Run ID" value={<span className="font-mono text-xs">{currentRun.id}</span>} />
                          <LabeledValue label="Scope" value={currentRun.scope_name} />
                          <LabeledValue label="Started" value={formatTimestamp(currentRun.started_at)} />
                          <LabeledValue label="Finished" value={formatTimestamp(currentRun.finished_at)} />
                        </div>

                        <div className="grid gap-4 lg:grid-cols-2">
                          <div className="rounded-3xl border border-white/10 bg-white/[0.03] p-4">
                            <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
                              <TerminalSquare className="h-4 w-4 text-cyan-300/80" />
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
                                <FileText className="h-4 w-4 text-cyan-300/80" />
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
                            <Sparkles className="h-4 w-4 text-cyan-300/80" />
                            Run summary
                          </div>
                          <div className="grid gap-4">
                            <LabeledValue label="Report" value={currentRun.report_path ?? "Pending"} />
                            <LabeledValue label="Manual notes" value={currentRun.manual_notes ?? "None"} />
                            <LabeledValue label="Plan ID" value={currentRun.plan_id ?? "N/A"} />
                            <LabeledValue label="State" value={titleCase(currentRun.state)} />
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <EmptyState title="No run selected" description="Pick a run from the selector or start a new assessment." icon={PlayCircle} />
                  )}
                </Card>
              ) : null}
              {section === "approvals" ? (
                <Card eyebrow="Approval queue" title="Non-passive actions awaiting explicit approval">
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
                                className={cx(buttonBase, "w-full border-cyan-400/20 bg-cyan-400/15 text-cyan-50")}
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
                  eyebrow="Report viewer"
                  title="Rendered Markdown report"
                  description="The assessment report is generated locally and can be exported as Markdown."
                  actions={
                    currentRun && reportLink ? (
                      <a href={reportLink} className={cx(buttonBase, "border-cyan-400/20 bg-cyan-400/15 text-cyan-50")}>
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
                          <LabeledValue label="Run ID" value={<span className="font-mono text-xs">{currentRun.id}</span>} />
                          <LabeledValue label="Generated" value={formatTimestamp(currentRun.finished_at)} />
                          <LabeledValue label="Report path" value={currentRun.report_path ?? "Pending"} />
                          <LabeledValue label="State" value={titleCase(currentRun.state)} />
                        </div>
                        <div className="rounded-3xl border border-white/10 bg-slate-950/70 p-5">
                          <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-white">
                            <FileText className="h-4 w-4 text-cyan-300/80" />
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
                            <Sparkles className="h-4 w-4 text-cyan-300/80" />
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
                            <FileDown className="h-4 w-4 text-cyan-300/80" />
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
                  <Card eyebrow="LLM planner" title="Ollama-backed suggestion service">
                    <div className="space-y-5">
                      <div className="space-y-2">
                        <Label text="Model" hint="Leave blank to use the backend default" />
                        <input
                          value={plannerModel}
                          onChange={(event) => setPlannerModel(event.target.value)}
                          className={inputBase}
                          placeholder="llama3.1"
                        />
                      </div>
                      <div className="grid gap-4 md:grid-cols-2">
                        <LabeledValue label="Scope" value={currentScope?.name ?? "No scope"} />
                        <LabeledValue label="Run" value={currentRun?.id ?? "No run"} />
                      </div>
                      <button
                        type="button"
                        onClick={handlePlanner}
                        className={cx(buttonBase, "w-full border-cyan-400/20 bg-cyan-400/15 text-cyan-50")}
                        disabled={busyAction === "planner"}
                      >
                        {busyAction === "planner" ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Brain className="h-4 w-4" />}
                        Generate suggestion
                      </button>
                    </div>
                  </Card>

                  <Card
                    eyebrow="Planner output"
                    title="Next allowed step"
                    description="The planner is constrained to summarization and the next permitted step."
                  >
                    {plannerResult ? (
                      <div className="grid gap-5">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge className="border-cyan-400/20 bg-cyan-400/10 text-cyan-200">{plannerResult.source}</Badge>
                          <Badge className="border-white/10 bg-white/5 text-slate-200">{plannerResult.model}</Badge>
                          <Badge className={stateTone(currentRun?.state ?? dashboard.state)}>
                            {titleCase(currentRun?.state ?? dashboard.state)}
                          </Badge>
                        </div>
                        <div className="grid gap-4">
                          <LabeledValue label="Summary" value={plannerResult.summary} />
                          <LabeledValue label="Next step" value={plannerResult.next_allowed_step} />
                          <LabeledValue label="Recommended action" value={plannerResult.recommended_action_id ?? "None"} />
                          <LabeledValue label="Confidence" value={plannerResult.confidence} />
                        </div>
                        <div className="rounded-3xl border border-white/10 bg-slate-950/70 p-5">
                          <div className="mb-2 text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">
                            Rationale
                          </div>
                          <p className="text-sm leading-7 text-slate-300">{plannerResult.rationale}</p>
                        </div>
                        <div className="rounded-3xl border border-white/10 bg-slate-950/70 p-5">
                          <div className="mb-2 text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">
                            Raw response
                          </div>
                          <pre className="overflow-auto whitespace-pre-wrap break-words text-xs leading-6 text-slate-300">
                            {JSON.stringify(plannerResult.raw, null, 2)}
                          </pre>
                        </div>
                      </div>
                    ) : (
                      <EmptyState
                        title="No suggestion yet"
                        description="Ask the planner to summarize the latest run and propose the next allowed step."
                        icon={Brain}
                      />
                    )}
                  </Card>
                </div>
              ) : null}
            </>
          ) : (
            <div className="grid min-h-[60vh] place-items-center">
              <div className={cx(panelBase, "max-w-2xl p-8 text-center")}>
                <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-400 via-sky-500 to-indigo-500 text-2xl font-bold text-slate-950">
                  P
                </div>
                <h2 className="text-2xl font-semibold tracking-tight text-white">Bootstrapping Pengetic</h2>
                <p className="mt-3 text-sm leading-7 text-slate-400">
                  Loading the local API, SQLite store, and current assessment state. This console stays
                  scope-bound and approval-gated from the first page load.
                </p>
                <div className="mt-6 flex items-center justify-center gap-2 text-sm text-slate-400">
                  <RefreshCw className="h-4 w-4 animate-spin text-cyan-300/80" />
                  Waiting for dashboard data
                </div>
              </div>
            </div>
          )}

          <footer className="grid gap-4 border-t border-white/5 px-2 pb-4 pt-1 text-xs text-slate-500 sm:grid-cols-3">
            <div>Pengetic keeps all actions within validated scope boundaries.</div>
            <div>Active steps require an explicit approval record before execution.</div>
            <div>LLM planning is local and constrained to the current plan context.</div>
          </footer>
        </main>
      </div>
    </div>
  );
}

export default App;
