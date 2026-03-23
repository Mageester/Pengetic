export function cx(...classes: Array<string | false | null | undefined>): string {
  return classes.filter(Boolean).join(" ");
}

export function formatTimestamp(value: string | null | undefined): string {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export function formatShortTimestamp(value: string | null | undefined): string {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function titleCase(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

const riskLabels: Record<string, string> = {
  PASSIVE_SAFE: "Passive Safe",
  LOW_RISK_ACTIVE: "Low Risk Active",
  HIGH_RISK_ACTIVE: "High Risk Active",
  FORBIDDEN: "Forbidden",
};

const riskClasses: Record<string, string> = {
  PASSIVE_SAFE: "border-emerald-400/20 bg-emerald-400/10 text-emerald-200",
  LOW_RISK_ACTIVE: "border-red-400/20 bg-red-400/10 text-red-200",
  HIGH_RISK_ACTIVE: "border-amber-400/20 bg-amber-400/10 text-amber-200",
  FORBIDDEN: "border-rose-400/20 bg-rose-400/10 text-rose-200",
};

const stateClasses: Record<string, string> = {
  idle: "border-slate-400/20 bg-slate-400/10 text-slate-200",
  scope_uploaded: "border-red-400/20 bg-red-400/10 text-red-200",
  scope_validated: "border-red-400/20 bg-red-400/10 text-red-200",
  plan_ready: "border-red-500/20 bg-red-500/10 text-red-100",
  running: "border-red-500/20 bg-red-500/10 text-red-100",
  awaiting_approval: "border-amber-400/20 bg-amber-400/10 text-amber-200",
  completed: "border-emerald-400/20 bg-emerald-400/10 text-emerald-200",
  failed: "border-rose-400/20 bg-rose-400/10 text-rose-200",
};

const statusClasses: Record<string, string> = {
  queued: "border-slate-400/20 bg-slate-400/10 text-slate-200",
  "pending-approval": "border-amber-400/20 bg-amber-400/10 text-amber-200",
  approved: "border-red-400/20 bg-red-400/10 text-red-200",
  executed: "border-emerald-400/20 bg-emerald-400/10 text-emerald-200",
  skipped: "border-slate-400/20 bg-slate-400/10 text-slate-200",
  blocked: "border-rose-400/20 bg-rose-400/10 text-rose-200",
  failed: "border-rose-400/20 bg-rose-400/10 text-rose-200",
};

const severityClasses: Record<string, string> = {
  critical: "border-rose-400/20 bg-rose-400/10 text-rose-200",
  high: "border-orange-400/20 bg-orange-400/10 text-orange-200",
  medium: "border-amber-400/20 bg-amber-400/10 text-amber-200",
  low: "border-red-400/20 bg-red-400/10 text-red-200",
  informational: "border-slate-400/20 bg-slate-400/10 text-slate-200",
};

const statusLabels: Record<string, string> = {
  queued: "Queued",
  "pending-approval": "Pending approval",
  approved: "Approved",
  executed: "Executed",
  skipped: "Skipped",
  blocked: "Blocked",
  failed: "Failed",
};

export function riskLabel(value: string): string {
  return riskLabels[value] ?? titleCase(value);
}

export function riskTone(value: string): string {
  return riskClasses[value] ?? "border-slate-400/20 bg-slate-400/10 text-slate-200";
}

export function stateTone(value: string): string {
  return stateClasses[value] ?? "border-slate-400/20 bg-slate-400/10 text-slate-200";
}

export function statusTone(value: string): string {
  return statusClasses[value] ?? "border-slate-400/20 bg-slate-400/10 text-slate-200";
}

export function statusLabel(value: string): string {
  return statusLabels[value] ?? titleCase(value);
}

export function severityTone(value: string): string {
  return severityClasses[value] ?? "border-slate-400/20 bg-slate-400/10 text-slate-200";
}

export function shortList(items: string[] | null | undefined, fallback = "-"): string {
  return items && items.length > 0 ? items.join(", ") : fallback;
}

export function summarizeTarget(value: string | null | undefined): string {
  if (!value) {
    return "-";
  }
  const trimmed = value.trim();
  return trimmed.length > 88 ? `${trimmed.slice(0, 85)}...` : trimmed;
}
