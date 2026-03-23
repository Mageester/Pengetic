from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import json
import sqlite3
from typing import Any, Iterable
from uuid import uuid4

from scopeguard.findings.models import Finding
from scopeguard.policy.plan import AssessmentAction, AssessmentPlan
from scopeguard.scope.fingerprint import scope_fingerprint
from scopeguard.scope.models import ScopePackage
from scopeguard.tools.base import ToolArtifact, ToolResult


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _loads(value: str | None) -> Any:
    if value in (None, ""):
        return None
    return json.loads(value)


def _int(value: bool) -> int:
    return 1 if value else 0


def _bool(value: Any) -> bool:
    return bool(value)


def _row_dict(row: sqlite3.Row | None, *, json_fields: Iterable[str] = ()) -> dict[str, Any] | None:
    if row is None:
        return None
    data = dict(row)
    for field in json_fields:
        if field in data and data[field] is not None:
            data[field] = json.loads(data[field])
    return data


SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scopes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    primary_domain TEXT NOT NULL,
    base_url TEXT NOT NULL,
    authorized_hosts_json TEXT NOT NULL,
    allowed_subdomains_json TEXT NOT NULL,
    allowed_urls_json TEXT NOT NULL,
    login_areas_allowed_json TEXT NOT NULL,
    apis_allowed_json TEXT NOT NULL,
    tool_allowlist_json TEXT NOT NULL,
    authorization_note TEXT NOT NULL,
    notes TEXT,
    source_path TEXT,
    raw_yaml TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    scope_name TEXT NOT NULL,
    scope_fingerprint TEXT NOT NULL,
    profile TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    is_current INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    scope_name TEXT NOT NULL,
    scope_fingerprint TEXT NOT NULL,
    profile TEXT NOT NULL,
    state TEXT NOT NULL,
    status TEXT NOT NULL,
    plan_id TEXT REFERENCES plans(id) ON DELETE SET NULL,
    manual_notes TEXT,
    plan_json TEXT NOT NULL,
    report_path TEXT,
    report_text TEXT,
    summary_json TEXT,
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS run_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    action_id TEXT NOT NULL,
    title TEXT NOT NULL,
    objective TEXT NOT NULL,
    target TEXT NOT NULL,
    tool_id TEXT NOT NULL,
    classification TEXT NOT NULL,
    expected_evidence_json TEXT NOT NULL,
    approval_required INTEGER NOT NULL,
    allowed_by_scope INTEGER NOT NULL,
    notes TEXT,
    status TEXT NOT NULL,
    decision_reason TEXT,
    result_json TEXT,
    evidence_paths_json TEXT NOT NULL DEFAULT '[]',
    started_at TEXT,
    finished_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(run_id, action_id)
);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    action_id TEXT NOT NULL,
    scope_fingerprint TEXT NOT NULL,
    risk TEXT NOT NULL,
    status TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    note TEXT,
    decision_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    action_id TEXT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    affected_asset TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    why_it_matters TEXT NOT NULL,
    safe_verification_status TEXT NOT NULL,
    remediation TEXT NOT NULL,
    source_tool TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    action_id TEXT,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    action_id TEXT,
    tool_id TEXT,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    action_id TEXT,
    tool_id TEXT NOT NULL,
    target TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    status TEXT NOT NULL,
    raw_output_json TEXT NOT NULL,
    parsed_output_json TEXT NOT NULL,
    artifacts_json TEXT NOT NULL,
    findings_candidates_json TEXT NOT NULL,
    next_safe_checks_json TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_recommendations (
    id TEXT PRIMARY KEY,
    run_id TEXT REFERENCES runs(id) ON DELETE CASCADE,
    scope_id TEXT REFERENCES scopes(id) ON DELETE CASCADE,
    model TEXT NOT NULL,
    source TEXT NOT NULL,
    summary TEXT NOT NULL,
    next_allowed_step TEXT NOT NULL,
    recommended_action_id TEXT,
    rationale TEXT NOT NULL,
    confidence TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orchestrator_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    step_index INTEGER NOT NULL,
    planner_model TEXT NOT NULL,
    planner_source TEXT NOT NULL,
    state_before TEXT NOT NULL,
    state_after TEXT NOT NULL,
    selected_action_id TEXT,
    selected_tool_id TEXT,
    selected_risk TEXT,
    status TEXT NOT NULL,
    stop_reason TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    result_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(run_id, step_index)
);

CREATE INDEX IF NOT EXISTS idx_tool_results_run_id ON tool_results(run_id);
CREATE INDEX IF NOT EXISTS idx_tool_results_scope_id ON tool_results(scope_id);
CREATE INDEX IF NOT EXISTS idx_tool_results_tool_id ON tool_results(tool_id);
CREATE INDEX IF NOT EXISTS idx_tool_results_target ON tool_results(target);
CREATE INDEX IF NOT EXISTS idx_tool_results_timestamp ON tool_results(timestamp);
"""


@dataclass(slots=True)
class PengeticStore:
    db_path: Path

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def get_setting(self, key: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else None

    def set_setting(self, key: str, value: str | None) -> None:
        with self._connect() as conn:
            if value is None:
                conn.execute("DELETE FROM settings WHERE key = ?", (key,))
            else:
                conn.execute(
                    "INSERT INTO settings(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, value),
                )

    def set_current_scope(self, scope_id: str | None) -> None:
        self.set_setting("current_scope_id", scope_id)

    def set_current_plan(self, plan_id: str | None) -> None:
        self.set_setting("current_plan_id", plan_id)

    def set_current_run(self, run_id: str | None) -> None:
        self.set_setting("current_run_id", run_id)

    def set_assessment_state(self, state: str | None) -> None:
        self.set_setting("assessment_state", state)

    def set_selected_ollama_model(self, model: str | None) -> None:
        self.set_setting("ollama_model", model)

    def get_selected_ollama_model(self) -> str | None:
        return self.get_setting("ollama_model")

    def wipe_database(self) -> None:
        tables = [
            "orchestrator_steps",
            "events",
            "tool_results",
            "artifacts",
            "findings",
            "approvals",
            "run_actions",
            "llm_recommendations",
            "runs",
            "plans",
            "scopes",
            "settings",
        ]
        with self._connect() as conn:
            conn.execute("PRAGMA foreign_keys = OFF")
            for table in tables:
                conn.execute(f"DELETE FROM {table}")
            conn.execute("DELETE FROM sqlite_sequence")
            conn.execute("PRAGMA foreign_keys = ON")
        with self._connect() as conn:
            conn.execute("VACUUM")

    def current_scope_id(self) -> str | None:
        return self.get_setting("current_scope_id")

    def current_plan_id(self) -> str | None:
        return self.get_setting("current_plan_id")

    def current_run_id(self) -> str | None:
        return self.get_setting("current_run_id")

    def current_state(self) -> str | None:
        return self.get_setting("assessment_state")

    def upsert_scope(self, scope: ScopePackage, *, raw_yaml: str, source_path: str | None = None) -> dict[str, Any]:
        scope_id = scope_fingerprint(scope)
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scopes(
                    id, name, primary_domain, base_url, authorized_hosts_json, allowed_subdomains_json,
                    allowed_urls_json, login_areas_allowed_json, apis_allowed_json, tool_allowlist_json,
                    authorization_note, notes, source_path, raw_yaml, scope_json, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    primary_domain = excluded.primary_domain,
                    base_url = excluded.base_url,
                    authorized_hosts_json = excluded.authorized_hosts_json,
                    allowed_subdomains_json = excluded.allowed_subdomains_json,
                    allowed_urls_json = excluded.allowed_urls_json,
                    login_areas_allowed_json = excluded.login_areas_allowed_json,
                    apis_allowed_json = excluded.apis_allowed_json,
                    tool_allowlist_json = excluded.tool_allowlist_json,
                    authorization_note = excluded.authorization_note,
                    notes = excluded.notes,
                    source_path = excluded.source_path,
                    raw_yaml = excluded.raw_yaml,
                    scope_json = excluded.scope_json,
                    updated_at = excluded.updated_at
                """,
                (
                    scope_id,
                    scope.name,
                    scope.primary_domain,
                    str(scope.base_url),
                    _dumps(scope.authorized_hosts),
                    _dumps(scope.allowed_subdomains),
                    _dumps([str(url) for url in scope.allowed_urls]),
                    _dumps(scope.login_areas_allowed),
                    _dumps(scope.apis_allowed),
                    _dumps(scope.tool_allowlist),
                    scope.authorization_note,
                    scope.notes,
                    source_path,
                    raw_yaml,
                    _dumps(scope.model_dump(mode="json")),
                    now,
                    now,
                ),
            )
        self.set_current_scope(scope_id)
        return self.get_scope(scope_id) or {}

    def get_scope(self, scope_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scopes WHERE id = ?", (scope_id,)).fetchone()
        data = _row_dict(
            row,
            json_fields=(
                "authorized_hosts_json",
                "allowed_subdomains_json",
                "allowed_urls_json",
                "login_areas_allowed_json",
                "apis_allowed_json",
                "tool_allowlist_json",
                "scope_json",
            ),
        )
        if data is None:
            return None
        return {
            "id": data["id"],
            "name": data["name"],
            "primary_domain": data["primary_domain"],
            "base_url": data["base_url"],
            "authorized_hosts": data["authorized_hosts_json"],
            "allowed_subdomains": data["allowed_subdomains_json"],
            "allowed_urls": data["allowed_urls_json"],
            "login_areas_allowed": data["login_areas_allowed_json"],
            "apis_allowed": data["apis_allowed_json"],
            "tool_allowlist": data["tool_allowlist_json"],
            "authorization_note": data["authorization_note"],
            "notes": data["notes"],
            "source_path": data["source_path"],
            "raw_yaml": data["raw_yaml"],
            "scope_json": data["scope_json"],
            "created_at": data["created_at"],
            "updated_at": data["updated_at"],
        }

    def list_scopes(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT id FROM scopes ORDER BY updated_at DESC").fetchall()
        return [scope for row in rows if (scope := self.get_scope(row["id"])) is not None]

    def get_current_scope(self) -> dict[str, Any] | None:
        scope_id = self.current_scope_id()
        return self.get_scope(scope_id) if scope_id else None

    def save_plan(self, scope: ScopePackage, profile: str, plan: AssessmentPlan, *, activate: bool = True) -> dict[str, Any]:
        plan_id = uuid4().hex
        now = _now()
        scope_id = scope_fingerprint(scope)
        with self._connect() as conn:
            if activate:
                conn.execute("UPDATE plans SET is_current = 0 WHERE scope_id = ?", (scope_id,))
            conn.execute(
                """
                INSERT INTO plans(
                    id, scope_id, scope_name, scope_fingerprint, profile, plan_json, created_at, updated_at, is_current
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan_id,
                    scope_id,
                    scope.name,
                    plan.scope_fingerprint,
                    profile,
                    plan.model_dump_json(indent=2),
                    now,
                    now,
                    1 if activate else 0,
                ),
            )
        if activate:
            self.set_current_plan(plan_id)
        return self.get_plan(plan_id) or {}

    def get_plan(self, plan_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
        data = _row_dict(row)
        if data is None:
            return None
        plan = AssessmentPlan.model_validate_json(data["plan_json"])
        return {
            "id": data["id"],
            "scope_id": data["scope_id"],
            "scope_name": data["scope_name"],
            "scope_fingerprint": data["scope_fingerprint"],
            "profile": data["profile"],
            "generated_at": plan.generated_at,
            "actions": [action.model_dump(mode="json") for action in plan.actions],
            "plan_json": data["plan_json"],
            "created_at": data["created_at"],
            "updated_at": data["updated_at"],
            "is_current": _bool(data["is_current"]),
        }

    def get_current_plan(self, scope_id: str | None = None) -> dict[str, Any] | None:
        active_scope_id = scope_id or self.current_scope_id()
        plan_id = self.current_plan_id()
        if plan_id:
            current_plan = self.get_plan(plan_id)
            if current_plan and (active_scope_id is None or current_plan["scope_id"] == active_scope_id):
                return current_plan
        with self._connect() as conn:
            if active_scope_id:
                row = conn.execute(
                    "SELECT id FROM plans WHERE is_current = 1 AND scope_id = ? ORDER BY updated_at DESC LIMIT 1",
                    (active_scope_id,),
                ).fetchone()
                if row is None:
                    row = conn.execute(
                        "SELECT id FROM plans WHERE scope_id = ? ORDER BY updated_at DESC LIMIT 1",
                        (active_scope_id,),
                    ).fetchone()
            else:
                row = conn.execute("SELECT id FROM plans WHERE is_current = 1 ORDER BY updated_at DESC LIMIT 1").fetchone()
                if row is None:
                    row = conn.execute("SELECT id FROM plans ORDER BY updated_at DESC LIMIT 1").fetchone()
        return self.get_plan(row["id"]) if row else None

    def create_run(
        self,
        scope: ScopePackage,
        plan: AssessmentPlan,
        *,
        profile: str,
        manual_notes: str | None = None,
    ) -> dict[str, Any]:
        run_id = uuid4().hex
        now = _now()
        scope_id = scope_fingerprint(scope)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO runs(
                    id, scope_id, scope_name, scope_fingerprint, profile, state, status, plan_id, manual_notes,
                    plan_json, created_at, updated_at, started_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    scope_id,
                    scope.name,
                    plan.scope_fingerprint,
                    profile,
                    "running",
                    "running",
                    self.current_plan_id(),
                    manual_notes,
                    plan.model_dump_json(indent=2),
                    now,
                    now,
                    now,
                ),
            )
            for action in plan.actions:
                conn.execute(
                    """
                    INSERT INTO run_actions(
                        run_id, action_id, title, objective, target, tool_id, classification,
                        expected_evidence_json, approval_required, allowed_by_scope, notes, status,
                        decision_reason, evidence_paths_json, created_at, updated_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        action.action_id,
                        action.title,
                        action.objective,
                        action.target,
                        action.tool_id,
                        action.classification.value,
                        _dumps(action.expected_evidence),
                        _int(action.approval_required),
                        _int(action.allowed_by_scope),
                        action.notes,
                        "queued",
                        None,
                        _dumps([]),
                        now,
                        now,
                    ),
                )
        self.set_current_run(run_id)
        return self.get_run(run_id) or {}

    def list_runs(self, *, limit: int = 20, scope_id: str | None = None) -> list[dict[str, Any]]:
        active_scope_id = scope_id or self.current_scope_id()
        with self._connect() as conn:
            if active_scope_id:
                rows = conn.execute(
                    "SELECT id FROM runs WHERE scope_id = ? ORDER BY updated_at DESC LIMIT ?",
                    (active_scope_id, limit),
                ).fetchall()
            else:
                rows = conn.execute("SELECT id FROM runs ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
        return [run for row in rows if (run := self.get_run(row["id"])) is not None]

    def list_run_ids_for_scope(self, scope_id: str) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT id FROM runs WHERE scope_id = ? ORDER BY created_at DESC", (scope_id,)).fetchall()
        return [str(row["id"]) for row in rows]

    def delete_runs_for_scope(self, scope_id: str) -> list[str]:
        run_ids = self.list_run_ids_for_scope(scope_id)
        if not run_ids:
            return []
        with self._connect() as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            for run_id in run_ids:
                conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
        if self.current_run_id() in run_ids:
            self.set_current_run(None)
        if self.current_plan_id() and any(run_id for run_id in run_ids):
            # Keep the current plan reference if it belongs to another scope; callers decide whether to clear it.
            pass
        return run_ids

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        data = _row_dict(row)
        if data is None:
            return None
        plan = self.get_plan(data["plan_id"]) if data.get("plan_id") else None
        return {
            "id": data["id"],
            "scope_id": data["scope_id"],
            "scope_name": data["scope_name"],
            "scope_fingerprint": data["scope_fingerprint"],
            "profile": data["profile"],
            "state": data["state"],
            "status": data["status"],
            "plan_id": data["plan_id"],
            "manual_notes": data["manual_notes"],
            "plan_json": data["plan_json"],
            "report_path": data["report_path"],
            "report_text": data["report_text"],
            "summary_json": _loads(data["summary_json"]) or {},
            "started_at": data["started_at"],
            "finished_at": data["finished_at"],
            "created_at": data["created_at"],
            "updated_at": data["updated_at"],
            "plan": plan,
            "actions": self.list_run_actions(run_id),
            "findings": self.list_findings(run_id),
            "artifacts": self.list_artifacts(run_id),
            "approvals": self.list_approvals(run_id),
            "events": self.list_events(run_id),
        }

    def update_run(
        self,
        run_id: str,
        *,
        state: str | None = None,
        status: str | None = None,
        report_path: str | None = None,
        report_text: str | None = None,
        summary_json: dict[str, Any] | None = None,
        started_at: str | None = None,
        finished_at: str | None = None,
    ) -> None:
        now = _now()
        assignments: list[str] = ["updated_at = ?"]
        values: list[Any] = [now]
        if state is not None:
            assignments.append("state = ?")
            values.append(state)
        if status is not None:
            assignments.append("status = ?")
            values.append(status)
        if report_path is not None:
            assignments.append("report_path = ?")
            values.append(report_path)
        if report_text is not None:
            assignments.append("report_text = ?")
            values.append(report_text)
        if summary_json is not None:
            assignments.append("summary_json = ?")
            values.append(_dumps(summary_json))
        if started_at is not None:
            assignments.append("started_at = ?")
            values.append(started_at)
        if finished_at is not None:
            assignments.append("finished_at = ?")
            values.append(finished_at)
        values.append(run_id)
        with self._connect() as conn:
            conn.execute(f"UPDATE runs SET {', '.join(assignments)} WHERE id = ?", values)

    def add_run_event(
        self,
        run_id: str,
        *,
        event_type: str,
        message: str,
        level: str = "info",
        action_id: str | None = None,
        tool_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> int:
        payload = payload or {}
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO events(run_id, created_at, event_type, level, message, action_id, tool_id, payload_json)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, _now(), event_type, level, message, action_id, tool_id, _dumps(payload)),
            )
            return int(cursor.lastrowid)

    def list_events(self, run_id: str, *, after_id: int | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM events WHERE run_id = ?"
        params: list[Any] = [run_id]
        if after_id is not None:
            sql += " AND id > ?"
            params.append(after_id)
        sql += " ORDER BY id ASC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            {
                "id": row["id"],
                "run_id": row["run_id"],
                "created_at": row["created_at"],
                "event_type": row["event_type"],
                "level": row["level"],
                "message": row["message"],
                "action_id": row["action_id"],
                "tool_id": row["tool_id"],
                "payload": _loads(row["payload_json"]) or {},
            }
            for row in rows
        ]

    def add_run_action(
        self,
        run_id: str,
        action: AssessmentAction,
        *,
        status: str = "queued",
        decision_reason: str | None = None,
    ) -> None:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO run_actions(
                    run_id, action_id, title, objective, target, tool_id, classification,
                    expected_evidence_json, approval_required, allowed_by_scope, notes, status,
                    decision_reason, evidence_paths_json, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, action_id) DO UPDATE SET
                    title = excluded.title,
                    objective = excluded.objective,
                    target = excluded.target,
                    tool_id = excluded.tool_id,
                    classification = excluded.classification,
                    expected_evidence_json = excluded.expected_evidence_json,
                    approval_required = excluded.approval_required,
                    allowed_by_scope = excluded.allowed_by_scope,
                    notes = excluded.notes,
                    status = excluded.status,
                    decision_reason = excluded.decision_reason,
                    updated_at = excluded.updated_at
                """,
                (
                    run_id,
                    action.action_id,
                    action.title,
                    action.objective,
                    action.target,
                    action.tool_id,
                    action.classification.value,
                    _dumps(action.expected_evidence),
                    _int(action.approval_required),
                    _int(action.allowed_by_scope),
                    action.notes,
                    status,
                    decision_reason,
                    _dumps([]),
                    now,
                    now,
                ),
            )

    def update_run_action(
        self,
        run_id: str,
        action_id: str,
        *,
        status: str | None = None,
        decision_reason: str | None = None,
        result: dict[str, Any] | None = None,
        evidence_paths: list[str] | None = None,
        started_at: str | None = None,
        finished_at: str | None = None,
    ) -> None:
        now = _now()
        assignments: list[str] = ["updated_at = ?"]
        values: list[Any] = [now]
        if status is not None:
            assignments.append("status = ?")
            values.append(status)
        if decision_reason is not None:
            assignments.append("decision_reason = ?")
            values.append(decision_reason)
        if result is not None:
            assignments.append("result_json = ?")
            values.append(_dumps(result))
        if evidence_paths is not None:
            assignments.append("evidence_paths_json = ?")
            values.append(_dumps(evidence_paths))
        if started_at is not None:
            assignments.append("started_at = ?")
            values.append(started_at)
        if finished_at is not None:
            assignments.append("finished_at = ?")
            values.append(finished_at)
        values.extend([run_id, action_id])
        with self._connect() as conn:
            conn.execute(
                f"UPDATE run_actions SET {', '.join(assignments)} WHERE run_id = ? AND action_id = ?",
                values,
            )

    def list_run_actions(self, run_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM run_actions WHERE run_id = ? ORDER BY id ASC",
                (run_id,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "run_id": row["run_id"],
                "action_id": row["action_id"],
                "title": row["title"],
                "objective": row["objective"],
                "target": row["target"],
                "tool_id": row["tool_id"],
                "classification": row["classification"],
                "expected_evidence": _loads(row["expected_evidence_json"]) or [],
                "approval_required": _bool(row["approval_required"]),
                "allowed_by_scope": _bool(row["allowed_by_scope"]),
                "notes": row["notes"],
                "status": row["status"],
                "decision_reason": row["decision_reason"],
                "result": _loads(row["result_json"]),
                "evidence_paths": _loads(row["evidence_paths_json"]) or [],
                "started_at": row["started_at"],
                "finished_at": row["finished_at"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def list_pending_approvals(self, run_id: str) -> list[dict[str, Any]]:
        return [
            action
            for action in self.list_run_actions(run_id)
            if action["classification"] != "passive-safe" and action["status"] in {"queued", "pending-approval"}
        ]

    def list_approved_actions(self, run_id: str) -> list[dict[str, Any]]:
        return [action for action in self.list_run_actions(run_id) if action["status"] == "approved"]

    def list_approvals(self, run_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM approvals WHERE run_id = ? ORDER BY created_at DESC",
                (run_id,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "run_id": row["run_id"],
                "action_id": row["action_id"],
                "scope_fingerprint": row["scope_fingerprint"],
                "risk": row["risk"],
                "status": row["status"],
                "approved_by": row["approved_by"],
                "approved_at": row["approved_at"],
                "note": row["note"],
                "decision_reason": row["decision_reason"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def record_approval(
        self,
        *,
        run_id: str,
        action_id: str,
        scope_fingerprint_value: str,
        risk: str,
        approved_by: str,
        note: str,
        decision_reason: str | None = None,
    ) -> dict[str, Any]:
        approval_id = uuid4().hex
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO approvals(
                    id, run_id, action_id, scope_fingerprint, risk, status, approved_by,
                    approved_at, note, decision_reason, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval_id,
                    run_id,
                    action_id,
                    scope_fingerprint_value,
                    risk,
                    "approved",
                    approved_by,
                    now,
                    note,
                    decision_reason,
                    now,
                    now,
                ),
            )
            conn.execute(
                "UPDATE run_actions SET status = ?, decision_reason = ?, updated_at = ? WHERE run_id = ? AND action_id = ?",
                ("approved", decision_reason, now, run_id, action_id),
            )
        return {
            "id": approval_id,
            "run_id": run_id,
            "action_id": action_id,
            "scope_fingerprint": scope_fingerprint_value,
            "risk": risk,
            "status": "approved",
            "approved_by": approved_by,
            "approved_at": now,
            "note": note,
            "decision_reason": decision_reason,
            "created_at": now,
            "updated_at": now,
        }

    def add_finding(self, run_id: str, finding: Finding, *, action_id: str | None = None) -> dict[str, Any]:
        created_at = _now()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO findings(
                    run_id, action_id, title, severity, confidence, affected_asset, evidence_json,
                    why_it_matters, safe_verification_status, remediation, source_tool, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    action_id or finding.source_action_id,
                    finding.title,
                    finding.severity.value,
                    finding.confidence.value,
                    finding.affected_asset,
                    _dumps(finding.evidence),
                    finding.why_it_matters,
                    finding.safe_verification_status,
                    finding.remediation,
                    finding.source_tool,
                    created_at,
                ),
            )
        return {
            "id": int(cursor.lastrowid),
            "run_id": run_id,
            "action_id": action_id or finding.source_action_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "affected_asset": finding.affected_asset,
            "evidence": finding.evidence,
            "why_it_matters": finding.why_it_matters,
            "safe_verification_status": finding.safe_verification_status,
            "remediation": finding.remediation,
            "source_tool": finding.source_tool,
            "created_at": created_at,
        }

    def list_findings(self, run_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM findings WHERE run_id = ? ORDER BY id ASC", (run_id,)).fetchall()
        return [
            {
                "id": row["id"],
                "run_id": row["run_id"],
                "action_id": row["action_id"],
                "title": row["title"],
                "severity": row["severity"],
                "confidence": row["confidence"],
                "affected_asset": row["affected_asset"],
                "evidence": _loads(row["evidence_json"]) or [],
                "why_it_matters": row["why_it_matters"],
                "safe_verification_status": row["safe_verification_status"],
                "remediation": row["remediation"],
                "source_tool": row["source_tool"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def add_artifact(
        self,
        run_id: str,
        *,
        kind: str,
        path: str,
        description: str | None = None,
        action_id: str | None = None,
    ) -> dict[str, Any]:
        created_at = _now()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO artifacts(run_id, action_id, kind, path, description, created_at)
                VALUES(?, ?, ?, ?, ?, ?)
                """,
                (run_id, action_id, kind, path, description, created_at),
            )
        return {
            "id": int(cursor.lastrowid),
            "run_id": run_id,
            "action_id": action_id,
            "kind": kind,
            "path": path,
            "description": description,
            "created_at": created_at,
        }

    def list_artifacts(self, run_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM artifacts WHERE run_id = ? ORDER BY id ASC", (run_id,)).fetchall()
        return [
            {
                "id": row["id"],
                "run_id": row["run_id"],
                "action_id": row["action_id"],
                "kind": row["kind"],
                "path": row["path"],
                "description": row["description"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def add_tool_result(
        self,
        run_id: str,
        scope_id: str,
        result: ToolResult,
        *,
        action_id: str | None = None,
    ) -> dict[str, Any]:
        created_at = _now()
        payload = result.to_dict()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO tool_results(
                    run_id, scope_id, action_id, tool_id, target, timestamp, status,
                    raw_output_json, parsed_output_json, artifacts_json, findings_candidates_json,
                    next_safe_checks_json, metadata_json, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    scope_id,
                    action_id or result.action_id,
                    result.tool_id,
                    result.target,
                    result.timestamp,
                    result.status,
                    _dumps(payload["raw_output"]),
                    _dumps(payload["parsed_output"]),
                    _dumps(payload["artifacts"]),
                    _dumps(payload["findings_candidates"]),
                    _dumps(payload["next_safe_checks"]),
                    _dumps(payload["metadata"]),
                    created_at,
                ),
            )
        return {
            "id": int(cursor.lastrowid),
            "run_id": run_id,
            "scope_id": scope_id,
            "action_id": action_id or result.action_id,
            "tool_id": result.tool_id,
            "target": result.target,
            "timestamp": result.timestamp,
            "status": result.status,
            "raw_output": payload["raw_output"],
            "parsed_output": payload["parsed_output"],
            "artifacts": payload["artifacts"],
            "findings_candidates": payload["findings_candidates"],
            "next_safe_checks": payload["next_safe_checks"],
            "metadata": payload["metadata"],
            "created_at": created_at,
        }

    def list_tool_results(
        self,
        run_id: str | None = None,
        *,
        scope_id: str | None = None,
        tool_id: str | None = None,
        target: str | None = None,
        since: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses = []
        values: list[Any] = []
        if run_id is not None:
            clauses.append("run_id = ?")
            values.append(run_id)
        if scope_id is not None:
            clauses.append("scope_id = ?")
            values.append(scope_id)
        if tool_id is not None:
            clauses.append("tool_id = ?")
            values.append(tool_id)
        if target is not None:
            clauses.append("target = ?")
            values.append(target)
        if since is not None:
            clauses.append("timestamp >= ?")
            values.append(since)
        query = "SELECT * FROM tool_results"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY timestamp ASC, id ASC"
        with self._connect() as conn:
            rows = conn.execute(query, values).fetchall()
        return [
            {
                "id": row["id"],
                "run_id": row["run_id"],
                "scope_id": row["scope_id"],
                "action_id": row["action_id"],
                "tool_id": row["tool_id"],
                "target": row["target"],
                "timestamp": row["timestamp"],
                "status": row["status"],
                "raw_output": _loads(row["raw_output_json"]) or {},
                "parsed_output": _loads(row["parsed_output_json"]) or {},
                "artifacts": _loads(row["artifacts_json"]) or [],
                "findings_candidates": _loads(row["findings_candidates_json"]) or [],
                "next_safe_checks": _loads(row["next_safe_checks_json"]) or [],
                "metadata": _loads(row["metadata_json"]) or {},
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def correlate_tool_results(self, run_id: str) -> dict[str, Any]:
        results = self.list_tool_results(run_id)
        grouped: dict[str, list[dict[str, Any]]] = {}
        for item in results:
            grouped.setdefault(item["tool_id"], []).append(item)

        service_inventory = [item for item in grouped.get("nmap-service-discovery", []) if item["parsed_output"].get("services")]
        route_inventory = [item for item in grouped.get("route-inventory", []) if item["parsed_output"].get("routes")]
        tls_posture = grouped.get("tls-review", [])
        header_posture = grouped.get("header-review", [])
        http_probe = grouped.get("http-probe", [])
        dns_visibility = grouped.get("dns-visibility", [])

        observations: list[str] = []
        if service_inventory:
            first = service_inventory[0]["parsed_output"]
            open_ports = [f"{item.get('protocol')}/{item.get('port')}" for item in first.get("services", []) if item.get("port")]
            observations.append(f"Nmap discovered {len(first.get('services', []))} open service(s): {', '.join(open_ports[:10])}.")
        if http_probe:
            first = http_probe[0]["parsed_output"]
            if first.get("redirects"):
                observations.append(f"HTTP probe observed {len(first['redirects'])} redirect hop(s).")
            if first.get("title"):
                observations.append(f"HTTP title detected: {first['title']}.")
        if tls_posture:
            first = tls_posture[0]["parsed_output"]
            certificate = first.get("certificate") or {}
            if isinstance(certificate, dict) and certificate.get("not_after"):
                observations.append(f"TLS certificate expires on {certificate.get('not_after')}.")
            if first.get("protocol"):
                observations.append(f"Negotiated TLS protocol: {first['protocol']}.")
        if header_posture:
            first = header_posture[0]["parsed_output"]
            missing = [key for key, value in (first.get("security_headers") or {}).items() if not value]
            if missing:
                observations.append(f"Missing security headers: {', '.join(missing[:5])}.")
        if route_inventory:
            first = route_inventory[0]["parsed_output"]
            flagged = first.get("sensitive_markers") or []
            if flagged:
                observations.append(f"Potentially sensitive routes surfaced: {', '.join(flagged[:10])}.")
        if dns_visibility:
            first = dns_visibility[0]["parsed_output"]
            record_summary = ", ".join(
                f"{record_type}={len(records or [])}"
                for record_type, records in (first.get("records") or {}).items()
            )
            if record_summary:
                observations.append(f"DNS visibility summary: {record_summary}.")

        evidence_refs = sorted(
            {
                artifact["path"]
                for item in results
                for artifact in item.get("artifacts", [])
                if isinstance(artifact, dict) and artifact.get("path")
            }
        )

        return {
            "run_id": run_id,
            "tool_ids": sorted(grouped),
            "service_inventory": [item["parsed_output"] for item in service_inventory],
            "route_inventory": [item["parsed_output"] for item in route_inventory],
            "tls_posture": [item["parsed_output"] for item in tls_posture],
            "header_posture": [item["parsed_output"] for item in header_posture],
            "http_probe": [item["parsed_output"] for item in http_probe],
            "dns_visibility": [item["parsed_output"] for item in dns_visibility],
            "evidence_refs": evidence_refs,
            "observations": observations,
            "by_tool": grouped,
        }

    def store_llm_recommendation(
        self,
        *,
        run_id: str | None,
        scope_id: str | None,
        model: str,
        source: str,
        summary: str,
        next_allowed_step: str,
        recommended_action_id: str | None,
        rationale: str,
        confidence: str,
        raw_json: dict[str, Any],
    ) -> dict[str, Any]:
        recommendation_id = uuid4().hex
        created_at = _now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO llm_recommendations(
                    id, run_id, scope_id, model, source, summary, next_allowed_step,
                    recommended_action_id, rationale, confidence, raw_json, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    recommendation_id,
                    run_id,
                    scope_id,
                    model,
                    source,
                    summary,
                    next_allowed_step,
                    recommended_action_id,
                    rationale,
                    confidence,
                    _dumps(raw_json),
                    created_at,
                ),
            )
        return {
            "id": recommendation_id,
            "run_id": run_id,
            "scope_id": scope_id,
            "model": model,
            "source": source,
            "summary": summary,
            "next_allowed_step": next_allowed_step,
            "recommended_action_id": recommended_action_id,
            "rationale": rationale,
            "confidence": confidence,
            "raw_json": raw_json,
            "created_at": created_at,
        }

    def add_orchestrator_step(
        self,
        *,
        run_id: str,
        step_index: int,
        planner_model: str,
        planner_source: str,
        state_before: str,
        state_after: str,
        selected_action_id: str | None,
        selected_tool_id: str | None,
        selected_risk: str | None,
        status: str,
        stop_reason: str,
        decision_json: dict[str, Any],
        result_json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        created_at = _now()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO orchestrator_steps(
                    run_id, step_index, planner_model, planner_source, state_before, state_after,
                    selected_action_id, selected_tool_id, selected_risk, status, stop_reason,
                    decision_json, result_json, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    step_index,
                    planner_model,
                    planner_source,
                    state_before,
                    state_after,
                    selected_action_id,
                    selected_tool_id,
                    selected_risk,
                    status,
                    stop_reason,
                    _dumps(decision_json),
                    _dumps(result_json) if result_json is not None else None,
                    created_at,
                    created_at,
                ),
            )
        return {
            "id": int(cursor.lastrowid),
            "run_id": run_id,
            "step_index": step_index,
            "planner_model": planner_model,
            "planner_source": planner_source,
            "state_before": state_before,
            "state_after": state_after,
            "selected_action_id": selected_action_id,
            "selected_tool_id": selected_tool_id,
            "selected_risk": selected_risk,
            "status": status,
            "stop_reason": stop_reason,
            "decision_json": decision_json,
            "result_json": result_json,
            "created_at": created_at,
            "updated_at": created_at,
        }

    def list_orchestrator_steps(self, run_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM orchestrator_steps WHERE run_id = ? ORDER BY step_index ASC, id ASC",
                (run_id,),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "run_id": row["run_id"],
                "step_index": row["step_index"],
                "planner_model": row["planner_model"],
                "planner_source": row["planner_source"],
                "state_before": row["state_before"],
                "state_after": row["state_after"],
                "selected_action_id": row["selected_action_id"],
                "selected_tool_id": row["selected_tool_id"],
                "selected_risk": row["selected_risk"],
                "status": row["status"],
                "stop_reason": row["stop_reason"],
                "decision_json": _loads(row["decision_json"]) or {},
                "result_json": _loads(row["result_json"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def latest_orchestrator_step(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM orchestrator_steps WHERE run_id = ? ORDER BY step_index DESC, id DESC LIMIT 1",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        return self.list_orchestrator_steps(run_id)[-1]

    def get_latest_run(self, scope_id: str | None = None) -> dict[str, Any] | None:
        active_scope_id = scope_id or self.current_scope_id()
        with self._connect() as conn:
            if active_scope_id:
                row = conn.execute(
                    "SELECT id FROM runs WHERE scope_id = ? ORDER BY created_at DESC LIMIT 1",
                    (active_scope_id,),
                ).fetchone()
            else:
                row = conn.execute("SELECT id FROM runs ORDER BY created_at DESC LIMIT 1").fetchone()
        return self.get_run(row["id"]) if row else None

    def get_dashboard_counts(self, scope_id: str | None = None) -> dict[str, int]:
        active_scope_id = scope_id or self.current_scope_id()
        with self._connect() as conn:
            if active_scope_id:
                total_runs = conn.execute(
                    "SELECT COUNT(*) AS count FROM runs WHERE scope_id = ?",
                    (active_scope_id,),
                ).fetchone()["count"]
                total_findings = conn.execute(
                    "SELECT COUNT(*) AS count FROM findings WHERE run_id IN (SELECT id FROM runs WHERE scope_id = ?)",
                    (active_scope_id,),
                ).fetchone()["count"]
                pending_approvals = conn.execute(
                    "SELECT COUNT(*) AS count FROM run_actions "
                    "WHERE run_id IN (SELECT id FROM runs WHERE scope_id = ?) "
                    "AND classification != 'passive-safe' AND status IN ('queued', 'pending-approval')",
                    (active_scope_id,),
                ).fetchone()["count"]
                approved_actions = conn.execute(
                    "SELECT COUNT(*) AS count FROM run_actions "
                    "WHERE run_id IN (SELECT id FROM runs WHERE scope_id = ?) AND status = 'approved'",
                    (active_scope_id,),
                ).fetchone()["count"]
            else:
                total_runs = conn.execute("SELECT COUNT(*) AS count FROM runs").fetchone()["count"]
                total_findings = conn.execute("SELECT COUNT(*) AS count FROM findings").fetchone()["count"]
                pending_approvals = conn.execute(
                    "SELECT COUNT(*) AS count FROM run_actions "
                    "WHERE classification != 'passive-safe' AND status IN ('queued', 'pending-approval')"
                ).fetchone()["count"]
                approved_actions = conn.execute(
                    "SELECT COUNT(*) AS count FROM run_actions WHERE status = 'approved'"
                ).fetchone()["count"]
        return {
            "runs": int(total_runs),
            "findings": int(total_findings),
            "pending_approvals": int(pending_approvals),
            "approved_actions": int(approved_actions),
        }
