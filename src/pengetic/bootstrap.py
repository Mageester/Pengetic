from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
import asyncio
import subprocess
import sys
import tempfile
from typing import Any

from .llm import OllamaPulseService
from .settings import AppSettings
from .storage import PengeticStore
from .workspace import ensure_workspace


@dataclass(slots=True)
class CheckResult:
    name: str
    required: bool
    ok: bool
    detail: str
    remediation: str


@dataclass(slots=True)
class DoctorReport:
    generated_at: str
    root: str
    data_dir: str
    artifacts_dir: str
    db_path: str
    frontend_dist_dir: str
    selected_model: str
    backend_default_model: str
    model_source: str
    checks: list[CheckResult] = field(default_factory=list)
    ollama: dict[str, Any] = field(default_factory=dict)
    workspace_ready: bool = False
    frontend_ready: bool = False
    database_ready: bool = False
    writable: bool = False

    @property
    def required_failures(self) -> list[CheckResult]:
        return [check for check in self.checks if check.required and not check.ok]

    @property
    def ready(self) -> bool:
        return not self.required_failures and self.workspace_ready and self.frontend_ready and self.database_ready and self.writable


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _run_command(command: list[str], *, timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
    if sys.platform.startswith("win"):
        suffix = Path(command[0]).suffix.lower()
        if suffix in {".cmd", ".bat", ".ps1"} or command[0].lower() in {"npm", "npm.cmd", "npm.ps1"}:
            return subprocess.run(["cmd", "/c", *command], capture_output=True, text=True, timeout=timeout, check=False)
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)


def _command_version(
    command: list[str],
    *,
    required: bool,
    remediation: str,
    timeout: float = 10.0,
    display_name: str | None = None,
) -> CheckResult:
    label = display_name or command[0]
    try:
        completed = _run_command(command, timeout=timeout)
        output = (completed.stdout or completed.stderr or "").strip()
        if completed.returncode == 0:
            return CheckResult(name=label, required=required, ok=True, detail=output or f"{label} is available.", remediation=remediation)
        return CheckResult(
            name=label,
            required=required,
            ok=False,
            detail=output or f"{label} returned exit code {completed.returncode}.",
            remediation=remediation,
        )
    except FileNotFoundError:
        return CheckResult(
            name=label,
            required=required,
            ok=False,
            detail=f"{label} was not found on PATH.",
            remediation=remediation,
        )
    except Exception as exc:
        return CheckResult(
            name=label,
            required=required,
            ok=False,
            detail=str(exc),
            remediation=remediation,
        )


def _python_check() -> CheckResult:
    version = sys.version_info
    ok = version.major > 3 or (version.major == 3 and version.minor >= 12)
    return CheckResult(
        name="python",
        required=True,
        ok=ok,
        detail=f"{sys.version.split()[0]} ({sys.executable})",
        remediation="Install Python 3.12 or newer and ensure it is the interpreter used for Pengetic.",
    )


def _pip_check() -> CheckResult:
    return _command_version(
        [sys.executable, "-m", "pip", "--version"],
        required=True,
        remediation="Install pip or repair the Python installation used by Pengetic.",
        display_name="pip",
    )


def _node_check() -> CheckResult:
    return _command_version(
        ["node", "--version"],
        required=True,
        remediation="Install Node.js 18+ and ensure node is available on PATH.",
    )


def _npm_check() -> CheckResult:
    return _command_version(
        ["npm", "--version"],
        required=True,
        remediation="Install npm alongside Node.js and ensure npm is available on PATH.",
    )


def _git_check() -> CheckResult:
    return _command_version(
        ["git", "--version"],
        required=False,
        remediation="Git is optional for fresh installs, but it is useful for updates and source control.",
    )


def _ollama_cli_check() -> CheckResult:
    return _command_version(
        ["ollama", "--version"],
        required=False,
        remediation="Install Ollama if you want the local planner and Engine Pulse health checks.",
    )


def _workspace_writable_check(settings: AppSettings) -> CheckResult:
    try:
        settings.paths.data_dir.mkdir(parents=True, exist_ok=True)
        settings.paths.artifacts_dir.mkdir(parents=True, exist_ok=True)
        settings.paths.scopes_dir.mkdir(parents=True, exist_ok=True)
        settings.paths.runs_dir.mkdir(parents=True, exist_ok=True)
        probe_dir = settings.paths.artifacts_dir
        with tempfile.NamedTemporaryFile("w", dir=probe_dir, delete=True, encoding="utf-8") as handle:
            handle.write("pengetic write probe\n")
        return CheckResult(
            name="workspace-writable",
            required=True,
            ok=True,
            detail="Workspace directories are writable.",
            remediation="",
        )
    except Exception as exc:
        return CheckResult(
            name="workspace-writable",
            required=True,
            ok=False,
            detail=str(exc),
            remediation="Check filesystem permissions for the Pengetic data and artifacts directories.",
        )


def _frontend_build_check(settings: AppSettings) -> CheckResult:
    index_path = settings.paths.frontend_dist_dir / "index.html"
    assets_dir = settings.paths.frontend_dist_dir / "assets"
    js_assets = list(assets_dir.glob("*.js")) if assets_dir.exists() else []
    ok = index_path.exists() and assets_dir.exists() and bool(js_assets)
    detail = (
        f"Built UI found at {settings.paths.frontend_dist_dir}."
        if ok
        else f"Missing production frontend build at {settings.paths.frontend_dist_dir}."
    )
    return CheckResult(
        name="frontend-build",
        required=True,
        ok=ok,
        detail=detail,
        remediation="Run `cd frontend && npm install && npm run build` before starting the production UI.",
    )


def _database_check(settings: AppSettings, store: PengeticStore) -> CheckResult:
    try:
        store.initialize()
        ok = settings.paths.db_path.exists()
        return CheckResult(
            name="database",
            required=True,
            ok=ok,
            detail=f"SQLite database initialized at {settings.paths.db_path}.",
            remediation="",
        )
    except Exception as exc:
        return CheckResult(
            name="database",
            required=True,
            ok=False,
            detail=str(exc),
            remediation="Check that the data directory is writable and the database path is not locked.",
        )


async def _ollama_tags_check(settings: AppSettings, selected_model: str) -> dict[str, Any]:
    service = OllamaPulseService(base_url=settings.ollama_base_url)
    return await service.pulse(selected_model=selected_model)


def build_doctor_report(settings: AppSettings, *, check_ollama: bool = True) -> DoctorReport:
    workspace = ensure_workspace(settings)
    store = PengeticStore(settings.paths.db_path)
    selected_model = store.get_selected_ollama_model() or settings.ollama_model
    model_source = "database" if store.get_selected_ollama_model() else "environment"
    checks = [
        _python_check(),
        _pip_check(),
        _node_check(),
        _npm_check(),
        _git_check(),
        _ollama_cli_check(),
        _workspace_writable_check(settings),
        _frontend_build_check(settings),
        _database_check(settings, store),
    ]
    ollama: dict[str, Any] = {
        "status": "skipped",
        "service": "ollama",
        "selected_model": selected_model,
        "selected_model_available": False,
        "available_models": [],
        "checked_at": _now(),
    }
    if check_ollama:
        try:
            ollama = asyncio.run(_ollama_tags_check(settings, selected_model))
        except RuntimeError:
            ollama = {
                "status": "offline",
                "service": "ollama",
                "selected_model": selected_model,
                "selected_model_available": False,
                "available_models": [],
                "checked_at": _now(),
                "error": "Unable to execute Ollama health check in the current event loop.",
            }
    return DoctorReport(
        generated_at=_now(),
        root=str(settings.paths.root),
        data_dir=str(settings.paths.data_dir),
        artifacts_dir=str(settings.paths.artifacts_dir),
        db_path=str(settings.paths.db_path),
        frontend_dist_dir=str(settings.paths.frontend_dist_dir),
        selected_model=selected_model,
        backend_default_model=settings.ollama_model,
        model_source=model_source,
        checks=checks,
        ollama=ollama,
        workspace_ready=True,
        frontend_ready=(settings.paths.frontend_dist_dir / "index.html").exists(),
        database_ready=settings.paths.db_path.exists(),
        writable=_workspace_writable_check(settings).ok,
    )


def format_doctor_report(report: DoctorReport) -> str:
    lines = [
        "Pengetic Doctor",
        f"Generated: {report.generated_at}",
        f"Root: {report.root}",
        f"Database: {report.db_path}",
        f"Data: {report.data_dir}",
        f"Artifacts: {report.artifacts_dir}",
        f"Frontend dist: {report.frontend_dist_dir}",
        f"Selected model: {report.selected_model} ({report.model_source})",
        f"Backend default model: {report.backend_default_model}",
        "",
        "Checks",
    ]
    for check in report.checks:
        status = "OK" if check.ok else "MISSING"
        required = "required" if check.required else "optional"
        lines.append(f"- {check.name}: {status} ({required}) - {check.detail}")
        if not check.ok and check.remediation:
            lines.append(f"  fix: {check.remediation}")
    lines.extend(
        [
            "",
            "Workspace",
            f"- ready: {'yes' if report.workspace_ready else 'no'}",
            f"- writable: {'yes' if report.writable else 'no'}",
            f"- database ready: {'yes' if report.database_ready else 'no'}",
            f"- frontend ready: {'yes' if report.frontend_ready else 'no'}",
            "",
            "Ollama",
            f"- status: {report.ollama.get('status', 'unknown')}",
            f"- selected model: {report.ollama.get('selected_model', report.selected_model)}",
            f"- selected model available: {'yes' if report.ollama.get('selected_model_available') else 'no'}",
        ]
    )
    available_models = report.ollama.get("available_models") or []
    if available_models:
        lines.append(f"- available models: {', '.join(str(item) for item in available_models[:8])}")
    error = report.ollama.get("error")
    if error:
        lines.append(f"- error: {error}")
    failures = report.required_failures
    lines.extend(
        [
            "",
            "Status",
            f"- ready to launch: {'yes' if report.ready else 'no'}",
            f"- required failures: {len(failures)}",
        ]
    )
    if failures:
        lines.append("")
        lines.append("Common fixes")
        for check in failures:
            if check.remediation:
                lines.append(f"- {check.name}: {check.remediation}")
    return "\n".join(lines).rstrip() + "\n"
