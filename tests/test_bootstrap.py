from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from pengetic.bootstrap import CheckResult, DoctorReport, ensure_workspace, format_doctor_report
from pengetic.cli import app
from pengetic.settings import load_settings


def test_ensure_workspace_creates_pengetic_directories(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("PENGETIC_ROOT", raising=False)
    settings = load_settings(root=tmp_path)

    result = ensure_workspace(settings)

    assert Path(result["db_path"]).exists()
    assert settings.paths.data_dir.exists()
    assert settings.paths.artifacts_dir.exists()
    assert settings.paths.scopes_dir.exists()
    assert settings.paths.runs_dir.exists()


def test_doctor_cli_smoke(monkeypatch) -> None:
    report = DoctorReport(
        generated_at="2026-03-22T12:00:00Z",
        root="C:/Pengetic",
        data_dir="C:/Pengetic/data",
        artifacts_dir="C:/Pengetic/artifacts",
        db_path="C:/Pengetic/data/pengetic.sqlite3",
        frontend_dist_dir="C:/Pengetic/frontend/dist",
        selected_model="qwen2.5-coder:14b",
        backend_default_model="qwen2.5-coder:14b",
        model_source="database",
        checks=[CheckResult(name="python", required=True, ok=True, detail="3.12.0", remediation="")],
        ollama={"status": "ok", "selected_model": "qwen2.5-coder:14b", "selected_model_available": True, "available_models": ["qwen2.5-coder:14b"], "checked_at": "2026-03-22T12:00:00Z"},
        workspace_ready=True,
        frontend_ready=True,
        database_ready=True,
        writable=True,
    )
    monkeypatch.setattr("pengetic.cli.build_doctor_report", lambda settings, check_ollama=True: report)

    runner = CliRunner()
    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0, result.output
    assert "Pengetic Doctor" in result.output
    assert "qwen2.5-coder:14b" in result.output
