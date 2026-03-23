from __future__ import annotations

from typing import Annotated
import threading
import webbrowser

import typer

from scopeguard.cli import approve as legacy_approve
from scopeguard.cli import plan as legacy_plan
from scopeguard.cli import report as legacy_report
from scopeguard.cli import run as legacy_run
from scopeguard.cli import validate_scope as legacy_validate_scope

from .bootstrap import build_doctor_report, format_doctor_report
from .settings import load_settings


app = typer.Typer(
    help="Pengetic local-first defensive web assessment platform.",
    add_completion=False,
    no_args_is_help=True,
)


app.command("validate-scope")(legacy_validate_scope)
app.command("plan")(legacy_plan)
app.command("approve")(legacy_approve)
app.command("run")(legacy_run)
app.command("report")(legacy_report)


@app.command("doctor")
def doctor(
    check_ollama: Annotated[bool, typer.Option("--check-ollama/--no-check-ollama")] = True,
) -> None:
    settings = load_settings()
    report = build_doctor_report(settings, check_ollama=check_ollama)
    typer.echo(format_doctor_report(report), nl=False)
    if report.required_failures:
        raise typer.Exit(code=1)


@app.command("serve")
def serve(
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 8000,
    reload: Annotated[bool, typer.Option("--reload/--no-reload")] = False,
    open_browser: Annotated[bool, typer.Option("--open-browser/--no-open-browser")] = False,
) -> None:
    settings = load_settings()
    report = build_doctor_report(settings, check_ollama=True)
    backend_host = host or settings.api_host
    backend_port = port or settings.api_port
    browser_host = backend_host
    if browser_host in {"0.0.0.0", "::"}:
        browser_host = "127.0.0.1"
    typer.echo(f"Backend URL: http://{backend_host}:{backend_port}")
    typer.echo(
        "Production frontend: "
        + ("ready" if report.frontend_ready else "setup page (build frontend to serve the GUI)")
    )
    typer.echo(f"Ollama: {report.ollama.get('status', 'unknown')} | selected model: {report.selected_model}")
    typer.echo(f"Data directory: {report.data_dir}")
    typer.echo(f"Artifacts directory: {report.artifacts_dir}")
    if open_browser:
        url = f"http://{browser_host}:{backend_port}/"
        threading.Timer(1.5, webbrowser.open, args=(url,)).start()
    import uvicorn

    uvicorn.run(
        "pengetic.api:create_app",
        factory=True,
        host=backend_host,
        port=backend_port,
        reload=reload,
        reload_dirs=[str(settings.paths.root)] if reload else None,
    )


@app.command("paths")
def show_paths() -> None:
    settings = load_settings()
    typer.echo(f"Root: {settings.paths.root}")
    typer.echo(f"Data: {settings.paths.data_dir}")
    typer.echo(f"Database: {settings.paths.db_path}")
    typer.echo(f"Artifacts: {settings.paths.artifacts_dir}")
    typer.echo(f"Frontend dist: {settings.paths.frontend_dist_dir}")
