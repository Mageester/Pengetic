from __future__ import annotations

from typing import Annotated

import typer

from scopeguard.cli import approve as legacy_approve
from scopeguard.cli import plan as legacy_plan
from scopeguard.cli import report as legacy_report
from scopeguard.cli import run as legacy_run
from scopeguard.cli import validate_scope as legacy_validate_scope

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


@app.command("serve")
def serve(
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port")] = 8000,
    reload: Annotated[bool, typer.Option("--reload/--no-reload")] = False,
) -> None:
    settings = load_settings()
    if settings.paths.frontend_dist_dir.exists():
        typer.echo(f"Serving built frontend from {settings.paths.frontend_dist_dir}")
    else:
        typer.echo(
            "Frontend build output not found. The root page will show a setup hint until you run "
            "`cd frontend && npm install && npm run build`."
        )
    import uvicorn

    uvicorn.run(
        "pengetic.api:create_app",
        factory=True,
        host=host or settings.api_host,
        port=port or settings.api_port,
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
