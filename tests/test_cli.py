from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from scopeguard.cli import app


def test_validate_scope_cli_smoke() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["validate-scope", str(Path("examples/scope.demo.yaml"))])
    assert result.exit_code == 0, result.output
    assert "Scope package is valid" in result.output

