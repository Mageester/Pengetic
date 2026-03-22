from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


def _resolve_path(value: str | None, fallback: Path) -> Path:
    return Path(value).expanduser().resolve() if value else fallback.expanduser().resolve()


@dataclass(frozen=True, slots=True)
class AppPaths:
    root: Path
    data_dir: Path
    db_path: Path
    scopes_dir: Path
    artifacts_dir: Path
    runs_dir: Path
    frontend_dist_dir: Path


@dataclass(frozen=True, slots=True)
class AppSettings:
    paths: AppPaths
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    ollama_base_url: str = "http://127.0.0.1:11434/v1"
    ollama_model: str = "llama3.1"
    cors_origins: tuple[str, ...] = (
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    )


def load_settings(root: Path | None = None) -> AppSettings:
    resolved_root = _resolve_path(
        os.getenv("PENGETIC_ROOT"),
        Path(root or Path.cwd()),
    )
    data_dir = _resolve_path(os.getenv("PENGETIC_DATA_DIR"), resolved_root / "data")
    artifacts_dir = _resolve_path(os.getenv("PENGETIC_ARTIFACTS_DIR"), resolved_root / "artifacts")
    frontend_dist_dir = _resolve_path(os.getenv("PENGETIC_FRONTEND_DIST"), resolved_root / "frontend" / "dist")
    paths = AppPaths(
        root=resolved_root,
        data_dir=data_dir,
        db_path=data_dir / "pengetic.sqlite3",
        scopes_dir=data_dir / "scopes",
        artifacts_dir=artifacts_dir,
        runs_dir=artifacts_dir / "runs",
        frontend_dist_dir=frontend_dist_dir,
    )
    return AppSettings(
        paths=paths,
        api_host=os.getenv("PENGETIC_API_HOST", "127.0.0.1"),
        api_port=int(os.getenv("PENGETIC_API_PORT", "8000")),
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1"),
        ollama_model=os.getenv("OLLAMA_MODEL", "llama3.1"),
    )
