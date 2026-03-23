from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
from typing import Any

from scopeguard.runtime import build_workspace
from scopeguard.scope.models import ScopePackage

from .settings import AppSettings
from .storage import PengeticStore


def ensure_workspace(settings: AppSettings) -> dict[str, Any]:
    settings.paths.data_dir.mkdir(parents=True, exist_ok=True)
    settings.paths.artifacts_dir.mkdir(parents=True, exist_ok=True)
    settings.paths.scopes_dir.mkdir(parents=True, exist_ok=True)
    settings.paths.runs_dir.mkdir(parents=True, exist_ok=True)
    store = PengeticStore(settings.paths.db_path)
    store.initialize()
    return {
        "data_dir": str(settings.paths.data_dir),
        "artifacts_dir": str(settings.paths.artifacts_dir),
        "scopes_dir": str(settings.paths.scopes_dir),
        "runs_dir": str(settings.paths.runs_dir),
        "db_path": str(settings.paths.db_path),
    }


@dataclass(slots=True)
class WorkspaceReset:
    store: PengeticStore
    settings: AppSettings

    def purge_all(self, *, confirmation: str) -> dict[str, Any]:
        if confirmation.strip() != "CONFIRM_PURGE":
            raise ValueError("Confirmation string must exactly match CONFIRM_PURGE.")

        removed_paths: list[str] = []
        protected_names = {
            self.settings.paths.db_path.name,
            f"{self.settings.paths.db_path.name}-wal",
            f"{self.settings.paths.db_path.name}-shm",
            f"{self.settings.paths.db_path.name}-journal",
        }
        if self.settings.paths.data_dir.exists():
            for target in self.settings.paths.data_dir.iterdir():
                if target.name in protected_names:
                    continue
                removed_paths.append(str(target))
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()

        self.store.wipe_database()

        if self.settings.paths.data_dir.exists():
            for lock_name in (
                f"{self.settings.paths.db_path.name}-wal",
                f"{self.settings.paths.db_path.name}-shm",
                f"{self.settings.paths.db_path.name}-journal",
            ):
                target = self.settings.paths.data_dir / lock_name
                if target.exists():
                    try:
                        target.unlink()
                        removed_paths.append(str(target))
                    except PermissionError:
                        pass

        if self.settings.paths.artifacts_dir.exists():
            removed_paths.append(str(self.settings.paths.artifacts_dir))
            shutil.rmtree(self.settings.paths.artifacts_dir)

        self.settings.paths.data_dir.mkdir(parents=True, exist_ok=True)
        self.settings.paths.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.settings.paths.scopes_dir.mkdir(parents=True, exist_ok=True)
        self.settings.paths.runs_dir.mkdir(parents=True, exist_ok=True)
        if not self.settings.paths.db_path.exists():
            self.store.initialize()
        self.store.set_current_scope(None)
        self.store.set_current_plan(None)
        self.store.set_current_run(None)
        self.store.set_assessment_state(None)
        self.store.set_selected_ollama_model(None)
        return {
            "status": "purged",
            "removed_paths": removed_paths,
        }

    def reset_current_scope(self, *, confirmation: str) -> dict[str, Any]:
        if confirmation.strip() != "RESET_SCOPE":
            raise ValueError("Confirmation string must exactly match RESET_SCOPE.")

        scope_id = self.store.current_scope_id()
        self.store.set_current_scope(None)
        self.store.set_current_plan(None)
        self.store.set_current_run(None)
        self.store.set_assessment_state(None)
        return {
            "status": "reset",
            "scope_id": scope_id,
        }

    def delete_runs_for_current_scope(self, *, confirmation: str) -> dict[str, Any]:
        if confirmation.strip() != "DELETE_RUNS":
            raise ValueError("Confirmation string must exactly match DELETE_RUNS.")

        scope_row = self.store.get_current_scope()
        if scope_row is None:
            return {
                "status": "no-scope",
                "scope_id": None,
                "deleted_run_ids": [],
                "removed_paths": [],
            }

        scope = ScopePackage.model_validate(scope_row["scope_json"])
        workspace = build_workspace(scope, self.settings.paths.artifacts_dir)
        workspace.ensure()
        deleted_run_ids = self.store.delete_runs_for_scope(scope_row["id"])
        removed_paths: list[str] = []
        for run_id in deleted_run_ids:
            run_dir = workspace.runs_dir / run_id
            if run_dir.exists():
                removed_paths.append(str(run_dir))
                shutil.rmtree(run_dir)
        if self.store.current_scope_id() == scope_row["id"]:
            self.store.set_current_run(None)
            self.store.set_assessment_state(None)
        return {
            "status": "deleted",
            "scope_id": scope_row["id"],
            "deleted_run_ids": deleted_run_ids,
            "removed_paths": removed_paths,
        }
