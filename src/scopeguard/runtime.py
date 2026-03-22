from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import re

from .scope.fingerprint import scope_fingerprint
from .scope.models import ScopePackage


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(value: str) -> str:
    slug = _SLUG_RE.sub("-", value.lower()).strip("-")
    return slug or "scope"


def timestamp_slug(moment: datetime | None = None) -> str:
    moment = moment or datetime.now(UTC)
    return moment.strftime("%Y%m%dT%H%M%SZ")


@dataclass(frozen=True, slots=True)
class WorkspacePaths:
    root: Path
    assessment_dir: Path
    runs_dir: Path
    plan_path: Path
    approvals_path: Path
    scope_snapshot_path: Path

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.assessment_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.plan_path.parent.mkdir(parents=True, exist_ok=True)
        self.approvals_path.parent.mkdir(parents=True, exist_ok=True)


def build_workspace(scope: ScopePackage, root: Path | str = Path("artifacts")) -> WorkspacePaths:
    root_path = Path(root)
    assessment_id = f"{slugify(scope.name)}-{scope_fingerprint(scope)[:12]}"
    assessment_dir = root_path / assessment_id
    runs_dir = assessment_dir / "runs"
    return WorkspacePaths(
        root=root_path,
        assessment_dir=assessment_dir,
        runs_dir=runs_dir,
        plan_path=assessment_dir / "plan.json",
        approvals_path=assessment_dir / "approvals.jsonl",
        scope_snapshot_path=assessment_dir / "scope.json",
    )


def build_run_dir(workspace: WorkspacePaths, run_id: str | None = None) -> Path:
    run_name = run_id or timestamp_slug()
    return workspace.runs_dir / run_name

