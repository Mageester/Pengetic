from __future__ import annotations

from pathlib import Path

from .models import ScopePackage
from .validator import validate_scope_file


def load_scope_package(path: Path | str) -> ScopePackage:
    return validate_scope_file(path)

