from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .errors import ScopeValidationError
from .models import ScopePackage


def load_scope_data(path: Path | str) -> dict[str, Any]:
    scope_path = Path(path)
    if not scope_path.exists():
        raise ScopeValidationError(f"Scope file does not exist: {scope_path}")
    data = yaml.safe_load(scope_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ScopeValidationError("Scope file must contain a YAML mapping.")
    return data


def validate_scope_data(data: dict[str, Any]) -> ScopePackage:
    try:
        return ScopePackage.model_validate(data)
    except ScopeValidationError:
        raise
    except ValidationError as exc:
        raise ScopeValidationError(str(exc)) from exc
    except Exception as exc:
        raise ScopeValidationError(str(exc)) from exc


def validate_scope_file(path: Path | str) -> ScopePackage:
    return validate_scope_data(load_scope_data(path))
