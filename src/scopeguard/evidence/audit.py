from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
import json
from typing import Any

from .redaction import redact_sensitive_value


def _json_safe(value: Any) -> Any:
    if is_dataclass(value):
        return _json_safe(asdict(value))
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    return value


@dataclass(slots=True)
class AuditLogger:
    path: Path
    _ensured: bool = field(default=False, init=False, repr=False)

    def _ensure(self) -> None:
        if not self._ensured:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._ensured = True

    def log(self, event_type: str, **payload: Any) -> Path:
        self._ensure()
        record = {
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "event_type": event_type,
            **payload,
        }
        record = redact_sensitive_value(_json_safe(record))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n")
        return self.path

