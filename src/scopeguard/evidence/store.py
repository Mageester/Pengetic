from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json

from .redaction import redact_sensitive_value


@dataclass(slots=True)
class EvidenceStore:
    root: Path

    def __post_init__(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    def write_text(self, name: str, content: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(redact_sensitive_value(content), encoding="utf-8")
        return path

    def write_json(self, name: str, payload: object) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(redact_sensitive_value(payload), ensure_ascii=False, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )
        return path

    def write_note(self, name: str, note: str) -> Path:
        return self.write_text(name, note)

