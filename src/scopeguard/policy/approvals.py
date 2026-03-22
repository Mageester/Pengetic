from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
import json

from .risk import RiskLevel


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    action_id: str
    scope_fingerprint: str
    approved_by: str
    approved_at: str
    note: str
    risk: RiskLevel

    @classmethod
    def create(
        cls,
        *,
        action_id: str,
        scope_fingerprint: str,
        approved_by: str,
        note: str,
        risk: RiskLevel,
        approved_at: datetime | None = None,
    ) -> "ApprovalRecord":
        moment = approved_at or datetime.now(UTC)
        return cls(
            action_id=action_id,
            scope_fingerprint=scope_fingerprint,
            approved_by=approved_by,
            approved_at=moment.isoformat().replace("+00:00", "Z"),
            note=note,
            risk=risk,
        )


class ApprovalStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def append(self, record: ApprovalRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            payload = asdict(record)
            payload["risk"] = record.risk.value
            handle.write(json.dumps(payload, sort_keys=True) + "\n")

    def all(self) -> list[ApprovalRecord]:
        if not self.path.exists():
            return []
        records: list[ApprovalRecord] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                payload = json.loads(line)
                payload["risk"] = RiskLevel(payload["risk"])
                records.append(ApprovalRecord(**payload))
        return records

    def latest_for_action(
        self, action_id: str, scope_fingerprint: str
    ) -> ApprovalRecord | None:
        for record in reversed(self.all()):
            if record.action_id == action_id and record.scope_fingerprint == scope_fingerprint:
                return record
        return None

