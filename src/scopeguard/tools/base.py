from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from httpx import Client

from ..policy.risk import RiskLevel


@dataclass(slots=True)
class ExecutionContext:
    scope: Any
    scope_fingerprint: str
    run_id: str
    run_dir: Path
    evidence_store: Any
    audit_logger: Any
    http_client: Client
    manual_notes: str | None = None
    cache: dict[str, Any] = field(default_factory=dict)
    user_agent: str = "ScopeGuard/0.1"
    max_body_chars: int = 10_000


@dataclass(frozen=True, slots=True)
class ToolResult:
    tool_id: str
    action_id: str
    target: str
    started_at: str
    finished_at: str
    success: bool
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    evidence_paths: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        *,
        tool_id: str,
        action_id: str,
        target: str,
        summary: str,
        success: bool = True,
        details: dict[str, Any] | None = None,
        evidence_paths: list[str] | None = None,
        findings: list[dict[str, Any]] | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> "ToolResult":
        start = started_at or datetime.now(UTC)
        end = finished_at or datetime.now(UTC)
        return cls(
            tool_id=tool_id,
            action_id=action_id,
            target=target,
            started_at=start.isoformat().replace("+00:00", "Z"),
            finished_at=end.isoformat().replace("+00:00", "Z"),
            success=success,
            summary=summary,
            details=details or {},
            evidence_paths=evidence_paths or [],
            findings=findings or [],
        )


Executor = Callable[[Any, ExecutionContext], ToolResult]


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    tool_id: str
    title: str
    description: str
    default_risk: RiskLevel
    executor: Executor
    allowed_in_passive_profile: bool = True

