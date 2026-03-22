from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .base import ExecutionContext, ToolResult


def active_validation_stub(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=action.target,
        summary="Active validation is registered but not executed automatically in this build.",
        details={
            "note": "This is a safe stub to preserve the approval gate and keep the framework non-destructive by default.",
            "classification": action.classification.value,
        },
        evidence_paths=[],
        findings=[],
        started_at=started,
        finished_at=datetime.now(UTC),
        success=False,
    )

