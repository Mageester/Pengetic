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
        run_id=context.run_id,
        scope_id=context.scope_fingerprint,
        status="skipped",
        raw_output={"note": "Active validation is registered but not executed automatically in this build."},
        parsed_output={
            "classification": action.classification.value,
            "note": "This is a safe stub to preserve the approval gate and keep the framework non-destructive by default.",
        },
        artifacts=[],
        findings_candidates=[],
        next_safe_checks=["Wait for explicit operator approval before executing any active validation step."],
        metadata={
            "summary": "Active validation is registered but not executed automatically in this build.",
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        },
        started_at=started,
        finished_at=datetime.now(UTC),
        success=False,
    )
