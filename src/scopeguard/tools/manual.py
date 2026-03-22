from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..evidence.redaction import redact_sensitive_text
from .base import ExecutionContext, ToolResult
from .common import make_evidence_name


def manual_review_capture(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    note = context.manual_notes or "No manual notes were supplied."
    evidence_name = make_evidence_name(context, action.action_id, "manual-notes.txt")
    path = context.evidence_store.write_note(evidence_name, redact_sensitive_text(note))
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=action.target,
        summary="Captured manual review notes.",
        details={"note_path": str(path)},
        evidence_paths=[str(path)],
        findings=[],
        started_at=started,
        finished_at=datetime.now(UTC),
    )

