from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..evidence.redaction import redact_sensitive_text
from .base import ExecutionContext, ToolArtifact, ToolResult
from .common import make_evidence_name


def manual_review_capture(action: Any, context: ExecutionContext) -> ToolResult:
    started = datetime.now(UTC)
    note = context.manual_notes or "No manual notes were supplied."
    evidence_name = make_evidence_name(context, action.action_id, "manual-notes.txt")
    redacted = redact_sensitive_text(note)
    path = context.evidence_store.write_note(evidence_name, redacted)
    return ToolResult.create(
        tool_id=action.tool_id,
        action_id=action.action_id,
        target=action.target,
        run_id=context.run_id,
        scope_id=context.scope_fingerprint,
        status="success",
        raw_output=note,
        parsed_output={"note_path": str(path), "redacted_note": redacted},
        artifacts=[ToolArtifact(kind="evidence", path=str(path), description="Manual review notes")],
        findings_candidates=[],
        next_safe_checks=["Use manual notes to annotate the active scope or evidence picture."],
        metadata={
            "summary": "Captured manual review notes.",
            "started_at": started.isoformat().replace("+00:00", "Z"),
            "finished_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        },
        started_at=started,
        finished_at=datetime.now(UTC),
    )
