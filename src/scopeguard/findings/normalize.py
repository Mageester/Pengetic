from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..evidence.redaction import redact_sensitive_value
from .models import Finding


def normalize_finding(raw: Finding | Mapping[str, Any], *, source_action_id: str | None = None) -> Finding:
    if isinstance(raw, Finding):
        finding = raw
    else:
        payload = dict(raw)
        payload.pop("metadata", None)
        if source_action_id and "source_action_id" not in payload:
            payload["source_action_id"] = source_action_id
        finding = Finding.model_validate(redact_sensitive_value(payload))
    return finding


def normalize_findings(
    raw_findings: list[Finding | Mapping[str, Any]], *, source_action_id: str | None = None
) -> list[Finding]:
    return [normalize_finding(item, source_action_id=source_action_id) for item in raw_findings]
