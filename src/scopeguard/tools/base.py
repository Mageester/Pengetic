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
    user_agent: str = "Pengetic/0.1"
    max_body_chars: int = 10_000


@dataclass(frozen=True, slots=True)
class ToolArtifact:
    kind: str
    path: str
    description: str | None = None
    evidence_id: str | None = None
    persisted: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "description": self.description,
            "evidence_id": self.evidence_id,
            "persisted": self.persisted,
        }


@dataclass(frozen=True, slots=True)
class FindingCandidate:
    title: str
    severity: str
    confidence: str
    affected_asset: str
    evidence: list[str] = field(default_factory=list)
    why_it_matters: str = ""
    safe_verification_status: str = ""
    remediation: str = ""
    source_tool: str | None = None
    source_action_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "affected_asset": self.affected_asset,
            "evidence": self.evidence,
            "why_it_matters": self.why_it_matters,
            "safe_verification_status": self.safe_verification_status,
            "remediation": self.remediation,
            "source_tool": self.source_tool,
            "source_action_id": self.source_action_id,
            "metadata": self.metadata,
        }


def _coerce_finding_candidate(candidate: FindingCandidate | dict[str, Any]) -> FindingCandidate:
    if isinstance(candidate, FindingCandidate):
        return candidate

    payload = dict(candidate)
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    return FindingCandidate(
        title=str(payload.get("title", "")),
        severity=str(payload.get("severity", "")),
        confidence=str(payload.get("confidence", "")),
        affected_asset=str(payload.get("affected_asset", "")),
        evidence=[str(item) for item in payload.get("evidence", [])],
        why_it_matters=str(payload.get("why_it_matters", "")),
        safe_verification_status=str(payload.get("safe_verification_status", "")),
        remediation=str(payload.get("remediation", "")),
        source_tool=payload.get("source_tool"),
        source_action_id=payload.get("source_action_id"),
        metadata=metadata,
    )


@dataclass(frozen=True, slots=True)
class ToolResult:
    tool_id: str
    action_id: str
    target: str
    run_id: str
    scope_id: str
    timestamp: str
    status: str
    raw_output: Any
    parsed_output: dict[str, Any] = field(default_factory=dict)
    artifacts: list[ToolArtifact] = field(default_factory=list)
    findings_candidates: list[FindingCandidate] = field(default_factory=list)
    next_safe_checks: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.status in {"success", "ok", "completed", "executed", "partial"}

    @property
    def summary(self) -> str:
        return str(self.metadata.get("summary", ""))

    @property
    def details(self) -> dict[str, Any]:
        return self.parsed_output

    @property
    def evidence_paths(self) -> list[str]:
        return [artifact.path for artifact in self.artifacts]

    @property
    def findings(self) -> list[dict[str, Any]]:
        return [candidate.to_dict() for candidate in self.findings_candidates]

    @property
    def started_at(self) -> str:
        return str(self.metadata.get("started_at", self.timestamp))

    @property
    def finished_at(self) -> str:
        return str(self.metadata.get("finished_at", self.timestamp))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "action_id": self.action_id,
            "target": self.target,
            "run_id": self.run_id,
            "scope_id": self.scope_id,
            "timestamp": self.timestamp,
            "status": self.status,
            "raw_output": self.raw_output,
            "parsed_output": self.parsed_output,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "findings_candidates": [candidate.to_dict() for candidate in self.findings_candidates],
            "next_safe_checks": self.next_safe_checks,
            "metadata": self.metadata,
            "summary": self.summary,
            "success": self.success,
            "details": self.parsed_output,
            "evidence_paths": self.evidence_paths,
            "findings": self.findings,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }

    @classmethod
    def create(
        cls,
        *,
        tool_id: str,
        action_id: str,
        target: str,
        run_id: str | None = None,
        scope_id: str | None = None,
        summary: str = "",
        status: str | None = None,
        success: bool | None = True,
        raw_output: Any | None = None,
        parsed_output: dict[str, Any] | None = None,
        details: dict[str, Any] | None = None,
        artifacts: list[ToolArtifact | dict[str, Any]] | None = None,
        evidence_paths: list[str] | None = None,
        findings_candidates: list[FindingCandidate | dict[str, Any]] | None = None,
        findings: list[dict[str, Any]] | None = None,
        next_safe_checks: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> "ToolResult":
        start = started_at or datetime.now(UTC)
        end = finished_at or datetime.now(UTC)
        resolved_status = status or ("success" if success else "failed")
        resolved_parsed_output = parsed_output or details or {}
        resolved_raw_output = raw_output if raw_output is not None else resolved_parsed_output
        resolved_metadata = {
            "summary": summary,
            "started_at": start.isoformat().replace("+00:00", "Z"),
            "finished_at": end.isoformat().replace("+00:00", "Z"),
            "duration_seconds": max((end - start).total_seconds(), 0.0),
        }
        if metadata:
            resolved_metadata.update(metadata)
        resolved_artifacts = [
            artifact if isinstance(artifact, ToolArtifact) else ToolArtifact(**artifact)
            for artifact in (artifacts or [])
        ]
        if evidence_paths and not resolved_artifacts:
            resolved_artifacts = [ToolArtifact(kind="evidence", path=path) for path in evidence_paths]
        resolved_findings = [_coerce_finding_candidate(candidate) for candidate in (findings_candidates or findings or [])]
        return cls(
            tool_id=tool_id,
            action_id=action_id,
            target=target,
            run_id=run_id or "",
            scope_id=scope_id or "",
            timestamp=end.isoformat().replace("+00:00", "Z"),
            status=resolved_status,
            raw_output=resolved_raw_output,
            parsed_output=resolved_parsed_output,
            artifacts=resolved_artifacts,
            findings_candidates=resolved_findings,
            next_safe_checks=next_safe_checks or [],
            metadata=resolved_metadata,
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
    approval_required: bool = False
    allowed_target_kinds: tuple[str, ...] = ("scope_base_url",)
    expected_artifact_kinds: tuple[str, ...] = ("evidence",)
    parser_available: bool = True
    scope_rule: str = "target must remain inside the validated scope"

    def execute(self, action: Any, context: ExecutionContext) -> ToolResult:
        return self.executor(action, context)

    def parse(self, result: ToolResult) -> dict[str, Any]:
        return result.parsed_output

    def summarize(self, result: ToolResult) -> str:
        return result.summary

    def to_artifacts(self, result: ToolResult) -> list[ToolArtifact]:
        return result.artifacts

    def to_findings_candidates(self, result: ToolResult) -> list[FindingCandidate]:
        return result.findings_candidates
