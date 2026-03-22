from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Confidence(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    title: str
    severity: Severity
    confidence: Confidence
    affected_asset: str
    evidence: list[str] = Field(default_factory=list)
    why_it_matters: str
    safe_verification_status: str
    remediation: str
    source_tool: str | None = None
    source_action_id: str | None = None

