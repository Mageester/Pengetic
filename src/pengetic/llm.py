from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import json
import re

import httpx
from pydantic import BaseModel, ConfigDict, Field


class PlannerSuggestion(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    model: str
    source: str
    summary: str
    next_allowed_step: str
    recommended_action_id: str | None = None
    rationale: str
    confidence: str = "medium"
    raw: dict[str, Any] = Field(default_factory=dict)


@dataclass(slots=True)
class PlannerContext:
    scope_name: str
    scope_id: str | None
    run_id: str | None
    state: str
    profile: str
    findings: list[dict[str, Any]]
    pending_actions: list[dict[str, Any]]
    approved_actions: list[dict[str, Any]]
    plan_actions: list[dict[str, Any]]
    completed_actions: list[dict[str, Any]] = field(default_factory=list)
    evidence_artifacts: list[dict[str, Any]] = field(default_factory=list)
    remaining_actions: list[dict[str, Any]] = field(default_factory=list)
    rate_limit_snapshot: dict[str, Any] = field(default_factory=dict)
    latest_run_summary: str | None = None


def _extract_json_block(text: str) -> dict[str, Any]:
    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        raise ValueError("No JSON object found in planner response.")
    return json.loads(match.group(0))


def _fallback_suggestion(context: PlannerContext, *, model: str) -> PlannerSuggestion:
    if context.approved_actions:
        action = context.approved_actions[0]
        return PlannerSuggestion(
            model=model,
            source="fallback",
            summary=f"{len(context.findings)} finding(s) recorded. Approved actions are available for safe continuation.",
            next_allowed_step="Execute the first approved active action in scope.",
            recommended_action_id=action["action_id"],
            rationale="A matching approval already exists and the action remains within the validated scope.",
            confidence="medium",
            raw={"fallback": True},
        )
    if context.pending_actions:
        action = context.pending_actions[0]
        return PlannerSuggestion(
            model=model,
            source="fallback",
            summary=f"{len(context.findings)} finding(s) recorded. The next step is still waiting on approval.",
            next_allowed_step="Wait for explicit approval before any active step runs.",
            recommended_action_id=action["action_id"],
            rationale="The action is in scope but is not yet approved.",
            confidence="medium",
            raw={"fallback": True},
        )
    return PlannerSuggestion(
        model=model,
        source="fallback",
        summary=f"{len(context.findings)} finding(s) recorded and no further allowed actions are queued.",
        next_allowed_step="Review findings and export the report.",
        recommended_action_id=None,
        rationale="No additional allowed actions remain in the current plan.",
        confidence="high",
        raw={"fallback": True},
    )


@dataclass(slots=True)
class OllamaPlannerService:
    base_url: str
    model: str = "llama3.1"
    timeout_seconds: float = 30.0

    def _normalized_base_url(self) -> str:
        return self.base_url.rstrip("/")

    def _messages(self, context: PlannerContext) -> list[dict[str, str]]:
        system = (
            "You are Pengetic's local defensive planning assistant. "
            "You may only summarize findings and recommend the next allowed step from the supplied plan. "
            "Never suggest exploit payloads, persistence, brute force, credential attacks, destructive actions, "
            "shell commands, or anything outside the validated scope. "
            "Return only JSON with keys: summary, next_allowed_step, recommended_action_id, rationale, confidence."
        )
        user = {
            "scope_name": context.scope_name,
            "scope_id": context.scope_id,
            "run_id": context.run_id,
            "state": context.state,
            "profile": context.profile,
            "findings": context.findings,
            "pending_actions": context.pending_actions,
            "approved_actions": context.approved_actions,
            "plan_actions": context.plan_actions,
            "completed_actions": context.completed_actions,
            "evidence_artifacts": context.evidence_artifacts,
            "remaining_actions": context.remaining_actions,
            "rate_limit_snapshot": context.rate_limit_snapshot,
            "latest_run_summary": context.latest_run_summary,
        }
        return [
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": (
                    "Summarize the current assessment and propose the next allowed step. "
                    "If an approved active action is available, recommend that action id. "
                    "If only pending approvals remain, recommend waiting for approval. "
                    f"Context: {json.dumps(user, ensure_ascii=False, default=str)}"
                ),
            },
        ]

    async def suggest(self, context: PlannerContext, *, model: str | None = None) -> PlannerSuggestion:
        active_model = model or self.model
        body = {
            "model": active_model,
            "messages": self._messages(context),
            "temperature": 0.2,
            "stream": False,
        }
        try:
            async with httpx.AsyncClient(base_url=self._normalized_base_url(), timeout=self.timeout_seconds) as client:
                response = await client.post("/chat/completions", json=body)
                response.raise_for_status()
                payload = response.json()
            content = payload["choices"][0]["message"]["content"]
            raw = _extract_json_block(content)
            suggestion = PlannerSuggestion.model_validate(
                {
                    "model": active_model,
                    "source": "ollama",
                    "summary": raw.get("summary", ""),
                    "next_allowed_step": raw.get("next_allowed_step", ""),
                    "recommended_action_id": raw.get("recommended_action_id"),
                    "rationale": raw.get("rationale", ""),
                    "confidence": raw.get("confidence", "medium"),
                    "raw": raw,
                }
            )
            allowed_ids = {action["action_id"] for action in context.plan_actions}
            if suggestion.recommended_action_id and suggestion.recommended_action_id not in allowed_ids:
                return _fallback_suggestion(context, model=active_model)
            return suggestion
        except Exception:
            return _fallback_suggestion(context, model=active_model)
