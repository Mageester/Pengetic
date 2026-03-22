from __future__ import annotations

import asyncio
from dataclasses import dataclass

from pengetic.llm import OllamaPlannerService, PlannerContext, PlannerSuggestion


@dataclass
class _FakeResponse:
    payload: dict[str, object]

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return self.payload


class _FakeClient:
    def __init__(self, *args, **kwargs) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def __aenter__(self) -> "_FakeClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def post(self, path: str, json: dict[str, object]) -> _FakeResponse:
        self.calls.append((path, json))
        return _FakeResponse(
            {
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"summary":"Passive review complete.",'
                                '"next_allowed_step":"Execute the approved login probe.",'
                                '"recommended_action_id":"approved-login",'
                                '"rationale":"The action is already approved and remains in scope.",'
                                '"confidence":"high"}'
                            )
                        }
                    }
                ]
            }
        )


def test_ollama_planner_service_parses_json(monkeypatch) -> None:
    monkeypatch.setattr("pengetic.llm.httpx.AsyncClient", _FakeClient)
    service = OllamaPlannerService(base_url="http://127.0.0.1:11434/v1", model="llama3.1")
    context = PlannerContext(
        scope_name="Demo",
        scope_id="scope-1",
        run_id="run-1",
        state="awaiting_approval",
        profile="passive-only",
        findings=[{"title": "Missing HSTS header"}],
        pending_actions=[{"action_id": "pending-login"}],
        approved_actions=[{"action_id": "approved-login"}],
        plan_actions=[
            {"action_id": "approved-login"},
            {"action_id": "pending-login"},
        ],
        latest_run_summary='{"state":"awaiting_approval"}',
    )

    suggestion = asyncio.run(service.suggest(context, model="llama3.1"))

    assert isinstance(suggestion, PlannerSuggestion)
    assert suggestion.source == "ollama"
    assert suggestion.recommended_action_id == "approved-login"
    assert suggestion.next_allowed_step == "Execute the approved login probe."
    assert suggestion.confidence == "high"
