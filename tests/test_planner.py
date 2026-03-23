from __future__ import annotations

from pathlib import Path

from scopeguard.config import RuntimeProfile
from scopeguard.policy.plan import AssessmentPlanner
from scopeguard.scope.loader import load_scope_package
from scopeguard.tools.registry import default_tool_registry


def test_planner_builds_expected_actions() -> None:
    scope = load_scope_package(Path("examples/scope.demo.yaml"))
    plan = AssessmentPlanner(default_tool_registry()).build(scope, RuntimeProfile.passive_only)
    action_ids = [action.action_id for action in plan.actions]

    assert action_ids[:5] == [
        "active-nmap-service-discovery",
        "passive-http-probe",
        "passive-tls-review",
        "passive-route-inventory",
        "passive-header-review",
    ]
    assert "passive-dns-visibility" in action_ids
    assert "passive-robots-fetch" in action_ids
    assert "passive-sitemap-fetch" in action_ids
    assert "passive-tech-fingerprint" in action_ids
    assert "active-login-surface-probe" in action_ids
    assert "active-api-surface-probe" in action_ids
    assert "active-rate-limit-probe" in action_ids

    passive = plan.get_action("passive-header-review")
    assert passive.allowed_by_scope is True
    assert passive.classification.value == "PASSIVE_SAFE"
