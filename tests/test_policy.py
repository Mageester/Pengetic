from __future__ import annotations

from pathlib import Path

from scopeguard.policy.approvals import ApprovalRecord, ApprovalStore
from scopeguard.policy.gate import ApprovalGate
from scopeguard.policy.plan import AssessmentAction
from scopeguard.policy.risk import RiskLevel


def test_approval_gate_requires_record_for_active_actions(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "approvals.jsonl")
    gate = ApprovalGate()
    scope_fp = "abc123"

    passive = AssessmentAction(
        action_id="passive",
        title="Passive",
        objective="Passive",
        target="https://demo.example",
        tool_id="header-review",
        classification=RiskLevel.passive_safe,
    )
    active = AssessmentAction(
        action_id="active",
        title="Active",
        objective="Active",
        target="/login",
        tool_id="approved-login-surface-probe",
        classification=RiskLevel.low_risk_active,
    )

    passive_decision = gate.evaluate(
        action_id=passive.action_id,
        risk=passive.classification,
        scope_fingerprint=scope_fp,
        approvals=store,
    )
    active_decision = gate.evaluate(
        action_id=active.action_id,
        risk=active.classification,
        scope_fingerprint=scope_fp,
        approvals=store,
    )

    assert passive_decision.approved is True
    assert passive_decision.auto_approved is True
    assert active_decision.approved is False

    store.append(
        ApprovalRecord.create(
            action_id=active.action_id,
            scope_fingerprint=scope_fp,
            approved_by="tester",
            note="Approved in lab.",
            risk=active.classification,
        )
    )
    approved_decision = gate.evaluate(
        action_id=active.action_id,
        risk=active.classification,
        scope_fingerprint=scope_fp,
        approvals=store,
    )
    assert approved_decision.approved is True
    assert approved_decision.approval_record is not None


def test_forbidden_actions_are_blocked(tmp_path: Path) -> None:
    store = ApprovalStore(tmp_path / "approvals.jsonl")
    gate = ApprovalGate()
    decision = gate.evaluate(
        action_id="forbidden",
        risk=RiskLevel.forbidden,
        scope_fingerprint="abc123",
        approvals=store,
    )
    assert decision.approved is False

