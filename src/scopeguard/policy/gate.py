from __future__ import annotations

from dataclasses import dataclass

from .approvals import ApprovalRecord, ApprovalStore
from .risk import RiskLevel


@dataclass(frozen=True, slots=True)
class GateDecision:
    approved: bool
    auto_approved: bool
    reason: str
    approval_record: ApprovalRecord | None = None


class ApprovalGate:
    def evaluate(
        self,
        *,
        action_id: str,
        risk: RiskLevel,
        scope_fingerprint: str,
        approvals: ApprovalStore,
    ) -> GateDecision:
        if risk == RiskLevel.forbidden:
            return GateDecision(
                approved=False,
                auto_approved=False,
                reason="Action is forbidden by policy.",
            )

        if risk == RiskLevel.passive_safe:
            return GateDecision(
                approved=True,
                auto_approved=True,
                reason="Passive-safe actions may execute automatically.",
            )

        approval = approvals.latest_for_action(action_id, scope_fingerprint)
        if approval is not None:
            return GateDecision(
                approved=True,
                auto_approved=False,
                reason="Matching approval record found.",
                approval_record=approval,
            )

        return GateDecision(
            approved=False,
            auto_approved=False,
            reason="Explicit approval is required before this action can run.",
        )

