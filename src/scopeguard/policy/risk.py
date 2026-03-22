from __future__ import annotations

from enum import Enum


class RiskLevel(str, Enum):
    passive_safe = "PASSIVE_SAFE"
    low_risk_active = "LOW_RISK_ACTIVE"
    high_risk_active = "HIGH_RISK_ACTIVE"
    forbidden = "FORBIDDEN"


RISK_ORDER = {
    RiskLevel.passive_safe: 0,
    RiskLevel.low_risk_active: 1,
    RiskLevel.high_risk_active: 2,
    RiskLevel.forbidden: 3,
}


def approval_required(risk: RiskLevel) -> bool:
    return risk != RiskLevel.passive_safe and risk != RiskLevel.forbidden

