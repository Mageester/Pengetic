from __future__ import annotations

from enum import Enum


class AssessmentState(str, Enum):
    idle = "idle"
    scope_uploaded = "scope_uploaded"
    scope_validated = "scope_validated"
    plan_ready = "plan_ready"
    running = "running"
    awaiting_approval = "awaiting_approval"
    completed = "completed"
    failed = "failed"


_ALLOWED_TRANSITIONS: dict[AssessmentState, set[AssessmentState]] = {
    AssessmentState.idle: {AssessmentState.scope_uploaded, AssessmentState.failed},
    AssessmentState.scope_uploaded: {
        AssessmentState.scope_validated,
        AssessmentState.plan_ready,
        AssessmentState.failed,
    },
    AssessmentState.scope_validated: {AssessmentState.plan_ready, AssessmentState.failed},
    AssessmentState.plan_ready: {AssessmentState.running, AssessmentState.failed},
    AssessmentState.running: {
        AssessmentState.awaiting_approval,
        AssessmentState.completed,
        AssessmentState.failed,
    },
    AssessmentState.awaiting_approval: {
        AssessmentState.running,
        AssessmentState.completed,
        AssessmentState.failed,
    },
    AssessmentState.completed: {AssessmentState.running},
    AssessmentState.failed: {AssessmentState.running},
}


class AssessmentStateMachine:
    @staticmethod
    def can_transition(current: AssessmentState, new_state: AssessmentState) -> bool:
        return new_state in _ALLOWED_TRANSITIONS.get(current, set())

    @classmethod
    def transition(cls, current: AssessmentState, new_state: AssessmentState) -> AssessmentState:
        if current == new_state:
            return current
        if not cls.can_transition(current, new_state):
            raise ValueError(f"Invalid assessment state transition: {current.value} -> {new_state.value}")
        return new_state
