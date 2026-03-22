from __future__ import annotations

import pytest

from pengetic.state import AssessmentState, AssessmentStateMachine


def test_state_machine_allows_expected_progression() -> None:
    current = AssessmentState.idle
    current = AssessmentStateMachine.transition(current, AssessmentState.scope_uploaded)
    current = AssessmentStateMachine.transition(current, AssessmentState.scope_validated)
    current = AssessmentStateMachine.transition(current, AssessmentState.plan_ready)
    current = AssessmentStateMachine.transition(current, AssessmentState.running)
    current = AssessmentStateMachine.transition(current, AssessmentState.awaiting_approval)
    current = AssessmentStateMachine.transition(current, AssessmentState.running)
    current = AssessmentStateMachine.transition(current, AssessmentState.completed)

    assert current is AssessmentState.completed


def test_state_machine_rejects_invalid_transition() -> None:
    with pytest.raises(ValueError):
        AssessmentStateMachine.transition(AssessmentState.idle, AssessmentState.completed)
