from typing import Dict, Set, Tuple
from app.services.case_management.models import CaseStatus


class InvalidCaseStateTransitionError(ValueError):
    """Raised when an illegal or unsupported case state transition is attempted."""
    pass


# Mapping of current status -> allowed next statuses
VALID_TRANSITIONS: Dict[CaseStatus, Set[CaseStatus]] = {
    CaseStatus.NEW: {
        CaseStatus.TRIAGING,
        CaseStatus.INVESTIGATING,
        CaseStatus.CLOSED,
    },
    CaseStatus.TRIAGING: {
        CaseStatus.INVESTIGATING,
        CaseStatus.NEW,
        CaseStatus.CLOSED,
    },
    CaseStatus.INVESTIGATING: {
        CaseStatus.CONTAINMENT,
        CaseStatus.TRIAGING,
        CaseStatus.RESOLVED,
        CaseStatus.CLOSED,
    },
    CaseStatus.CONTAINMENT: {
        CaseStatus.ERADICATION,
        CaseStatus.INVESTIGATING,
        CaseStatus.CLOSED,
    },
    CaseStatus.ERADICATION: {
        CaseStatus.RECOVERY,
        CaseStatus.CONTAINMENT,
        CaseStatus.CLOSED,
    },
    CaseStatus.RECOVERY: {
        CaseStatus.MONITORING,
        CaseStatus.ERADICATION,
        CaseStatus.CLOSED,
    },
    CaseStatus.MONITORING: {
        CaseStatus.RESOLVED,
        CaseStatus.INVESTIGATING,
        CaseStatus.CLOSED,
    },
    CaseStatus.RESOLVED: {
        CaseStatus.CLOSED,
        CaseStatus.MONITORING,
        CaseStatus.INVESTIGATING,
    },
    CaseStatus.CLOSED: {
        CaseStatus.TRIAGING,
        CaseStatus.INVESTIGATING,
    },
}


def validate_status_transition(
    current_status: CaseStatus,
    new_status: CaseStatus,
) -> Tuple[bool, str]:
    """
    Validates if transitioning from current_status to new_status is permissible.
    Returns (is_valid, explanation_message).
    """
    if current_status == new_status:
        return True, f"Status is already {current_status.value}."

    allowed = VALID_TRANSITIONS.get(current_status, set())
    if new_status in allowed:
        return True, f"Valid transition from {current_status.value} to {new_status.value}."

    return False, (
        f"Invalid status transition: Cannot transition case directly from "
        f"'{current_status.value}' to '{new_status.value}'. "
        f"Permissible next states are: {', '.join(s.value for s in allowed)}."
    )
