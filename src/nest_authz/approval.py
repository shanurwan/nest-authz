"""Pure deterministic transitions for receipt-bound approvals."""

from __future__ import annotations

from .canonical import sha256_digest
from .domain import (
    ApprovalRequirement,
    ApprovalRequirementState,
    ApprovalRequirementStatus,
    ApprovalStatus,
    DecisionReceipt,
    PendingApproval,
    Principal,
    _PENDING_APPROVAL_TOKEN,
)


class ApprovalTransitionError(RuntimeError):
    """A deterministic invalid approval-state transition."""


def _validate_logical_time(
    approval: PendingApproval,
    logical_time: int,
) -> None:
    if type(logical_time) is not int:
        raise TypeError("logical_time must be an exact integer")
    if logical_time < approval.logical_time:
        raise ApprovalTransitionError(
            "logical time cannot precede the current approval state"
        )


def _transition_requirement(
    approval: PendingApproval,
    requirement: ApprovalRequirement,
    status: ApprovalRequirementStatus,
    decided_by: Principal | None,
    logical_time: int,
) -> PendingApproval:
    if type(approval) is not PendingApproval:
        raise TypeError("approval must be a PendingApproval")
    if type(requirement) is not ApprovalRequirement:
        raise TypeError("requirement must be an ApprovalRequirement")
    if type(status) is not ApprovalRequirementStatus:
        raise TypeError("status must be an ApprovalRequirementStatus")
    if decided_by is not None and type(decided_by) is not Principal:
        raise TypeError("decided_by must be a Principal or None")
    _validate_logical_time(approval, logical_time)

    if approval.status is ApprovalStatus.CONSUMED:
        raise ApprovalTransitionError("consumed approval cannot transition")

    selected: ApprovalRequirementState | None = None
    for state in approval.requirement_states:
        if state.requirement == requirement:
            selected = state
            break
    if selected is None:
        raise ApprovalTransitionError(
            "requirement is not part of the receipt approval set"
        )
    if selected.status is not ApprovalRequirementStatus.PENDING:
        raise ApprovalTransitionError(
            "only a pending requirement can transition"
        )

    replacement = ApprovalRequirementState(
        requirement=requirement,
        status=status,
        decided_by=decided_by,
        logical_time=logical_time,
    )
    states = tuple(
        replacement if state.requirement == requirement else state
        for state in approval.requirement_states
    )
    return PendingApproval._from_transition(
        receipt=approval.receipt,
        receipt_digest=approval.receipt_digest,
        requirement_states=states,
        logical_time=logical_time,
        consumed_at=None,
        _token=_PENDING_APPROVAL_TOKEN,
    )


def create_pending_approval(
    receipt: DecisionReceipt,
    logical_time: int,
) -> PendingApproval:
    """Create pending state for every requirement in an approval receipt."""

    if type(receipt) is not DecisionReceipt:
        raise TypeError("receipt must be a DecisionReceipt")
    if type(logical_time) is not int:
        raise TypeError("logical_time must be an exact integer")
    states = tuple(
        ApprovalRequirementState(
            requirement=requirement,
            status=ApprovalRequirementStatus.PENDING,
            decided_by=None,
            logical_time=logical_time,
        )
        for requirement in receipt.approval_requirements
    )
    return PendingApproval._from_transition(
        receipt=receipt,
        receipt_digest=sha256_digest(receipt),
        requirement_states=states,
        logical_time=logical_time,
        consumed_at=None,
        _token=_PENDING_APPROVAL_TOKEN,
    )


def approve_requirement(
    approval: PendingApproval,
    requirement: ApprovalRequirement,
    approver: Principal,
    logical_time: int,
) -> PendingApproval:
    """Approve one pending requirement and return a new state."""

    if type(approver) is not Principal:
        raise TypeError("approver must be a Principal")
    return _transition_requirement(
        approval,
        requirement,
        ApprovalRequirementStatus.APPROVED,
        approver,
        logical_time,
    )


def reject_requirement(
    approval: PendingApproval,
    requirement: ApprovalRequirement,
    rejector: Principal,
    logical_time: int,
) -> PendingApproval:
    """Reject one pending requirement and return a new state."""

    if type(rejector) is not Principal:
        raise TypeError("rejector must be a Principal")
    return _transition_requirement(
        approval,
        requirement,
        ApprovalRequirementStatus.REJECTED,
        rejector,
        logical_time,
    )


def expire_requirement(
    approval: PendingApproval,
    requirement: ApprovalRequirement,
    logical_time: int,
) -> PendingApproval:
    """Expire one pending requirement at supplied logical time."""

    return _transition_requirement(
        approval,
        requirement,
        ApprovalRequirementStatus.EXPIRED,
        None,
        logical_time,
    )


def consume_approval(
    approval: PendingApproval,
    current_receipt: DecisionReceipt,
    logical_time: int,
) -> PendingApproval:
    """Consume a fully approved state for the exact current receipt."""

    if type(approval) is not PendingApproval:
        raise TypeError("approval must be a PendingApproval")
    if type(current_receipt) is not DecisionReceipt:
        raise TypeError("current_receipt must be a DecisionReceipt")
    _validate_logical_time(approval, logical_time)

    if approval.status is ApprovalStatus.CONSUMED:
        raise ApprovalTransitionError("consumed approval cannot transition")
    if (
        approval.receipt != current_receipt
        or approval.receipt_digest != sha256_digest(current_receipt)
    ):
        raise ApprovalTransitionError(
            "approval receipt does not match the current receipt"
        )
    if approval.status is not ApprovalStatus.APPROVED:
        raise ApprovalTransitionError(
            "only an approved approval state can be consumed"
        )

    return PendingApproval._from_transition(
        receipt=approval.receipt,
        receipt_digest=approval.receipt_digest,
        requirement_states=approval.requirement_states,
        logical_time=logical_time,
        consumed_at=logical_time,
        _token=_PENDING_APPROVAL_TOKEN,
    )
