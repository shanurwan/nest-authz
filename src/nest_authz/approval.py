"""Pure deterministic transitions for receipt-bound approvals."""

from __future__ import annotations

from .canonical import sha256_digest
from .domain import (
    ApprovalRequirement,
    ApprovalRequirementState,
    ApprovalRequirementStatus,
    ApprovalStatus,
    ApproverAuthorizationResult,
    ApproverAuthorizationStatus,
    DecisionReceipt,
    ExecutionPermit,
    PendingApproval,
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
    authorization: ApproverAuthorizationResult | None,
    logical_time: int,
) -> PendingApproval:
    if type(approval) is not PendingApproval:
        raise TypeError("approval must be a PendingApproval")
    if type(requirement) is not ApprovalRequirement:
        raise TypeError("requirement must be an ApprovalRequirement")
    if type(status) is not ApprovalRequirementStatus:
        raise TypeError("status must be an ApprovalRequirementStatus")
    if (
        authorization is not None
        and type(authorization) is not ApproverAuthorizationResult
    ):
        raise TypeError(
            "authorization must be an ApproverAuthorizationResult or None"
        )
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
    if status in (
        ApprovalRequirementStatus.APPROVED,
        ApprovalRequirementStatus.REJECTED,
    ):
        if (
            authorization is None
            or authorization.status
            is not ApproverAuthorizationStatus.AUTHORIZED
        ):
            raise ApprovalTransitionError(
                "approval transition requires AUTHORIZED approver evidence"
            )
        if (
            authorization.required_requirement != requirement
            or authorization.attempted_requirement != requirement
        ):
            raise ApprovalTransitionError(
                "approver evidence does not bind the exact requirement"
            )

    replacement = ApprovalRequirementState(
        requirement=requirement,
        status=status,
        authorization=authorization,
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
        execution_permit_digest=None,
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
            authorization=None,
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
        execution_permit_digest=None,
        _token=_PENDING_APPROVAL_TOKEN,
    )


def approve_requirement(
    approval: PendingApproval,
    requirement: ApprovalRequirement,
    authorization: ApproverAuthorizationResult,
    logical_time: int,
) -> PendingApproval:
    """Approve one pending requirement and return a new state."""

    return _transition_requirement(
        approval,
        requirement,
        ApprovalRequirementStatus.APPROVED,
        authorization,
        logical_time,
    )


def reject_requirement(
    approval: PendingApproval,
    requirement: ApprovalRequirement,
    authorization: ApproverAuthorizationResult,
    logical_time: int,
) -> PendingApproval:
    """Reject one pending requirement and return a new state."""

    return _transition_requirement(
        approval,
        requirement,
        ApprovalRequirementStatus.REJECTED,
        authorization,
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
    execution_permit: ExecutionPermit,
    logical_time: int,
) -> PendingApproval:
    """Consume a fully approved state using its exact execution permit."""

    if type(approval) is not PendingApproval:
        raise TypeError("approval must be a PendingApproval")
    if type(execution_permit) is not ExecutionPermit:
        raise TypeError("execution_permit must be an ExecutionPermit")
    _validate_logical_time(approval, logical_time)

    if approval.status is ApprovalStatus.CONSUMED:
        raise ApprovalTransitionError("consumed approval cannot transition")
    if approval.receipt_digest != execution_permit.original_receipt_digest:
        raise ApprovalTransitionError(
            "execution permit does not bind the approval receipt"
        )
    if sha256_digest(approval) != execution_permit.approved_state_digest:
        raise ApprovalTransitionError(
            "execution permit does not bind the exact approved state"
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
        execution_permit_digest=sha256_digest(execution_permit),
        _token=_PENDING_APPROVAL_TOKEN,
    )
