"""Pure deterministic authorization of approval actors."""

from __future__ import annotations

from .domain import (
    ApprovalRequirement,
    ApproverAuthorizationResult,
    ApproverAuthorizationStatus,
    ApproverSubjectPrincipalBinding,
    Subject,
)


def check_approver_authorization(
    actor: Subject,
    binding: ApproverSubjectPrincipalBinding,
    required_requirement: ApprovalRequirement,
    attempted_requirement: ApprovalRequirement,
) -> ApproverAuthorizationResult:
    """Authorize one bound actor for one exact approval requirement."""

    if type(actor) is not Subject:
        raise TypeError("actor must be a Subject")
    if type(binding) is not ApproverSubjectPrincipalBinding:
        raise TypeError("binding must be an ApproverSubjectPrincipalBinding")
    if type(required_requirement) is not ApprovalRequirement:
        raise TypeError("required_requirement must be an ApprovalRequirement")
    if type(attempted_requirement) is not ApprovalRequirement:
        raise TypeError("attempted_requirement must be an ApprovalRequirement")

    if required_requirement != attempted_requirement:
        status = ApproverAuthorizationStatus.REQUIREMENT_MISMATCH
    elif actor != binding.subject:
        status = ApproverAuthorizationStatus.SUBJECT_MISMATCH
    elif binding.principal not in required_requirement.allowed_principals:
        status = ApproverAuthorizationStatus.PRINCIPAL_NOT_ALLOWED
    else:
        status = ApproverAuthorizationStatus.AUTHORIZED

    return ApproverAuthorizationResult(
        status=status,
        actor=actor,
        binding=binding,
        required_requirement=required_requirement,
        attempted_requirement=attempted_requirement,
    )
