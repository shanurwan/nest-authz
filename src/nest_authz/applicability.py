"""Pure binding of validated delegated authority to one exact request."""

from __future__ import annotations

from typing import TypeAlias

from .canonical import sha256_digest
from .domain import (
    AuthorityApplicabilityResult,
    AuthorityApplicabilityStatus,
    AuthorityBoundEvaluation,
    AuthorizationRequest,
    VerifiedAuthority,
)


_Scalar: TypeAlias = str | int | bool | None


def _context_value(
    request: AuthorizationRequest,
    name: str,
) -> tuple[bool, _Scalar]:
    for key, value in request.context.attributes:
        if key == name:
            return True, value
    return False, None


def _evaluate_bound(
    request: AuthorizationRequest,
    name: str,
    upper_bound: int,
) -> AuthorityBoundEvaluation:
    present, supplied_value = _context_value(request, name)
    if not present:
        status = AuthorityApplicabilityStatus.MISSING_CONTEXT
    elif type(supplied_value) is not int:
        status = AuthorityApplicabilityStatus.TYPE_ERROR
    elif supplied_value > upper_bound:
        status = AuthorityApplicabilityStatus.BOUND_EXCEEDED
    else:
        status = AuthorityApplicabilityStatus.APPLICABLE

    return AuthorityBoundEvaluation(
        name=name,
        upper_bound=upper_bound,
        present=present,
        supplied_value=supplied_value,
        status=status,
    )


def check_authority_applicability(
    request: AuthorizationRequest,
    authority: VerifiedAuthority,
) -> AuthorityApplicabilityResult:
    """Check whether effective validated authority contains one request."""

    if type(request) is not AuthorizationRequest:
        raise TypeError("request must be an AuthorizationRequest")
    if type(authority) is not VerifiedAuthority:
        raise TypeError("authority must be a VerifiedAuthority")

    action_matches = authority.scope.action == request.action
    resource_matches = authority.scope.resource == request.resource
    bound_evaluations = tuple(
        _evaluate_bound(request, name, upper_bound)
        for name, upper_bound in authority.scope.context_upper_bounds
    )
    bound_statuses = tuple(
        evaluation.status for evaluation in bound_evaluations
    )

    if not action_matches:
        status = AuthorityApplicabilityStatus.ACTION_MISMATCH
    elif not resource_matches:
        status = AuthorityApplicabilityStatus.RESOURCE_MISMATCH
    elif AuthorityApplicabilityStatus.MISSING_CONTEXT in bound_statuses:
        status = AuthorityApplicabilityStatus.MISSING_CONTEXT
    elif AuthorityApplicabilityStatus.TYPE_ERROR in bound_statuses:
        status = AuthorityApplicabilityStatus.TYPE_ERROR
    elif AuthorityApplicabilityStatus.BOUND_EXCEEDED in bound_statuses:
        status = AuthorityApplicabilityStatus.BOUND_EXCEEDED
    else:
        status = AuthorityApplicabilityStatus.APPLICABLE

    return AuthorityApplicabilityResult(
        status=status,
        request_digest=sha256_digest(request),
        authority_digest=sha256_digest(authority),
        chain_digest=authority.chain_digest,
        state_digest=authority.state_digest,
        effective_grant_id=authority.grant_id,
        expected_action=authority.scope.action,
        request_action=request.action,
        action_matches=action_matches,
        expected_resource=authority.scope.resource,
        request_resource=request.resource,
        resource_matches=resource_matches,
        bound_evaluations=bound_evaluations,
    )
