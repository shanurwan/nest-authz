"""Pure deterministic binding of request subjects to authority holders."""

from __future__ import annotations

from .canonical import sha256_digest
from .domain import (
    AuthorizationRequest,
    SubjectAuthorityBindingResult,
    SubjectAuthorityBindingStatus,
    SubjectPrincipalBinding,
    VerifiedAuthority,
)


def check_subject_authority_binding(
    request: AuthorizationRequest,
    binding: SubjectPrincipalBinding,
    authority: VerifiedAuthority,
) -> SubjectAuthorityBindingResult:
    """Check a supplied Subject/Principal assertion against one authority."""

    if type(request) is not AuthorizationRequest:
        raise TypeError("request must be an AuthorizationRequest")
    if type(binding) is not SubjectPrincipalBinding:
        raise TypeError("binding must be a SubjectPrincipalBinding")
    if type(authority) is not VerifiedAuthority:
        raise TypeError("authority must be a VerifiedAuthority")

    if request.subject != binding.subject:
        status = SubjectAuthorityBindingStatus.SUBJECT_MISMATCH
    elif binding.principal != authority.principal:
        status = SubjectAuthorityBindingStatus.PRINCIPAL_MISMATCH
    else:
        status = SubjectAuthorityBindingStatus.BOUND

    return SubjectAuthorityBindingResult(
        status=status,
        request_digest=sha256_digest(request),
        authority_digest=sha256_digest(authority),
        request_subject=request.subject,
        binding=binding,
        authority_principal=authority.principal,
        effective_grant_id=authority.grant_id,
    )
