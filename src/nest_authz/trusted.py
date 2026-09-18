"""Trusted orchestration over authenticated policy and delegation artifacts."""

from __future__ import annotations

from .authenticated_delegation import authenticate_delegation_chain
from .canonical import sha256_digest
from .domain import (
    _TRUSTED_AUTHORIZATION_RESULT_TOKEN,
    _TRUSTED_EXECUTION_AUTHORIZATION_RESULT_TOKEN,
    AuthenticatedDelegatedAuthority,
    AuthorizationRequest,
    AuthorizationState,
    DecisionReceipt,
    DelegationAuthenticationStatus,
    DelegationChain,
    ExecutionAuthorizationStatus,
    GrantAttestationSet,
    PendingApproval,
    PrincipalKeyRegistry,
    SubjectPrincipalBinding,
    TrustedAuthorityRoots,
    TrustedAuthorizationResult,
    TrustedExecutionAuthorizationResult,
    TrustedExecutionAuthorizationStatus,
    TrustedPolicyBundle,
    TrustStore,
)
from .evaluator import evaluate
from .execution import revalidate_for_execution


def authorize_trusted(
    request: AuthorizationRequest,
    trusted_policy: TrustedPolicyBundle,
    authenticated_authority: AuthenticatedDelegatedAuthority,
    subject_binding: SubjectPrincipalBinding,
) -> TrustedAuthorizationResult:
    """Evaluate only after exact policy and delegation trust gates succeed."""

    if type(request) is not AuthorizationRequest:
        raise TypeError("request must be an AuthorizationRequest")
    if type(trusted_policy) is not TrustedPolicyBundle:
        raise TypeError("trusted_policy must be a TrustedPolicyBundle")
    if type(authenticated_authority) is not AuthenticatedDelegatedAuthority:
        raise TypeError(
            "authenticated_authority must be an AuthenticatedDelegatedAuthority"
        )
    if type(subject_binding) is not SubjectPrincipalBinding:
        raise TypeError("subject_binding must be a SubjectPrincipalBinding")

    verified_authority = authenticated_authority.verified_authority
    decision = evaluate(
        request,
        trusted_policy.bundle,
        verified_authority,
        subject_binding,
    )
    return TrustedAuthorizationResult._from_trusted_authorization(
        request_digest=sha256_digest(request),
        policy_bundle_digest=sha256_digest(trusted_policy.bundle),
        trusted_policy_digest=sha256_digest(trusted_policy),
        verified_authority_digest=sha256_digest(verified_authority),
        authenticated_authority_digest=sha256_digest(authenticated_authority),
        decision=decision,
        _token=_TRUSTED_AUTHORIZATION_RESULT_TOKEN,
    )


def revalidate_trusted_for_execution(
    original_receipt: DecisionReceipt,
    approved_state: PendingApproval,
    current_request: AuthorizationRequest,
    trusted_policy: TrustedPolicyBundle,
    current_chain: DelegationChain,
    current_state: AuthorizationState,
    current_subject_binding: SubjectPrincipalBinding,
    grant_attestations: GrantAttestationSet,
    trust_store: TrustStore,
    principal_key_registry: PrincipalKeyRegistry,
    trusted_authority_roots: TrustedAuthorityRoots,
) -> TrustedExecutionAuthorizationResult:
    """Freshly authenticate delegation before low-level revalidation."""

    if type(original_receipt) is not DecisionReceipt:
        raise TypeError("original_receipt must be a DecisionReceipt")
    if type(approved_state) is not PendingApproval:
        raise TypeError("approved_state must be a PendingApproval")
    if type(current_request) is not AuthorizationRequest:
        raise TypeError("current_request must be an AuthorizationRequest")
    if type(trusted_policy) is not TrustedPolicyBundle:
        raise TypeError("trusted_policy must be a TrustedPolicyBundle")
    if type(current_chain) is not DelegationChain:
        raise TypeError("current_chain must be a DelegationChain")
    if type(current_state) is not AuthorizationState:
        raise TypeError("current_state must be an AuthorizationState")
    if type(current_subject_binding) is not SubjectPrincipalBinding:
        raise TypeError("current_subject_binding must be a SubjectPrincipalBinding")

    authentication = authenticate_delegation_chain(
        current_chain,
        current_state,
        grant_attestations,
        trust_store,
        principal_key_registry,
        trusted_authority_roots,
    )
    execution_authorization = None
    if authentication.status is DelegationAuthenticationStatus.AUTHENTICATED:
        execution_authorization = revalidate_for_execution(
            original_receipt,
            approved_state,
            current_request,
            trusted_policy.bundle,
            current_chain,
            current_state,
            current_subject_binding,
        )
        status = (
            TrustedExecutionAuthorizationStatus.AUTHORIZED
            if execution_authorization.status is ExecutionAuthorizationStatus.AUTHORIZED
            else TrustedExecutionAuthorizationStatus.EXECUTION_REVALIDATION_FAILED
        )
    else:
        status = TrustedExecutionAuthorizationStatus.DELEGATION_AUTHENTICATION_FAILED

    return TrustedExecutionAuthorizationResult._from_trusted_revalidation(
        status=status,
        current_request_digest=sha256_digest(current_request),
        policy_bundle_digest=sha256_digest(trusted_policy.bundle),
        trusted_policy_digest=sha256_digest(trusted_policy),
        delegation_authentication=authentication,
        execution_authorization=execution_authorization,
        _token=_TRUSTED_EXECUTION_AUTHORIZATION_RESULT_TOKEN,
    )
