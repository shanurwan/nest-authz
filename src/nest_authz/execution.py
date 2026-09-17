"""Pure deterministic execution-time revalidation after approval."""

from __future__ import annotations

from .canonical import sha256_digest
from .delegation import validate_authority
from .domain import (
    ApprovalStatus,
    AuthorityApplicabilityStatus,
    AuthorityValidationStatus,
    AuthorizationRequest,
    AuthorizationState,
    DecisionReceipt,
    DelegationChain,
    ExecutionAuthorizationResult,
    ExecutionAuthorizationStatus,
    ExecutionPermit,
    Outcome,
    PendingApproval,
    PolicyBundle,
    SubjectAuthorityBindingStatus,
    SubjectPrincipalBinding,
    _EXECUTION_AUTHORIZATION_RESULT_TOKEN,
    _EXECUTION_PERMIT_TOKEN,
)
from .evaluator import evaluate


def revalidate_for_execution(
    original_receipt: DecisionReceipt,
    approved_state: PendingApproval,
    current_request: AuthorizationRequest,
    current_policy_bundle: PolicyBundle,
    current_delegation_chain: DelegationChain,
    current_authorization_state: AuthorizationState,
    current_subject_binding: SubjectPrincipalBinding,
) -> ExecutionAuthorizationResult:
    """Freshly revalidate approved intent against current supplied state."""

    if type(original_receipt) is not DecisionReceipt:
        raise TypeError("original_receipt must be a DecisionReceipt")
    if type(approved_state) is not PendingApproval:
        raise TypeError("approved_state must be a PendingApproval")
    if type(current_request) is not AuthorizationRequest:
        raise TypeError("current_request must be an AuthorizationRequest")
    if type(current_policy_bundle) is not PolicyBundle:
        raise TypeError("current_policy_bundle must be a PolicyBundle")
    if type(current_delegation_chain) is not DelegationChain:
        raise TypeError(
            "current_delegation_chain must be a DelegationChain"
        )
    if type(current_authorization_state) is not AuthorizationState:
        raise TypeError(
            "current_authorization_state must be an AuthorizationState"
        )
    if type(current_subject_binding) is not SubjectPrincipalBinding:
        raise TypeError(
            "current_subject_binding must be a SubjectPrincipalBinding"
        )

    original_receipt_digest = sha256_digest(original_receipt)
    approved_state_digest = sha256_digest(approved_state)
    request_digest = sha256_digest(current_request)
    policy_bundle_digest = sha256_digest(current_policy_bundle)
    chain_digest = sha256_digest(current_delegation_chain)
    state_digest = sha256_digest(current_authorization_state)

    validation = validate_authority(
        current_delegation_chain,
        current_authorization_state,
    )
    authority = validation.verified_authority
    decision = evaluate(
        current_request,
        current_policy_bundle,
        authority,
        current_subject_binding,
    )
    holder_binding = decision.evidence.subject_authority_binding
    applicability = decision.evidence.authority_applicability

    if approved_state.status is not ApprovalStatus.APPROVED:
        status = ExecutionAuthorizationStatus.APPROVAL_NOT_APPROVED
    elif (
        approved_state.receipt != original_receipt
        or approved_state.receipt_digest != original_receipt_digest
    ):
        status = ExecutionAuthorizationStatus.RECEIPT_MISMATCH
    elif request_digest != original_receipt.request_digest:
        status = ExecutionAuthorizationStatus.REQUEST_MISMATCH
    elif chain_digest != original_receipt.delegation_chain_digest:
        status = ExecutionAuthorizationStatus.DELEGATION_CHAIN_MISMATCH
    elif validation.status is not AuthorityValidationStatus.VALID:
        status = ExecutionAuthorizationStatus.AUTHORITY_INVALID
    elif (
        holder_binding is None
        or holder_binding.status is not SubjectAuthorityBindingStatus.BOUND
    ):
        status = ExecutionAuthorizationStatus.HOLDER_BINDING_FAILED
    elif (
        applicability is None
        or applicability.status
        is not AuthorityApplicabilityStatus.APPLICABLE
    ):
        status = ExecutionAuthorizationStatus.AUTHORITY_NOT_APPLICABLE
    elif decision.outcome is Outcome.DENY:
        status = ExecutionAuthorizationStatus.POLICY_DENIED
    elif decision.outcome is Outcome.PERMIT:
        status = (
            ExecutionAuthorizationStatus.POLICY_REAUTHORIZATION_REQUIRED
        )
    elif (
        decision.approval_requirements
        != original_receipt.approval_requirements
        or decision.approval_requirements
        != approved_state.approval_requirements
    ):
        status = ExecutionAuthorizationStatus.APPROVAL_REQUIREMENTS_CHANGED
    elif policy_bundle_digest != original_receipt.policy_bundle_digest:
        status = ExecutionAuthorizationStatus.POLICY_BUNDLE_MISMATCH
    else:
        status = ExecutionAuthorizationStatus.AUTHORIZED

    execution_permit = None
    if status is ExecutionAuthorizationStatus.AUTHORIZED:
        if authority is None or holder_binding is None or applicability is None:
            raise RuntimeError(
                "authorized execution requires complete authority evidence"
            )
        execution_permit = ExecutionPermit._from_revalidation(
            original_receipt_digest=original_receipt_digest,
            approved_state_digest=approved_state_digest,
            current_request_digest=request_digest,
            current_policy_bundle_digest=policy_bundle_digest,
            current_delegation_chain_digest=chain_digest,
            current_authorization_state_digest=state_digest,
            current_validated_authority_digest=sha256_digest(authority),
            subject_authority_binding=holder_binding,
            authority_applicability=applicability,
            decision=decision,
            _token=_EXECUTION_PERMIT_TOKEN,
        )

    return ExecutionAuthorizationResult._from_revalidation(
        status=status,
        original_receipt_digest=original_receipt_digest,
        approved_state_digest=approved_state_digest,
        current_request_digest=request_digest,
        current_policy_bundle_digest=policy_bundle_digest,
        current_delegation_chain_digest=chain_digest,
        current_authorization_state_digest=state_digest,
        authority_validation=validation,
        subject_authority_binding=holder_binding,
        authority_applicability=applicability,
        decision=decision,
        execution_permit=execution_permit,
        _token=_EXECUTION_AUTHORIZATION_RESULT_TOKEN,
    )
