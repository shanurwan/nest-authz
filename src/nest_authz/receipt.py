"""Pure deterministic construction of authorization decision receipts."""

from __future__ import annotations

from .canonical import sha256_digest
from .domain import (
    Decision,
    DecisionReceipt,
    _DECISION_RECEIPT_TOKEN,
)


def create_decision_receipt(decision: Decision) -> DecisionReceipt:
    """Bind one completed Decision to its security-relevant identities."""

    if type(decision) is not Decision:
        raise TypeError("decision must be a Decision")

    evidence = decision.evidence
    applicability = evidence.authority_applicability
    binding = evidence.subject_authority_binding

    if applicability is not None:
        validated_authority_digest = applicability.authority_digest
    elif binding is not None:
        validated_authority_digest = binding.authority_digest
    else:
        validated_authority_digest = None

    return DecisionReceipt._from_evaluation(
        request_digest=evidence.request_digest,
        policy_bundle_digest=evidence.policy_bundle_digest,
        validated_authority_digest=validated_authority_digest,
        delegation_chain_digest=(
            applicability.chain_digest
            if applicability is not None
            else None
        ),
        authorization_state_digest=(
            applicability.state_digest
            if applicability is not None
            else None
        ),
        subject_principal_binding_evidence_digest=(
            sha256_digest(binding) if binding is not None else None
        ),
        authority_applicability_evidence_digest=(
            sha256_digest(applicability)
            if applicability is not None
            else None
        ),
        decision_digest=sha256_digest(decision),
        outcome=decision.outcome,
        approval_requirements=decision.approval_requirements,
        _token=_DECISION_RECEIPT_TOKEN,
    )
