"""Deterministic canonical bytes and content digests for domain objects."""

from __future__ import annotations

from collections.abc import Iterable
from hashlib import sha256

from .domain import (
    Action,
    ApprovalRequirement,
    ApprovalRequirementState,
    ApprovalRequirementStatus,
    ApprovalStatus,
    ApproverAuthorizationResult,
    ApproverAuthorizationStatus,
    ApproverSubjectPrincipalBinding,
    AuthorityContext,
    AuthorityApplicabilityResult,
    AuthorityApplicabilityStatus,
    AuthorityBoundEvaluation,
    AuthorityGrant,
    AuthorityScope,
    AuthorityValidationResult,
    AuthorityValidationStatus,
    AuthorizationRequest,
    AuthorizationState,
    Condition,
    ConditionOperator,
    ConditionStatus,
    Decision,
    DecisionEvidence,
    DecisionReceipt,
    DelegationChain,
    ExecutionAuthorizationResult,
    ExecutionAuthorizationStatus,
    ExecutionPermit,
    Obligation,
    Outcome,
    FieldNamespace,
    FieldReference,
    Policy,
    PolicyBundle,
    PendingApproval,
    Principal,
    Reason,
    RequestContext,
    Resource,
    Rule,
    RuleEffect,
    RuleEvaluation,
    RuleEvaluationStatus,
    RevocationSet,
    Sha256Digest,
    Subject,
    SubjectAuthorityBindingResult,
    SubjectAuthorityBindingStatus,
    SubjectPrincipalBinding,
    VerifiedAuthority,
)

_PREAMBLE = b"NEST-AUTHZ-CANONICAL\x00\x01"
_MAX_PAYLOAD_LENGTH = (1 << 64) - 1


def canonical_bytes(value: object) -> bytes:
    """Return the version-1 canonical bytes for a supported domain value."""

    return _PREAMBLE + _encode_domain(value)


def sha256_digest(value: object) -> Sha256Digest:
    """Return the typed SHA-256 digest of a canonical domain value."""

    return Sha256Digest(sha256(canonical_bytes(value)).digest())


def _frame(tag: bytes, payload: bytes) -> bytes:
    if len(tag) != 1:
        raise ValueError("canonical tags must contain exactly one byte")
    if len(payload) > _MAX_PAYLOAD_LENGTH:
        raise ValueError("canonical payload is too large")
    return tag + len(payload).to_bytes(8, byteorder="big") + payload


def _utf8(value: str) -> bytes:
    return value.encode("utf-8", errors="strict")


def _encode_null() -> bytes:
    return _frame(b"N", b"")


def _encode_boolean(value: bool) -> bytes:
    return _frame(b"B", b"\x01" if value else b"\x00")


def _encode_integer(value: int) -> bytes:
    negative = value < 0
    magnitude = -value if negative else value
    magnitude_bytes = (
        magnitude.to_bytes((magnitude.bit_length() + 7) // 8, byteorder="big")
        if magnitude
        else b""
    )
    sign = b"\x01" if negative else b"\x00"
    return _frame(b"I", sign + magnitude_bytes)


def _encode_string(value: str) -> bytes:
    return _frame(b"S", _utf8(value))


def _encode_sequence(values: Iterable[object]) -> bytes:
    return _frame(b"L", b"".join(_encode_domain(value) for value in values))


def _encode_map(entries: Iterable[tuple[str, bytes]]) -> bytes:
    canonical_entries: list[tuple[bytes, bytes, bytes]] = []
    seen: set[str] = set()

    for key, encoded_value in entries:
        if type(key) is not str:
            raise TypeError("canonical map keys must be strings")
        if type(encoded_value) is not bytes:
            raise TypeError("canonical map values must already be encoded bytes")
        if key in seen:
            raise ValueError("canonical maps must not contain duplicate keys")
        seen.add(key)
        key_bytes = _utf8(key)
        canonical_entries.append((key_bytes, _encode_string(key), encoded_value))

    canonical_entries.sort(key=lambda entry: entry[0])
    payload = b"".join(
        encoded_key + encoded_value
        for _, encoded_key, encoded_value in canonical_entries
    )
    return _frame(b"M", payload)


def _encode_record(
    wire_type: str,
    fields: Iterable[tuple[str, bytes]],
) -> bytes:
    return _frame(b"R", _encode_string(wire_type) + _encode_map(fields))


def _encode_scalar(value: object) -> bytes:
    if value is None:
        return _encode_null()
    if type(value) is bool:
        return _encode_boolean(value)
    if type(value) is int:
        return _encode_integer(value)
    if type(value) is str:
        return _encode_string(value)
    raise TypeError("unsupported canonical scalar type")


def _encode_scalar_map(values: Iterable[tuple[str, object]]) -> bytes:
    return _encode_map(
        (key, _encode_scalar(value))
        for key, value in values
    )


def _encode_integer_map(values: Iterable[tuple[str, int]]) -> bytes:
    return _encode_map(
        (key, _encode_integer(value))
        for key, value in values
    )


def _encode_string_sequence(values: Iterable[str]) -> bytes:
    return _frame(b"L", b"".join(_encode_string(value) for value in values))


def _encode_condition_status_map(
    values: Iterable[tuple[str, ConditionStatus]],
) -> bytes:
    return _encode_map(
        (key, _encode_domain(value))
        for key, value in values
    )


def _encode_optional_domain(value: object | None) -> bytes:
    return _encode_null() if value is None else _encode_domain(value)


def _encode_domain(value: object) -> bytes:
    value_type = type(value)

    if value_type is Subject:
        return _encode_record(
            "nest-authz/subject@1",
            (("identifier", _encode_string(value.identifier)),),
        )
    if value_type is Action:
        return _encode_record(
            "nest-authz/action@1",
            (("name", _encode_string(value.name)),),
        )
    if value_type is Resource:
        return _encode_record(
            "nest-authz/resource@1",
            (("identifier", _encode_string(value.identifier)),),
        )
    if value_type is Sha256Digest:
        return _encode_record(
            "nest-authz/sha256-digest@1",
            (
                ("algorithm", _encode_string(value.algorithm)),
                ("value", _encode_string(value.hex_value)),
            ),
        )
    if value_type is Principal:
        return _encode_record(
            "nest-authz/principal@1",
            (("identifier", _encode_string(value.identifier)),),
        )
    if value_type is SubjectPrincipalBinding:
        return _encode_record(
            "nest-authz/subject-principal-binding@1",
            (
                ("subject", _encode_domain(value.subject)),
                ("principal", _encode_domain(value.principal)),
            ),
        )
    if value_type is ApproverSubjectPrincipalBinding:
        return _encode_record(
            "nest-authz/approver-subject-principal-binding@1",
            (
                ("subject", _encode_domain(value.subject)),
                ("principal", _encode_domain(value.principal)),
            ),
        )
    if value_type is AuthorityScope:
        return _encode_record(
            "nest-authz/authority-scope@1",
            (
                ("action", _encode_domain(value.action)),
                ("resource", _encode_domain(value.resource)),
                (
                    "context_upper_bounds",
                    _encode_integer_map(value.context_upper_bounds),
                ),
            ),
        )
    if value_type is AuthorityGrant:
        return _encode_record(
            "nest-authz/authority-grant@1",
            (
                ("identifier", _encode_string(value.identifier)),
                ("grantor", _encode_domain(value.grantor)),
                ("grantee", _encode_domain(value.grantee)),
                ("scope", _encode_domain(value.scope)),
                ("parent_grant_id", _encode_scalar(value.parent_grant_id)),
                ("valid_from", _encode_integer(value.valid_from)),
                ("valid_until", _encode_integer(value.valid_until)),
            ),
        )
    if value_type is DelegationChain:
        return _encode_record(
            "nest-authz/delegation-chain@1",
            (("grants", _encode_sequence(value.grants)),),
        )
    if value_type is RevocationSet:
        return _encode_record(
            "nest-authz/revocation-set@1",
            (("grant_ids", _encode_string_sequence(value.grant_ids)),),
        )
    if value_type is AuthorizationState:
        return _encode_record(
            "nest-authz/authorization-state@1",
            (
                ("logical_time", _encode_integer(value.logical_time)),
                ("revocations", _encode_domain(value.revocations)),
            ),
        )
    if value_type is AuthorityValidationStatus:
        return _encode_record(
            "nest-authz/authority-validation-status@1",
            (("value", _encode_string(value.value)),),
        )
    if value_type is VerifiedAuthority:
        return _encode_record(
            "nest-authz/verified-authority@1",
            (
                ("grant_id", _encode_string(value.grant_id)),
                ("principal", _encode_domain(value.principal)),
                ("scope", _encode_domain(value.scope)),
                ("validated_at", _encode_integer(value.validated_at)),
                ("chain_digest", _encode_domain(value.chain_digest)),
                ("state_digest", _encode_domain(value.state_digest)),
            ),
        )
    if value_type is AuthorityValidationResult:
        return _encode_record(
            "nest-authz/authority-validation-result@1",
            (
                ("status", _encode_domain(value.status)),
                ("chain_digest", _encode_domain(value.chain_digest)),
                ("state_digest", _encode_domain(value.state_digest)),
                (
                    "offending_grant_id",
                    _encode_scalar(value.offending_grant_id),
                ),
                (
                    "verified_authority",
                    _encode_optional_domain(value.verified_authority),
                ),
            ),
        )
    if value_type is AuthorityApplicabilityStatus:
        return _encode_record(
            "nest-authz/authority-applicability-status@1",
            (("value", _encode_string(value.value)),),
        )
    if value_type is AuthorityBoundEvaluation:
        return _encode_record(
            "nest-authz/authority-bound-evaluation@1",
            (
                ("name", _encode_string(value.name)),
                ("upper_bound", _encode_integer(value.upper_bound)),
                ("present", _encode_boolean(value.present)),
                ("supplied_value", _encode_scalar(value.supplied_value)),
                ("status", _encode_domain(value.status)),
            ),
        )
    if value_type is AuthorityApplicabilityResult:
        return _encode_record(
            "nest-authz/authority-applicability-result@1",
            (
                ("status", _encode_domain(value.status)),
                ("request_digest", _encode_domain(value.request_digest)),
                ("authority_digest", _encode_domain(value.authority_digest)),
                ("chain_digest", _encode_domain(value.chain_digest)),
                ("state_digest", _encode_domain(value.state_digest)),
                (
                    "effective_grant_id",
                    _encode_string(value.effective_grant_id),
                ),
                ("expected_action", _encode_domain(value.expected_action)),
                ("request_action", _encode_domain(value.request_action)),
                ("action_matches", _encode_boolean(value.action_matches)),
                (
                    "expected_resource",
                    _encode_domain(value.expected_resource),
                ),
                ("request_resource", _encode_domain(value.request_resource)),
                ("resource_matches", _encode_boolean(value.resource_matches)),
                (
                    "bound_evaluations",
                    _encode_sequence(value.bound_evaluations),
                ),
            ),
        )
    if value_type is FieldNamespace:
        return _encode_record(
            "nest-authz/field-namespace@1",
            (("value", _encode_string(value.value)),),
        )
    if value_type is FieldReference:
        return _encode_record(
            "nest-authz/field-reference@1",
            (
                ("namespace", _encode_domain(value.namespace)),
                ("name", _encode_string(value.name)),
            ),
        )
    if value_type is ConditionOperator:
        return _encode_record(
            "nest-authz/condition-operator@1",
            (("value", _encode_string(value.value)),),
        )
    if value_type is Condition:
        return _encode_record(
            "nest-authz/condition@2",
            (
                ("identifier", _encode_string(value.identifier)),
                ("field", _encode_domain(value.field)),
                ("operator", _encode_domain(value.operator)),
                ("value", _encode_scalar(value.value)),
            ),
        )
    if value_type is RequestContext:
        return _encode_record(
            "nest-authz/request-context@1",
            (("attributes", _encode_scalar_map(value.attributes)),),
        )
    if value_type is AuthorityContext:
        return _encode_record(
            "nest-authz/authority-context@1",
            (
                ("identifier", _encode_string(value.identifier)),
                ("attributes", _encode_scalar_map(value.attributes)),
            ),
        )
    if value_type is AuthorizationRequest:
        return _encode_record(
            "nest-authz/authorization-request@2",
            (
                ("subject", _encode_domain(value.subject)),
                ("action", _encode_domain(value.action)),
                ("resource", _encode_domain(value.resource)),
                ("context", _encode_domain(value.context)),
                (
                    "authority_context",
                    _encode_optional_domain(value.authority_context),
                ),
            ),
        )
    if value_type is SubjectAuthorityBindingStatus:
        return _encode_record(
            "nest-authz/subject-authority-binding-status@1",
            (("value", _encode_string(value.value)),),
        )
    if value_type is SubjectAuthorityBindingResult:
        return _encode_record(
            "nest-authz/subject-authority-binding-result@1",
            (
                ("status", _encode_domain(value.status)),
                ("request_digest", _encode_domain(value.request_digest)),
                ("authority_digest", _encode_domain(value.authority_digest)),
                ("request_subject", _encode_domain(value.request_subject)),
                ("binding", _encode_domain(value.binding)),
                (
                    "authority_principal",
                    _encode_domain(value.authority_principal),
                ),
                (
                    "effective_grant_id",
                    _encode_string(value.effective_grant_id),
                ),
            ),
        )
    if value_type is Outcome:
        return _encode_record(
            "nest-authz/outcome@1",
            (("value", _encode_string(value.value)),),
        )
    if value_type is ConditionStatus:
        return _encode_record(
            "nest-authz/condition-status@1",
            (("value", _encode_string(value.value)),),
        )
    if value_type is Reason:
        return _encode_record(
            "nest-authz/reason@1",
            (
                ("code", _encode_string(value.code)),
                ("message", _encode_string(value.message)),
            ),
        )
    if value_type is Obligation:
        return _encode_record(
            "nest-authz/obligation@1",
            (
                ("code", _encode_string(value.code)),
                ("parameters", _encode_scalar_map(value.parameters)),
            ),
        )
    if value_type is ApprovalRequirement:
        return _encode_record(
            "nest-authz/approval-requirement@2",
            (
                ("code", _encode_string(value.code)),
                (
                    "allowed_principals",
                    _encode_sequence(value.allowed_principals),
                ),
                ("parameters", _encode_scalar_map(value.parameters)),
            ),
        )
    if value_type is ApproverAuthorizationStatus:
        return _encode_record(
            "nest-authz/approver-authorization-status@1",
            (("value", _encode_string(value.value)),),
        )
    if value_type is ApproverAuthorizationResult:
        return _encode_record(
            "nest-authz/approver-authorization-result@1",
            (
                ("status", _encode_domain(value.status)),
                ("actor", _encode_domain(value.actor)),
                ("binding", _encode_domain(value.binding)),
                (
                    "required_requirement",
                    _encode_domain(value.required_requirement),
                ),
                (
                    "attempted_requirement",
                    _encode_domain(value.attempted_requirement),
                ),
            ),
        )
    if value_type is ApprovalRequirementStatus:
        return _encode_record(
            "nest-authz/approval-requirement-status@1",
            (("value", _encode_string(value.value)),),
        )
    if value_type is ApprovalStatus:
        return _encode_record(
            "nest-authz/approval-status@1",
            (("value", _encode_string(value.value)),),
        )
    if value_type is ApprovalRequirementState:
        return _encode_record(
            "nest-authz/approval-requirement-state@2",
            (
                ("requirement", _encode_domain(value.requirement)),
                ("status", _encode_domain(value.status)),
                (
                    "authorization",
                    _encode_optional_domain(value.authorization),
                ),
                ("logical_time", _encode_integer(value.logical_time)),
            ),
        )
    if value_type is RuleEffect:
        return _encode_record(
            "nest-authz/rule-effect@1",
            (("value", _encode_string(value.value)),),
        )
    if value_type is RuleEvaluationStatus:
        return _encode_record(
            "nest-authz/rule-evaluation-status@1",
            (("value", _encode_string(value.value)),),
        )
    if value_type is Rule:
        return _encode_record(
            "nest-authz/rule@3",
            (
                ("identifier", _encode_string(value.identifier)),
                ("effect", _encode_domain(value.effect)),
                ("conditions", _encode_sequence(value.conditions)),
                ("obligations", _encode_sequence(value.obligations)),
                (
                    "approval_requirements",
                    _encode_sequence(value.approval_requirements),
                ),
            ),
        )
    if value_type is Policy:
        return _encode_record(
            "nest-authz/policy@3",
            (
                ("identifier", _encode_string(value.identifier)),
                ("rules", _encode_sequence(value.rules)),
            ),
        )
    if value_type is PolicyBundle:
        return _encode_record(
            "nest-authz/policy-bundle@3",
            (
                (
                    "combining_algorithm",
                    _encode_string(value.combining_algorithm),
                ),
                ("policies", _encode_sequence(value.policies)),
            ),
        )
    if value_type is RuleEvaluation:
        return _encode_record(
            "nest-authz/rule-evaluation@1",
            (
                ("policy_id", _encode_string(value.policy_id)),
                ("rule_id", _encode_string(value.rule_id)),
                ("effect", _encode_domain(value.effect)),
                ("status", _encode_domain(value.status)),
                (
                    "condition_results",
                    _encode_condition_status_map(value.condition_results),
                ),
            ),
        )
    if value_type is DecisionEvidence:
        return _encode_record(
            "nest-authz/decision-evidence@5",
            (
                (
                    "policy_bundle_digest",
                    _encode_domain(value.policy_bundle_digest),
                ),
                ("request_digest", _encode_domain(value.request_digest)),
                ("rule_evaluations", _encode_sequence(value.rule_evaluations)),
                (
                    "authority_applicability",
                    _encode_optional_domain(value.authority_applicability),
                ),
                (
                    "subject_authority_binding",
                    _encode_optional_domain(value.subject_authority_binding),
                ),
            ),
        )
    if value_type is Decision:
        return _encode_record(
            "nest-authz/decision@5",
            (
                ("outcome", _encode_domain(value.outcome)),
                ("reasons", _encode_sequence(value.reasons)),
                ("evidence", _encode_domain(value.evidence)),
                ("obligations", _encode_sequence(value.obligations)),
                (
                    "approval_requirements",
                    _encode_sequence(value.approval_requirements),
                ),
            ),
        )
    if value_type is DecisionReceipt:
        return _encode_record(
            "nest-authz/decision-receipt@2",
            (
                ("request_digest", _encode_domain(value.request_digest)),
                (
                    "policy_bundle_digest",
                    _encode_domain(value.policy_bundle_digest),
                ),
                (
                    "validated_authority_digest",
                    _encode_optional_domain(value.validated_authority_digest),
                ),
                (
                    "delegation_chain_digest",
                    _encode_optional_domain(value.delegation_chain_digest),
                ),
                (
                    "authorization_state_digest",
                    _encode_optional_domain(value.authorization_state_digest),
                ),
                (
                    "subject_principal_binding_evidence_digest",
                    _encode_optional_domain(
                        value.subject_principal_binding_evidence_digest
                    ),
                ),
                (
                    "authority_applicability_evidence_digest",
                    _encode_optional_domain(
                        value.authority_applicability_evidence_digest
                    ),
                ),
                ("decision_digest", _encode_domain(value.decision_digest)),
                ("outcome", _encode_domain(value.outcome)),
                (
                    "approval_requirements",
                    _encode_sequence(value.approval_requirements),
                ),
            ),
        )
    if value_type is PendingApproval:
        return _encode_record(
            "nest-authz/pending-approval@2",
            (
                ("receipt", _encode_domain(value.receipt)),
                ("receipt_digest", _encode_domain(value.receipt_digest)),
                (
                    "requirement_states",
                    _encode_sequence(value.requirement_states),
                ),
                ("logical_time", _encode_integer(value.logical_time)),
                ("consumed_at", _encode_scalar(value.consumed_at)),
                (
                    "execution_permit_digest",
                    _encode_optional_domain(value.execution_permit_digest),
                ),
                ("status", _encode_domain(value.status)),
            ),
        )
    if value_type is ExecutionAuthorizationStatus:
        return _encode_record(
            "nest-authz/execution-authorization-status@1",
            (("value", _encode_string(value.value)),),
        )
    if value_type is ExecutionPermit:
        return _encode_record(
            "nest-authz/execution-permit@1",
            (
                (
                    "original_receipt_digest",
                    _encode_domain(value.original_receipt_digest),
                ),
                (
                    "approved_state_digest",
                    _encode_domain(value.approved_state_digest),
                ),
                (
                    "current_request_digest",
                    _encode_domain(value.current_request_digest),
                ),
                (
                    "current_policy_bundle_digest",
                    _encode_domain(value.current_policy_bundle_digest),
                ),
                (
                    "current_delegation_chain_digest",
                    _encode_domain(value.current_delegation_chain_digest),
                ),
                (
                    "current_authorization_state_digest",
                    _encode_domain(value.current_authorization_state_digest),
                ),
                (
                    "current_validated_authority_digest",
                    _encode_domain(value.current_validated_authority_digest),
                ),
                (
                    "subject_authority_binding",
                    _encode_domain(value.subject_authority_binding),
                ),
                (
                    "authority_applicability",
                    _encode_domain(value.authority_applicability),
                ),
                ("decision", _encode_domain(value.decision)),
            ),
        )
    if value_type is ExecutionAuthorizationResult:
        return _encode_record(
            "nest-authz/execution-authorization-result@1",
            (
                ("status", _encode_domain(value.status)),
                (
                    "original_receipt_digest",
                    _encode_domain(value.original_receipt_digest),
                ),
                (
                    "approved_state_digest",
                    _encode_domain(value.approved_state_digest),
                ),
                (
                    "current_request_digest",
                    _encode_domain(value.current_request_digest),
                ),
                (
                    "current_policy_bundle_digest",
                    _encode_domain(value.current_policy_bundle_digest),
                ),
                (
                    "current_delegation_chain_digest",
                    _encode_domain(value.current_delegation_chain_digest),
                ),
                (
                    "current_authorization_state_digest",
                    _encode_domain(value.current_authorization_state_digest),
                ),
                (
                    "authority_validation",
                    _encode_domain(value.authority_validation),
                ),
                (
                    "subject_authority_binding",
                    _encode_optional_domain(value.subject_authority_binding),
                ),
                (
                    "authority_applicability",
                    _encode_optional_domain(value.authority_applicability),
                ),
                ("decision", _encode_domain(value.decision)),
                (
                    "execution_permit",
                    _encode_optional_domain(value.execution_permit),
                ),
            ),
        )

    raise TypeError("value is not a supported canonical domain type")
