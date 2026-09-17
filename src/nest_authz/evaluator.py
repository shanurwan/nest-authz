"""Pure deterministic evaluation for the closed version-1 policy model."""

from __future__ import annotations

from typing import TypeAlias

from .applicability import check_authority_applicability
from .binding import check_subject_authority_binding
from .canonical import sha256_digest
from .domain import (
    AuthorityApplicabilityStatus,
    AuthorizationRequest,
    Condition,
    ConditionOperator,
    ConditionStatus,
    Decision,
    DecisionEvidence,
    FieldNamespace,
    FieldReference,
    Obligation,
    Outcome,
    PolicyBundle,
    Reason,
    Rule,
    RuleEffect,
    RuleEvaluation,
    RuleEvaluationStatus,
    SubjectAuthorityBindingStatus,
    SubjectPrincipalBinding,
    VerifiedAuthority,
)


class EvaluationError(RuntimeError):
    """An impossible or unsupported internal evaluator state."""


_Scalar: TypeAlias = str | int | bool | None
_Resolution: TypeAlias = tuple[bool, _Scalar, ConditionStatus | None]


def _direct_attribute(
    attributes: tuple[tuple[str, _Scalar], ...],
    name: str,
) -> tuple[bool, _Scalar]:
    for attribute_name, value in attributes:
        if attribute_name == name:
            return True, value
    return False, None


def _resolve_field(
    request: AuthorizationRequest,
    reference: FieldReference,
) -> _Resolution:
    namespace = reference.namespace

    if namespace is FieldNamespace.SUBJECT:
        if reference.name != "identifier":
            return False, None, ConditionStatus.ERROR
        return True, request.subject.identifier, None

    if namespace is FieldNamespace.ACTION:
        if reference.name != "name":
            return False, None, ConditionStatus.ERROR
        return True, request.action.name, None

    if namespace is FieldNamespace.RESOURCE:
        if reference.name != "identifier":
            return False, None, ConditionStatus.ERROR
        return True, request.resource.identifier, None

    if namespace is FieldNamespace.CONTEXT:
        present, value = _direct_attribute(
            request.context.attributes,
            reference.name,
        )
        return present, value, None

    if namespace is FieldNamespace.AUTHORITY:
        if request.authority_context is None:
            return False, None, ConditionStatus.MISSING_INPUT
        if reference.name == "identifier":
            return True, request.authority_context.identifier, None
        present, value = _direct_attribute(
            request.authority_context.attributes,
            reference.name,
        )
        return present, value, None

    raise EvaluationError("unsupported field namespace")


def _evaluate_condition(
    request: AuthorizationRequest,
    condition: Condition,
) -> ConditionStatus:
    present, actual, resolution_status = _resolve_field(
        request,
        condition.field,
    )
    if resolution_status is not None:
        return resolution_status

    operator = condition.operator
    if operator is ConditionOperator.EXISTS:
        return (
            ConditionStatus.SATISFIED
            if present
            else ConditionStatus.UNSATISFIED
        )

    if not present:
        return ConditionStatus.MISSING_INPUT

    if operator in (ConditionOperator.EQUALS, ConditionOperator.NOT_EQUALS):
        if type(actual) is not type(condition.value):
            return ConditionStatus.ERROR
        equal = actual == condition.value
        if operator is ConditionOperator.EQUALS:
            return (
                ConditionStatus.SATISFIED
                if equal
                else ConditionStatus.UNSATISFIED
            )
        return (
            ConditionStatus.SATISFIED
            if not equal
            else ConditionStatus.UNSATISFIED
        )

    if type(actual) is not int:
        return ConditionStatus.ERROR

    expected = condition.value
    if type(expected) is not int:
        raise EvaluationError("integer operator has a non-integer operand")

    if operator is ConditionOperator.INTEGER_LESS_THAN:
        result = actual < expected
    elif operator is ConditionOperator.INTEGER_LESS_THAN_OR_EQUAL:
        result = actual <= expected
    elif operator is ConditionOperator.INTEGER_GREATER_THAN:
        result = actual > expected
    elif operator is ConditionOperator.INTEGER_GREATER_THAN_OR_EQUAL:
        result = actual >= expected
    else:
        raise EvaluationError("unsupported condition operator")

    return (
        ConditionStatus.SATISFIED
        if result
        else ConditionStatus.UNSATISFIED
    )


def _rule_status(
    condition_results: tuple[tuple[str, ConditionStatus], ...],
) -> RuleEvaluationStatus:
    statuses = tuple(status for _, status in condition_results)
    if ConditionStatus.UNSATISFIED in statuses:
        return RuleEvaluationStatus.NOT_MATCHED
    if (
        ConditionStatus.MISSING_INPUT in statuses
        or ConditionStatus.ERROR in statuses
    ):
        return RuleEvaluationStatus.INDETERMINATE
    if all(status is ConditionStatus.SATISFIED for status in statuses):
        return RuleEvaluationStatus.MATCHED
    raise EvaluationError("unsupported condition status during rule aggregation")


def _evaluate_rule(
    request: AuthorizationRequest,
    policy_id: str,
    rule: Rule,
) -> RuleEvaluation:
    condition_results = tuple(
        (condition.identifier, _evaluate_condition(request, condition))
        for condition in rule.conditions
    )
    return RuleEvaluation(
        policy_id=policy_id,
        rule_id=rule.identifier,
        effect=rule.effect,
        status=_rule_status(condition_results),
        condition_results=condition_results,
    )


def _extend_unique(
    target: list[Obligation],
    values: tuple[Obligation, ...],
) -> None:
    for value in values:
        if value not in target:
            target.append(value)


def evaluate(
    request: AuthorizationRequest,
    bundle: PolicyBundle,
    authority: VerifiedAuthority | None,
    binding: SubjectPrincipalBinding | None,
) -> Decision:
    """Gate one request by holder-bound authority, then evaluate policy."""

    if type(request) is not AuthorizationRequest:
        raise TypeError("request must be an AuthorizationRequest")
    if type(bundle) is not PolicyBundle:
        raise TypeError("bundle must be a PolicyBundle")
    if authority is not None and type(authority) is not VerifiedAuthority:
        raise TypeError("authority must be a VerifiedAuthority or None")
    if binding is not None and type(binding) is not SubjectPrincipalBinding:
        raise TypeError("binding must be a SubjectPrincipalBinding or None")

    applicability = (
        check_authority_applicability(request, authority)
        if authority is not None
        else None
    )
    holder_binding = (
        check_subject_authority_binding(request, binding, authority)
        if authority is not None and binding is not None
        else None
    )

    rule_evaluations: list[RuleEvaluation] = []
    matched_rules: list[Rule] = []

    for policy in bundle.policies:
        for rule in policy.rules:
            evaluation = _evaluate_rule(request, policy.identifier, rule)
            rule_evaluations.append(evaluation)
            if evaluation.status is RuleEvaluationStatus.MATCHED:
                matched_rules.append(rule)

    evidence = DecisionEvidence(
        policy_bundle_digest=sha256_digest(bundle),
        request_digest=sha256_digest(request),
        rule_evaluations=rule_evaluations,
        authority_applicability=applicability,
        subject_authority_binding=holder_binding,
    )

    has_indeterminate = any(
        evaluation.status is RuleEvaluationStatus.INDETERMINATE
        for evaluation in rule_evaluations
    )
    has_deny = any(rule.effect is RuleEffect.DENY for rule in matched_rules)
    approval_rules = tuple(
        rule
        for rule in matched_rules
        if rule.effect is RuleEffect.APPROVAL_REQUIRED
    )
    permit_rules = tuple(
        rule for rule in matched_rules if rule.effect is RuleEffect.PERMIT
    )

    if applicability is None:
        return Decision(
            Outcome.DENY,
            (Reason("VALIDATED_AUTHORITY_REQUIRED"),),
            evidence,
        )
    if holder_binding is None:
        return Decision(
            Outcome.DENY,
            (Reason("SUBJECT_PRINCIPAL_BINDING_REQUIRED"),),
            evidence,
        )
    if holder_binding.status is not SubjectAuthorityBindingStatus.BOUND:
        return Decision(
            Outcome.DENY,
            (Reason(f"HOLDER_{holder_binding.status.value}"),),
            evidence,
        )
    if applicability.status is not AuthorityApplicabilityStatus.APPLICABLE:
        return Decision(
            Outcome.DENY,
            (Reason(f"AUTHORITY_{applicability.status.value}"),),
            evidence,
        )
    if has_indeterminate:
        return Decision(
            Outcome.DENY,
            (Reason("INDETERMINATE_RULE"),),
            evidence,
        )
    if has_deny:
        return Decision(
            Outcome.DENY,
            (Reason("DENY_RULE_MATCHED"),),
            evidence,
        )
    obligations: list[Obligation] = []
    if approval_rules:
        for rule in matched_rules:
            if rule.effect in (
                RuleEffect.PERMIT,
                RuleEffect.APPROVAL_REQUIRED,
            ):
                _extend_unique(obligations, rule.obligations)

        approval_requirements = []
        for rule in approval_rules:
            for requirement in rule.approval_requirements:
                if requirement not in approval_requirements:
                    approval_requirements.append(requirement)

        return Decision(
            Outcome.APPROVAL_REQUIRED,
            (Reason("APPROVAL_REQUIRED"),),
            evidence,
            obligations,
            approval_requirements,
        )

    if permit_rules:
        for rule in permit_rules:
            _extend_unique(obligations, rule.obligations)
        return Decision(
            Outcome.PERMIT,
            (Reason("PERMIT_RULE_MATCHED"),),
            evidence,
            obligations,
        )

    return Decision(
        Outcome.DENY,
        (Reason("NO_MATCHING_RULE"),),
        evidence,
    )
