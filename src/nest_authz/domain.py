"""Framework-free immutable authorization domain objects."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import TypeAlias, TypeVar


class ConditionStatus(str, Enum):
    """The auditable result of considering one policy condition."""

    SATISFIED = "SATISFIED"
    UNSATISFIED = "UNSATISFIED"
    NOT_EVALUATED = "NOT_EVALUATED"
    MISSING_INPUT = "MISSING_INPUT"
    ERROR = "ERROR"


class FieldNamespace(Enum):
    """A closed source namespace for direct policy field references."""

    SUBJECT = "SUBJECT"
    ACTION = "ACTION"
    RESOURCE = "RESOURCE"
    CONTEXT = "CONTEXT"
    AUTHORITY = "AUTHORITY"


class ConditionOperator(Enum):
    """The supported declarative condition operators."""

    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    EXISTS = "EXISTS"
    INTEGER_LESS_THAN = "INTEGER_LESS_THAN"
    INTEGER_LESS_THAN_OR_EQUAL = "INTEGER_LESS_THAN_OR_EQUAL"
    INTEGER_GREATER_THAN = "INTEGER_GREATER_THAN"
    INTEGER_GREATER_THAN_OR_EQUAL = "INTEGER_GREATER_THAN_OR_EQUAL"


class RuleEffect(Enum):
    """The effect contributed by a matching policy rule."""

    PERMIT = "PERMIT"
    DENY = "DENY"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


class RuleEvaluationStatus(Enum):
    """The aggregate result of evaluating every condition in one rule."""

    MATCHED = "MATCHED"
    NOT_MATCHED = "NOT_MATCHED"
    INDETERMINATE = "INDETERMINATE"


_Scalar: TypeAlias = str | int | bool | None
_Fields: TypeAlias = tuple[tuple[str, _Scalar], ...]
_ConditionResults: TypeAlias = tuple[tuple[str, ConditionStatus], ...]
_TypedFields: TypeAlias = tuple[tuple[str, str, _Scalar], ...]
_TypedScalar: TypeAlias = tuple[str, _Scalar]
_RuleIdentifier: TypeAlias = tuple[str, str]
_QualifiedConditionResult: TypeAlias = tuple[
    str,
    str,
    str,
    ConditionStatus,
]


def _valid_string(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be a string")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field_name} must be encodable as strict UTF-8") from error
    return value


def _non_blank(value: object, field_name: str) -> str:
    value = _valid_string(value, field_name)
    if not value.strip():
        raise ValueError(f"{field_name} must not be blank")
    return value


def _pairs(value: object, field_name: str) -> tuple[object, ...]:
    if isinstance(value, Mapping):
        return tuple(value.items())
    if isinstance(value, (str, bytes)):
        raise TypeError(f"{field_name} must be a mapping or iterable of pairs")
    if not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be a mapping or iterable of pairs")
    return tuple(value)


def _canonical_fields(value: object, field_name: str) -> _Fields:
    result: list[tuple[str, _Scalar]] = []
    seen: set[str] = set()

    for item in _pairs(value, field_name):
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise TypeError(f"{field_name} entries must be key/value pairs")
        key = _non_blank(item[0], f"{field_name} key")
        scalar = item[1]
        if scalar is not None and type(scalar) not in (str, int, bool):
            raise TypeError(
                f"{field_name} values must be str, int, bool, or None"
            )
        if type(scalar) is str:
            _valid_string(scalar, f"{field_name} value")
        if key in seen:
            raise ValueError(f"{field_name} contains a duplicate key")
        seen.add(key)
        result.append((key, scalar))

    return tuple(sorted(result, key=lambda pair: pair[0]))


def _typed_fields(fields: _Fields) -> _TypedFields:
    type_names = {
        str: "string",
        int: "integer",
        bool: "boolean",
        type(None): "null",
    }
    return tuple(
        (key, type_names[type(value)], value)
        for key, value in fields
    )


def _canonical_condition_results(value: object) -> _ConditionResults:
    result: list[tuple[str, ConditionStatus]] = []
    seen: set[str] = set()

    for item in _pairs(value, "condition_results"):
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise TypeError("condition_results entries must be name/result pairs")
        name = _non_blank(item[0], "condition name")
        status = item[1]
        if type(status) is not ConditionStatus:
            raise TypeError("condition results must be ConditionStatus values")
        if name in seen:
            raise ValueError("condition_results contains a duplicate name")
        seen.add(name)
        result.append((name, status))

    return tuple(sorted(result, key=lambda pair: pair[0]))


_T = TypeVar("_T")


def _typed_tuple(value: object, expected_type: type[_T], field_name: str) -> tuple[_T, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be an iterable")
    result = tuple(value)
    if not all(type(item) is expected_type for item in result):
        raise TypeError(
            f"every {field_name} entry must be {expected_type.__name__}"
        )
    return result


@dataclass(frozen=True, slots=True)
class Subject:
    """The principal asking to perform an action."""

    identifier: str

    def __post_init__(self) -> None:
        _non_blank(self.identifier, "subject identifier")


@dataclass(frozen=True, slots=True)
class Action:
    """A named operation requested by a subject."""

    name: str

    def __post_init__(self) -> None:
        _non_blank(self.name, "action name")


@dataclass(frozen=True, slots=True)
class Resource:
    """The object against which an action is requested."""

    identifier: str

    def __post_init__(self) -> None:
        _non_blank(self.identifier, "resource identifier")


@dataclass(frozen=True, slots=True)
class Sha256Digest:
    """A validated SHA-256 content digest."""

    value: bytes
    algorithm: str = field(init=False, default="sha256")

    def __post_init__(self) -> None:
        if type(self.value) is not bytes:
            raise TypeError("SHA-256 digest value must be bytes")
        if len(self.value) != 32:
            raise ValueError("SHA-256 digest value must contain exactly 32 bytes")

    @classmethod
    def from_hex(cls, value: str) -> Sha256Digest:
        """Construct a digest from exactly 64 lowercase hexadecimal characters."""

        if type(value) is not str:
            raise TypeError("SHA-256 hexadecimal value must be a string")
        if len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise ValueError(
                "SHA-256 hexadecimal value must contain exactly "
                "64 lowercase hexadecimal characters"
            )
        return cls(bytes.fromhex(value))

    @property
    def hex_value(self) -> str:
        """Return exactly 64 lowercase hexadecimal characters."""

        return self.value.hex()

    def __str__(self) -> str:
        return f"{self.algorithm}:{self.hex_value}"


@dataclass(frozen=True, slots=True)
class FieldReference:
    """A direct, typed reference to one authorization-input field."""

    namespace: FieldNamespace
    name: str

    def __post_init__(self) -> None:
        if type(self.namespace) is not FieldNamespace:
            raise TypeError("namespace must be a FieldNamespace")
        _non_blank(self.name, "field reference name")


@dataclass(frozen=True, slots=True)
class Condition:
    """A declarative comparison of one direct field with a literal value."""

    identifier: str
    field: FieldReference
    operator: ConditionOperator
    value: _Scalar = field(default=None, compare=False, hash=False)
    _typed_value: _TypedScalar = field(init=False, repr=False)

    def __post_init__(self) -> None:
        _non_blank(self.identifier, "condition identifier")
        if type(self.field) is not FieldReference:
            raise TypeError("field must be a FieldReference")
        if type(self.operator) is not ConditionOperator:
            raise TypeError("operator must be a ConditionOperator")

        if self.operator is ConditionOperator.EXISTS:
            if self.value is not None:
                raise ValueError("EXISTS must not have a value")
        else:
            if self.value is None:
                raise ValueError(f"{self.operator.value} requires a value")
            if type(self.value) not in (str, int, bool):
                raise TypeError("condition values must be str, int, or bool")
            if type(self.value) is str:
                _valid_string(self.value, "condition value")

        integer_operators = (
            ConditionOperator.INTEGER_LESS_THAN,
            ConditionOperator.INTEGER_LESS_THAN_OR_EQUAL,
            ConditionOperator.INTEGER_GREATER_THAN,
            ConditionOperator.INTEGER_GREATER_THAN_OR_EQUAL,
        )
        if self.operator in integer_operators and type(self.value) is not int:
            raise TypeError("integer comparison operators require an int value")

        type_names = {
            str: "string",
            int: "integer",
            bool: "boolean",
            type(None): "none",
        }
        object.__setattr__(
            self,
            "_typed_value",
            (type_names[type(self.value)], self.value),
        )


def _condition_structure(condition: Condition) -> tuple[object, ...]:
    return (
        condition.field.namespace.value,
        condition.field.name,
        condition.operator.value,
        condition._typed_value,
    )


def _canonical_conditions(value: object) -> tuple[Condition, ...]:
    conditions = _typed_tuple(value, Condition, "conditions")
    if not conditions:
        raise ValueError("a rule must contain at least one condition")

    identifiers: set[str] = set()
    structures: list[tuple[object, ...]] = []
    for condition in conditions:
        if condition.identifier in identifiers:
            raise ValueError("conditions must not contain duplicate identifiers")
        structure = _condition_structure(condition)
        if structure in structures:
            raise ValueError("conditions must not contain duplicate predicates")
        identifiers.add(condition.identifier)
        structures.append(structure)

    return tuple(
        sorted(
            conditions,
            key=lambda condition: condition.identifier.encode("utf-8"),
        )
    )


def _canonical_identified_records(
    value: object,
    expected_type: type[_T],
    field_name: str,
) -> tuple[_T, ...]:
    records = _typed_tuple(value, expected_type, field_name)
    seen: set[str] = set()

    for record in records:
        identifier = record.identifier
        if identifier in seen:
            raise ValueError(f"{field_name} must not contain duplicate identifiers")
        seen.add(identifier)

    return tuple(
        sorted(records, key=lambda record: record.identifier.encode("utf-8"))
    )


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Deterministic, explicitly supplied facts about a request."""

    attributes: _Fields = field(default=(), compare=False, hash=False)
    _typed_attributes: _TypedFields = field(init=False, repr=False)

    def __post_init__(self) -> None:
        attributes = _canonical_fields(self.attributes, "context attributes")
        object.__setattr__(
            self,
            "attributes",
            attributes,
        )
        object.__setattr__(self, "_typed_attributes", _typed_fields(attributes))


@dataclass(frozen=True, slots=True)
class Authority:
    """An explicit authority presented for consideration."""

    identifier: str
    attributes: _Fields = field(default=(), compare=False, hash=False)
    _typed_attributes: _TypedFields = field(init=False, repr=False)

    def __post_init__(self) -> None:
        _non_blank(self.identifier, "authority identifier")
        attributes = _canonical_fields(self.attributes, "authority attributes")
        object.__setattr__(
            self,
            "attributes",
            attributes,
        )
        object.__setattr__(self, "_typed_attributes", _typed_fields(attributes))


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """All domain input describing one authorization question."""

    subject: Subject
    action: Action
    resource: Resource
    context: RequestContext
    authority: Authority | None

    def __post_init__(self) -> None:
        if type(self.subject) is not Subject:
            raise TypeError("subject must be a Subject")
        if type(self.action) is not Action:
            raise TypeError("action must be an Action")
        if type(self.resource) is not Resource:
            raise TypeError("resource must be a Resource")
        if type(self.context) is not RequestContext:
            raise TypeError("context must be a RequestContext")
        if self.authority is not None and type(self.authority) is not Authority:
            raise TypeError("authority must be an Authority or None")


class Outcome(str, Enum):
    """The exhaustive terminal outcomes of authorization evaluation."""

    PERMIT = "PERMIT"
    DENY = "DENY"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"


@dataclass(frozen=True, slots=True)
class Reason:
    """A machine-readable decision reason with optional human detail."""

    code: str
    message: str = ""

    def __post_init__(self) -> None:
        _non_blank(self.code, "reason code")
        _valid_string(self.message, "reason message")


@dataclass(frozen=True, slots=True)
class Obligation:
    """A requirement imposed on the enforcement point."""

    code: str
    parameters: _Fields = field(default=(), compare=False, hash=False)
    _typed_parameters: _TypedFields = field(init=False, repr=False)

    def __post_init__(self) -> None:
        _non_blank(self.code, "obligation code")
        parameters = _canonical_fields(self.parameters, "obligation parameters")
        object.__setattr__(
            self,
            "parameters",
            parameters,
        )
        object.__setattr__(self, "_typed_parameters", _typed_fields(parameters))


@dataclass(frozen=True, slots=True)
class ApprovalRequirement:
    """A named human-approval condition that remains to be satisfied."""

    code: str
    parameters: _Fields = field(default=(), compare=False, hash=False)
    _typed_parameters: _TypedFields = field(init=False, repr=False)

    def __post_init__(self) -> None:
        _non_blank(self.code, "approval requirement code")
        parameters = _canonical_fields(
            self.parameters,
            "approval requirement parameters",
        )
        object.__setattr__(
            self,
            "parameters",
            parameters,
        )
        object.__setattr__(self, "_typed_parameters", _typed_fields(parameters))


def _approval_requirement_sort_key(
    requirement: ApprovalRequirement,
) -> tuple[object, ...]:
    return (
        requirement.code.encode("utf-8"),
        requirement._typed_parameters,
    )


def _canonical_approval_requirements(
    value: object,
) -> tuple[ApprovalRequirement, ...]:
    requirements = _typed_tuple(
        value,
        ApprovalRequirement,
        "approval_requirements",
    )
    unique: list[ApprovalRequirement] = []
    for requirement in requirements:
        if requirement in unique:
            raise ValueError("approval_requirements must not contain duplicates")
        unique.append(requirement)
    return tuple(sorted(unique, key=_approval_requirement_sort_key))


@dataclass(frozen=True, slots=True)
class Rule:
    """An immutable conditional contribution to policy combination."""

    identifier: str
    effect: RuleEffect
    conditions: tuple[Condition, ...]
    obligations: tuple[Obligation, ...] = ()
    approval_requirements: tuple[ApprovalRequirement, ...] = ()

    def __post_init__(self) -> None:
        _non_blank(self.identifier, "rule identifier")
        if type(self.effect) is not RuleEffect:
            raise TypeError("effect must be a RuleEffect")
        object.__setattr__(
            self,
            "conditions",
            _canonical_conditions(self.conditions),
        )
        object.__setattr__(
            self,
            "obligations",
            _typed_tuple(self.obligations, Obligation, "obligations"),
        )
        requirements = _canonical_approval_requirements(
            self.approval_requirements
        )
        object.__setattr__(self, "approval_requirements", requirements)

        approval_is_required = self.effect is RuleEffect.APPROVAL_REQUIRED
        has_approval_requirements = bool(requirements)
        if approval_is_required != has_approval_requirements:
            raise ValueError(
                "approval_requirements must be present exactly for "
                "APPROVAL_REQUIRED rules"
            )


@dataclass(frozen=True, slots=True)
class Policy:
    """An identified, order-independent collection of rules."""

    identifier: str
    rules: tuple[Rule, ...] = ()

    def __post_init__(self) -> None:
        _non_blank(self.identifier, "policy identifier")
        rules = _canonical_identified_records(self.rules, Rule, "rules")
        if not rules:
            raise ValueError("a policy must contain at least one rule")
        object.__setattr__(
            self,
            "rules",
            rules,
        )


@dataclass(frozen=True, slots=True)
class PolicyBundle:
    """A canonically ordered collection of policies using deny-overrides."""

    policies: tuple[Policy, ...] = ()
    combining_algorithm: str = field(init=False, default="DENY_OVERRIDES")

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "policies",
            _canonical_identified_records(self.policies, Policy, "policies"),
        )


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    """Complete condition evidence and aggregate status for one policy rule."""

    policy_id: str
    rule_id: str
    effect: RuleEffect
    status: RuleEvaluationStatus
    condition_results: _ConditionResults

    def __post_init__(self) -> None:
        _non_blank(self.policy_id, "policy identifier")
        _non_blank(self.rule_id, "rule identifier")
        if type(self.effect) is not RuleEffect:
            raise TypeError("effect must be a RuleEffect")
        if type(self.status) is not RuleEvaluationStatus:
            raise TypeError("status must be a RuleEvaluationStatus")

        condition_results = _canonical_condition_results(self.condition_results)
        if not condition_results:
            raise ValueError("a rule evaluation must contain condition results")
        if any(
            result is ConditionStatus.NOT_EVALUATED
            for _, result in condition_results
        ):
            raise ValueError(
                "NOT_EVALUATED is not valid in a version-1 rule evaluation"
            )

        results = tuple(result for _, result in condition_results)
        if ConditionStatus.UNSATISFIED in results:
            expected_status = RuleEvaluationStatus.NOT_MATCHED
        elif (
            ConditionStatus.MISSING_INPUT in results
            or ConditionStatus.ERROR in results
        ):
            expected_status = RuleEvaluationStatus.INDETERMINATE
        else:
            expected_status = RuleEvaluationStatus.MATCHED

        if self.status is not expected_status:
            raise ValueError(
                "rule evaluation status does not match its condition results"
            )
        object.__setattr__(self, "condition_results", condition_results)


def _canonical_rule_evaluations(
    value: object,
) -> tuple[RuleEvaluation, ...]:
    evaluations = _typed_tuple(value, RuleEvaluation, "rule_evaluations")
    identifiers: set[_RuleIdentifier] = set()
    for evaluation in evaluations:
        identifier = (evaluation.policy_id, evaluation.rule_id)
        if identifier in identifiers:
            raise ValueError(
                "rule_evaluations must not contain duplicate rule identifiers"
            )
        identifiers.add(identifier)
    return tuple(
        sorted(
            evaluations,
            key=lambda evaluation: (
                evaluation.policy_id.encode("utf-8"),
                evaluation.rule_id.encode("utf-8"),
            ),
        )
    )


@dataclass(frozen=True, slots=True)
class DecisionEvidence:
    """Machine-readable evidence supporting a decision."""

    policy_bundle_digest: Sha256Digest
    rule_evaluations: tuple[RuleEvaluation, ...] = ()
    request_authority: Authority | None = None

    def __post_init__(self) -> None:
        if type(self.policy_bundle_digest) is not Sha256Digest:
            raise TypeError("policy_bundle_digest must be a Sha256Digest")
        if (
            self.request_authority is not None
            and type(self.request_authority) is not Authority
        ):
            raise TypeError("request_authority must be an Authority or None")
        object.__setattr__(
            self,
            "rule_evaluations",
            _canonical_rule_evaluations(self.rule_evaluations),
        )

    @property
    def matched_policy_ids(self) -> tuple[str, ...]:
        """Return identifiers of policies containing matching rules."""

        identifiers: list[str] = []
        for evaluation in self.rule_evaluations:
            if (
                evaluation.status is RuleEvaluationStatus.MATCHED
                and evaluation.policy_id not in identifiers
            ):
                identifiers.append(evaluation.policy_id)
        return tuple(identifiers)

    @property
    def matched_rule_ids(self) -> tuple[_RuleIdentifier, ...]:
        """Return policy-scoped identifiers of matching rules."""

        return tuple(
            (evaluation.policy_id, evaluation.rule_id)
            for evaluation in self.rule_evaluations
            if evaluation.status is RuleEvaluationStatus.MATCHED
        )

    @property
    def condition_results(self) -> tuple[_QualifiedConditionResult, ...]:
        """Return all condition results qualified by policy and rule."""

        return tuple(
            (
                evaluation.policy_id,
                evaluation.rule_id,
                condition_id,
                status,
            )
            for evaluation in self.rule_evaluations
            for condition_id, status in evaluation.condition_results
        )

    @property
    def indeterminate_rule_ids(self) -> tuple[_RuleIdentifier, ...]:
        """Return policy-scoped identifiers of indeterminate rules."""

        return tuple(
            (evaluation.policy_id, evaluation.rule_id)
            for evaluation in self.rule_evaluations
            if evaluation.status is RuleEvaluationStatus.INDETERMINATE
        )

    @property
    def indeterminate_condition_results(
        self,
    ) -> tuple[_QualifiedConditionResult, ...]:
        """Return missing/error conditions in indeterminate rules."""

        indeterminate_statuses = (
            ConditionStatus.MISSING_INPUT,
            ConditionStatus.ERROR,
        )
        return tuple(
            (
                evaluation.policy_id,
                evaluation.rule_id,
                condition_id,
                status,
            )
            for evaluation in self.rule_evaluations
            if evaluation.status is RuleEvaluationStatus.INDETERMINATE
            for condition_id, status in evaluation.condition_results
            if status in indeterminate_statuses
        )


@dataclass(frozen=True, slots=True)
class Decision:
    """An explainable, internally consistent authorization decision."""

    outcome: Outcome
    reasons: tuple[Reason, ...]
    evidence: DecisionEvidence
    obligations: tuple[Obligation, ...] = ()
    approval_requirements: tuple[ApprovalRequirement, ...] = ()

    def __post_init__(self) -> None:
        if type(self.outcome) is not Outcome:
            raise TypeError("outcome must be an Outcome")

        reasons = _typed_tuple(self.reasons, Reason, "reasons")
        if not reasons:
            raise ValueError("a decision must contain at least one reason")
        object.__setattr__(self, "reasons", reasons)

        if type(self.evidence) is not DecisionEvidence:
            raise TypeError("evidence must be DecisionEvidence")

        object.__setattr__(
            self,
            "obligations",
            _typed_tuple(self.obligations, Obligation, "obligations"),
        )
        requirements = _canonical_approval_requirements(
            self.approval_requirements
        )
        object.__setattr__(self, "approval_requirements", requirements)

        approval_is_required = self.outcome is Outcome.APPROVAL_REQUIRED
        has_approval_requirements = bool(requirements)
        if approval_is_required != has_approval_requirements:
            raise ValueError(
                "approval_requirements must be present exactly when approval is required"
            )

        if self.outcome is not Outcome.DENY:
            if not self.evidence.matched_rule_ids:
                raise ValueError("non-deny decisions require a matched rule")
            if self.evidence.request_authority is None:
                raise ValueError("non-deny decisions require request authority")
