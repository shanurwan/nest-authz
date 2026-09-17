"""Framework-free immutable authorization domain objects."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import TypeAlias, TypeVar

_Scalar: TypeAlias = str | int | bool | None
_Fields: TypeAlias = tuple[tuple[str, _Scalar], ...]
_ConditionResults: TypeAlias = tuple[tuple[str, bool], ...]
_TypedFields: TypeAlias = tuple[tuple[str, str, _Scalar], ...]


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
    result: list[tuple[str, bool]] = []
    seen: set[str] = set()

    for item in _pairs(value, "condition_results"):
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise TypeError("condition_results entries must be name/result pairs")
        name = _non_blank(item[0], "condition name")
        succeeded = item[1]
        if type(succeeded) is not bool:
            raise TypeError("condition results must be bool values")
        if name in seen:
            raise ValueError("condition_results contains a duplicate name")
        seen.add(name)
        result.append((name, succeeded))

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


@dataclass(frozen=True, slots=True)
class DecisionEvidence:
    """Machine-readable evidence supporting a decision."""

    policy_bundle_id: str
    matched_policy_id: str | None = None
    matched_authority: Authority | None = None
    condition_results: _ConditionResults = ()

    def __post_init__(self) -> None:
        _non_blank(self.policy_bundle_id, "policy bundle identifier")
        if self.matched_policy_id is not None:
            _non_blank(self.matched_policy_id, "matched policy identifier")
        if (
            self.matched_authority is not None
            and type(self.matched_authority) is not Authority
        ):
            raise TypeError("matched_authority must be an Authority or None")
        object.__setattr__(
            self,
            "condition_results",
            _canonical_condition_results(self.condition_results),
        )


@dataclass(frozen=True, slots=True)
class Decision:
    """An explainable, internally consistent authorization decision."""

    outcome: Outcome
    reasons: tuple[Reason, ...]
    evidence: DecisionEvidence
    obligations: tuple[Obligation, ...] = ()
    approval_requirement: ApprovalRequirement | None = None

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

        if (
            self.approval_requirement is not None
            and type(self.approval_requirement) is not ApprovalRequirement
        ):
            raise TypeError(
                "approval_requirement must be an ApprovalRequirement or None"
            )

        approval_is_required = self.outcome is Outcome.APPROVAL_REQUIRED
        has_approval_requirement = self.approval_requirement is not None
        if approval_is_required != has_approval_requirement:
            raise ValueError(
                "approval_requirement must be present exactly when approval is required"
            )

        if self.outcome is not Outcome.DENY:
            if self.evidence.matched_policy_id is None:
                raise ValueError("non-deny decisions require a matched policy")
            if self.evidence.matched_authority is None:
                raise ValueError("non-deny decisions require matched authority")
