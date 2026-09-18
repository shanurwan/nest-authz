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


class AuthorityValidationStatus(Enum):
    """The deterministic result of validating delegated authority."""

    VALID = "VALID"
    REVOKED = "REVOKED"
    NOT_YET_VALID = "NOT_YET_VALID"
    EXPIRED = "EXPIRED"
    BROADENED_AUTHORITY = "BROADENED_AUTHORITY"
    BROKEN_PROVENANCE = "BROKEN_PROVENANCE"
    CYCLE = "CYCLE"
    INVALID_CHAIN = "INVALID_CHAIN"


class AuthorityApplicabilityStatus(Enum):
    """The result of binding validated authority to one exact request."""

    APPLICABLE = "APPLICABLE"
    ACTION_MISMATCH = "ACTION_MISMATCH"
    RESOURCE_MISMATCH = "RESOURCE_MISMATCH"
    MISSING_CONTEXT = "MISSING_CONTEXT"
    BOUND_EXCEEDED = "BOUND_EXCEEDED"
    TYPE_ERROR = "TYPE_ERROR"


class SubjectAuthorityBindingStatus(Enum):
    """The result of binding a request Subject to an authority holder."""

    BOUND = "BOUND"
    SUBJECT_MISMATCH = "SUBJECT_MISMATCH"
    PRINCIPAL_MISMATCH = "PRINCIPAL_MISMATCH"


class ApprovalRequirementStatus(Enum):
    """The state of one independently tracked approval requirement."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ApprovalStatus(Enum):
    """The derived aggregate state of an approval lifecycle."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


class ApproverAuthorizationStatus(Enum):
    """The result of authorizing one actor for one approval requirement."""

    AUTHORIZED = "AUTHORIZED"
    SUBJECT_MISMATCH = "SUBJECT_MISMATCH"
    PRINCIPAL_NOT_ALLOWED = "PRINCIPAL_NOT_ALLOWED"
    REQUIREMENT_MISMATCH = "REQUIREMENT_MISMATCH"


class ExecutionAuthorizationStatus(Enum):
    """The result of fresh execution-time authorization revalidation."""

    AUTHORIZED = "AUTHORIZED"
    APPROVAL_NOT_APPROVED = "APPROVAL_NOT_APPROVED"
    RECEIPT_MISMATCH = "RECEIPT_MISMATCH"
    REQUEST_MISMATCH = "REQUEST_MISMATCH"
    DELEGATION_CHAIN_MISMATCH = "DELEGATION_CHAIN_MISMATCH"
    AUTHORITY_INVALID = "AUTHORITY_INVALID"
    HOLDER_BINDING_FAILED = "HOLDER_BINDING_FAILED"
    AUTHORITY_NOT_APPLICABLE = "AUTHORITY_NOT_APPLICABLE"
    POLICY_DENIED = "POLICY_DENIED"
    POLICY_REAUTHORIZATION_REQUIRED = "POLICY_REAUTHORIZATION_REQUIRED"
    APPROVAL_REQUIREMENTS_CHANGED = "APPROVAL_REQUIREMENTS_CHANGED"
    POLICY_BUNDLE_MISMATCH = "POLICY_BUNDLE_MISMATCH"


class SignatureScheme(Enum):
    """The closed set of supported artifact-signature schemes."""

    ED25519 = "ED25519"


class ArtifactPurpose(Enum):
    """An exact trust purpose for an artifact-signing key."""

    POLICY_BUNDLE = "POLICY_BUNDLE"
    AUTHORITY_GRANT = "AUTHORITY_GRANT"
    DECISION_RECEIPT = "DECISION_RECEIPT"
    EXECUTION_PERMIT = "EXECUTION_PERMIT"


class ArtifactKind(Enum):
    """The closed canonical artifact type named by an attestation."""

    POLICY_BUNDLE = "POLICY_BUNDLE"
    AUTHORITY_GRANT = "AUTHORITY_GRANT"
    DECISION_RECEIPT = "DECISION_RECEIPT"
    EXECUTION_PERMIT = "EXECUTION_PERMIT"


class ArtifactVerificationStatus(Enum):
    """The deterministic result of detached artifact verification."""

    VERIFIED = "VERIFIED"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    UNKNOWN_KEY = "UNKNOWN_KEY"
    KEY_NOT_TRUSTED_FOR_PURPOSE = "KEY_NOT_TRUSTED_FOR_PURPOSE"
    ARTIFACT_KIND_MISMATCH = "ARTIFACT_KIND_MISMATCH"
    PURPOSE_MISMATCH = "PURPOSE_MISMATCH"
    SCHEME_UNSUPPORTED = "SCHEME_UNSUPPORTED"


class DelegationAuthenticationStatus(Enum):
    """The result of authenticating complete delegation provenance."""

    AUTHENTICATED = "AUTHENTICATED"
    MISSING_ATTESTATION = "MISSING_ATTESTATION"
    ATTESTATION_INVALID = "ATTESTATION_INVALID"
    SIGNER_KEY_NOT_BOUND_TO_GRANTOR = (
        "SIGNER_KEY_NOT_BOUND_TO_GRANTOR"
    )
    UNTRUSTED_ROOT_PRINCIPAL = "UNTRUSTED_ROOT_PRINCIPAL"
    UNKNOWN_SIGNING_KEY = "UNKNOWN_SIGNING_KEY"
    KEY_NOT_TRUSTED_FOR_AUTHORITY_GRANT = (
        "KEY_NOT_TRUSTED_FOR_AUTHORITY_GRANT"
    )
    GRANT_ARTIFACT_MISMATCH = "GRANT_ARTIFACT_MISMATCH"
    STRUCTURAL_AUTHORITY_INVALID = "STRUCTURAL_AUTHORITY_INVALID"
    UNKNOWN_GRANT_ATTESTATION = "UNKNOWN_GRANT_ATTESTATION"


class TrustedExecutionAuthorizationStatus(Enum):
    """The result of trusted execution-time orchestration."""

    AUTHORIZED = "AUTHORIZED"
    DELEGATION_AUTHENTICATION_FAILED = (
        "DELEGATION_AUTHENTICATION_FAILED"
    )
    EXECUTION_REVALIDATION_FAILED = "EXECUTION_REVALIDATION_FAILED"


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
_IntegerBounds: TypeAlias = tuple[tuple[str, int], ...]


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


def _canonical_integer_bounds(
    value: object,
    field_name: str,
) -> _IntegerBounds:
    result: list[tuple[str, int]] = []
    seen: set[str] = set()

    for item in _pairs(value, field_name):
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise TypeError(f"{field_name} entries must be name/bound pairs")
        name = _non_blank(item[0], f"{field_name} name")
        bound = item[1]
        if type(bound) is not int:
            raise TypeError(f"{field_name} values must be exact integers")
        if name in seen:
            raise ValueError(f"{field_name} contains a duplicate name")
        seen.add(name)
        result.append((name, bound))

    return tuple(
        sorted(result, key=lambda pair: pair[0].encode("utf-8"))
    )


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


def _fixed_bytes(value: object, length: int, field_name: str) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{field_name} must be bytes")
    if len(value) != length:
        raise ValueError(
            f"{field_name} must contain exactly {length} bytes"
        )
    return value


@dataclass(frozen=True, slots=True)
class SigningKeyId:
    """A stable semantic identifier for one signing key."""

    identifier: str

    def __post_init__(self) -> None:
        _non_blank(self.identifier, "signing key identifier")


@dataclass(frozen=True, slots=True)
class Ed25519PublicKey:
    """Exactly one raw 32-byte Ed25519 public key."""

    value: bytes

    def __post_init__(self) -> None:
        _fixed_bytes(self.value, 32, "Ed25519 public key")

    @property
    def hex_value(self) -> str:
        """Return exactly 64 lowercase hexadecimal characters."""

        return self.value.hex()


@dataclass(frozen=True, slots=True)
class ArtifactSignature:
    """Exactly one raw 64-byte Ed25519 artifact signature."""

    value: bytes

    def __post_init__(self) -> None:
        _fixed_bytes(self.value, 64, "Ed25519 signature")

    @property
    def hex_value(self) -> str:
        """Return exactly 128 lowercase hexadecimal characters."""

        return self.value.hex()


def _canonical_artifact_purposes(
    value: object,
) -> tuple[ArtifactPurpose, ...]:
    purposes = _typed_tuple(
        value,
        ArtifactPurpose,
        "allowed_purposes",
    )
    if not purposes:
        raise ValueError("trusted keys must allow at least one purpose")
    if len(set(purposes)) != len(purposes):
        raise ValueError("allowed_purposes must not contain duplicates")
    return tuple(
        sorted(purposes, key=lambda purpose: purpose.value.encode("utf-8"))
    )


@dataclass(frozen=True, slots=True)
class TrustedKey:
    """One public key trusted for an explicit immutable purpose set."""

    key_id: SigningKeyId
    public_key: Ed25519PublicKey
    allowed_purposes: tuple[ArtifactPurpose, ...]

    def __post_init__(self) -> None:
        if type(self.key_id) is not SigningKeyId:
            raise TypeError("key_id must be a SigningKeyId")
        if type(self.public_key) is not Ed25519PublicKey:
            raise TypeError("public_key must be an Ed25519PublicKey")
        object.__setattr__(
            self,
            "allowed_purposes",
            _canonical_artifact_purposes(self.allowed_purposes),
        )


@dataclass(frozen=True, slots=True)
class TrustStore:
    """An explicitly supplied immutable set of trusted public keys."""

    trusted_keys: tuple[TrustedKey, ...] = ()

    def __post_init__(self) -> None:
        keys = _typed_tuple(self.trusted_keys, TrustedKey, "trusted_keys")
        identifiers: set[str] = set()
        for trusted_key in keys:
            identifier = trusted_key.key_id.identifier
            if identifier in identifiers:
                raise ValueError(
                    "trusted_keys must not contain duplicate key identifiers"
                )
            identifiers.add(identifier)
        object.__setattr__(
            self,
            "trusted_keys",
            tuple(
                sorted(
                    keys,
                    key=lambda trusted_key: (
                        trusted_key.key_id.identifier.encode("utf-8")
                    ),
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class ArtifactAttestation:
    """A detached signature over one domain-separated artifact identity."""

    scheme: SignatureScheme
    key_id: SigningKeyId
    purpose: ArtifactPurpose
    artifact_kind: ArtifactKind
    artifact_digest: Sha256Digest
    signature: ArtifactSignature

    def __post_init__(self) -> None:
        if type(self.scheme) is not SignatureScheme:
            raise TypeError("scheme must be a SignatureScheme")
        if type(self.key_id) is not SigningKeyId:
            raise TypeError("key_id must be a SigningKeyId")
        if type(self.purpose) is not ArtifactPurpose:
            raise TypeError("purpose must be an ArtifactPurpose")
        if type(self.artifact_kind) is not ArtifactKind:
            raise TypeError("artifact_kind must be an ArtifactKind")
        if type(self.artifact_digest) is not Sha256Digest:
            raise TypeError("artifact_digest must be a Sha256Digest")
        if type(self.signature) is not ArtifactSignature:
            raise TypeError("signature must be an ArtifactSignature")


_ARTIFACT_VERIFICATION_RESULT_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class ArtifactVerificationResult:
    """Typed evidence from detached artifact-signature verification."""

    status: ArtifactVerificationStatus
    artifact_digest: Sha256Digest
    attestation: ArtifactAttestation
    expected_purpose: ArtifactPurpose
    expected_artifact_kind: ArtifactKind

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError(
            "ArtifactVerificationResult can only be created by verification"
        )

    @classmethod
    def _from_verification(
        cls,
        *,
        status: ArtifactVerificationStatus,
        artifact_digest: Sha256Digest,
        attestation: ArtifactAttestation,
        expected_purpose: ArtifactPurpose,
        expected_artifact_kind: ArtifactKind,
        _token: object,
    ) -> ArtifactVerificationResult:
        if _token is not _ARTIFACT_VERIFICATION_RESULT_TOKEN:
            raise TypeError(
                "ArtifactVerificationResult requires completed verification"
            )
        if type(status) is not ArtifactVerificationStatus:
            raise TypeError("status must be an ArtifactVerificationStatus")
        if type(artifact_digest) is not Sha256Digest:
            raise TypeError("artifact_digest must be a Sha256Digest")
        if type(attestation) is not ArtifactAttestation:
            raise TypeError("attestation must be an ArtifactAttestation")
        if type(expected_purpose) is not ArtifactPurpose:
            raise TypeError("expected_purpose must be an ArtifactPurpose")
        if type(expected_artifact_kind) is not ArtifactKind:
            raise TypeError(
                "expected_artifact_kind must be an ArtifactKind"
            )

        if status is ArtifactVerificationStatus.VERIFIED:
            if artifact_digest != attestation.artifact_digest:
                raise ValueError("VERIFIED evidence requires the exact digest")
            if expected_purpose is not attestation.purpose:
                raise ValueError("VERIFIED evidence requires the exact purpose")
            if expected_artifact_kind is not attestation.artifact_kind:
                raise ValueError("VERIFIED evidence requires the exact kind")
            if attestation.scheme is not SignatureScheme.ED25519:
                raise ValueError("VERIFIED evidence requires Ed25519")
        elif status is ArtifactVerificationStatus.DIGEST_MISMATCH:
            if artifact_digest == attestation.artifact_digest:
                raise ValueError("DIGEST_MISMATCH requires different digests")
        elif status is ArtifactVerificationStatus.PURPOSE_MISMATCH:
            if expected_purpose is attestation.purpose:
                raise ValueError("PURPOSE_MISMATCH requires different purposes")
        elif status is ArtifactVerificationStatus.ARTIFACT_KIND_MISMATCH:
            if expected_artifact_kind is attestation.artifact_kind:
                raise ValueError(
                    "ARTIFACT_KIND_MISMATCH requires different kinds"
                )

        result = object.__new__(cls)
        object.__setattr__(result, "status", status)
        object.__setattr__(result, "artifact_digest", artifact_digest)
        object.__setattr__(result, "attestation", attestation)
        object.__setattr__(result, "expected_purpose", expected_purpose)
        object.__setattr__(
            result,
            "expected_artifact_kind",
            expected_artifact_kind,
        )
        return result


@dataclass(frozen=True, slots=True)
class Principal:
    """A semantic grantor or grantee identifier, without authentication."""

    identifier: str

    def __post_init__(self) -> None:
        _non_blank(self.identifier, "principal identifier")


@dataclass(frozen=True, slots=True)
class PrincipalKeyBinding:
    """One explicit configured Principal-to-signing-key association."""

    principal: Principal
    key_id: SigningKeyId

    def __post_init__(self) -> None:
        if type(self.principal) is not Principal:
            raise TypeError("binding principal must be a Principal")
        if type(self.key_id) is not SigningKeyId:
            raise TypeError("binding key_id must be a SigningKeyId")


@dataclass(frozen=True, slots=True)
class PrincipalKeyRegistry:
    """An explicit immutable one-to-one Principal/signing-key registry."""

    bindings: tuple[PrincipalKeyBinding, ...] = ()

    def __post_init__(self) -> None:
        bindings = _typed_tuple(
            self.bindings,
            PrincipalKeyBinding,
            "principal-key bindings",
        )
        principals: set[str] = set()
        key_ids: set[str] = set()
        for binding in bindings:
            principal_id = binding.principal.identifier
            key_id = binding.key_id.identifier
            if principal_id in principals:
                raise ValueError(
                    "principal-key registry contains a duplicate or "
                    "conflicting Principal binding"
                )
            if key_id in key_ids:
                raise ValueError(
                    "principal-key registry contains a duplicate or "
                    "conflicting signing-key binding"
                )
            principals.add(principal_id)
            key_ids.add(key_id)
        object.__setattr__(
            self,
            "bindings",
            tuple(
                sorted(
                    bindings,
                    key=lambda binding: (
                        binding.principal.identifier.encode("utf-8")
                    ),
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class TrustedAuthorityRoots:
    """Exact Principals permitted to originate root authority grants."""

    principals: tuple[Principal, ...] = ()

    def __post_init__(self) -> None:
        principals = _typed_tuple(
            self.principals,
            Principal,
            "trusted authority roots",
        )
        identifiers: set[str] = set()
        for principal in principals:
            if principal.identifier in identifiers:
                raise ValueError(
                    "trusted authority roots must not contain duplicates"
                )
            identifiers.add(principal.identifier)
        object.__setattr__(
            self,
            "principals",
            tuple(
                sorted(
                    principals,
                    key=lambda principal: principal.identifier.encode(
                        "utf-8"
                    ),
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class SubjectPrincipalBinding:
    """An externally supplied assertion relating a Subject to a Principal."""

    subject: Subject
    principal: Principal

    def __post_init__(self) -> None:
        if type(self.subject) is not Subject:
            raise TypeError("binding subject must be a Subject")
        if type(self.principal) is not Principal:
            raise TypeError("binding principal must be a Principal")


@dataclass(frozen=True, slots=True)
class ApproverSubjectPrincipalBinding:
    """A trusted-input assertion relating an approver Subject to a Principal."""

    subject: Subject
    principal: Principal

    def __post_init__(self) -> None:
        if type(self.subject) is not Subject:
            raise TypeError("approver binding subject must be a Subject")
        if type(self.principal) is not Principal:
            raise TypeError("approver binding principal must be a Principal")


@dataclass(frozen=True, slots=True)
class AuthorityScope:
    """A closed, mechanically attenuable delegated-authority scope."""

    action: Action
    resource: Resource
    context_upper_bounds: _IntegerBounds = ()

    def __post_init__(self) -> None:
        if type(self.action) is not Action:
            raise TypeError("scope action must be an Action")
        if type(self.resource) is not Resource:
            raise TypeError("scope resource must be a Resource")
        object.__setattr__(
            self,
            "context_upper_bounds",
            _canonical_integer_bounds(
                self.context_upper_bounds,
                "context_upper_bounds",
            ),
        )


@dataclass(frozen=True, slots=True)
class AuthorityGrant:
    """One explicit root or delegated grant in a provenance chain."""

    identifier: str
    grantor: Principal
    grantee: Principal
    scope: AuthorityScope
    parent_grant_id: str | None
    valid_from: int
    valid_until: int

    def __post_init__(self) -> None:
        _non_blank(self.identifier, "grant identifier")
        if type(self.grantor) is not Principal:
            raise TypeError("grantor must be a Principal")
        if type(self.grantee) is not Principal:
            raise TypeError("grantee must be a Principal")
        if type(self.scope) is not AuthorityScope:
            raise TypeError("scope must be an AuthorityScope")
        if self.parent_grant_id is not None:
            _non_blank(self.parent_grant_id, "parent grant identifier")
        if type(self.valid_from) is not int:
            raise TypeError("valid_from must be an exact integer")
        if type(self.valid_until) is not int:
            raise TypeError("valid_until must be an exact integer")
        if self.valid_from >= self.valid_until:
            raise ValueError("valid_from must be less than valid_until")


@dataclass(frozen=True, slots=True)
class DelegationChain:
    """A nonempty immutable sequence of grants ordered root to leaf."""

    grants: tuple[AuthorityGrant, ...]

    def __post_init__(self) -> None:
        grants = _typed_tuple(self.grants, AuthorityGrant, "grants")
        if not grants:
            raise ValueError("a delegation chain must contain at least one grant")
        object.__setattr__(self, "grants", grants)


@dataclass(frozen=True, slots=True)
class GrantAttestation:
    """One detached attestation associated with one semantic grant ID."""

    grant_id: str
    attestation: ArtifactAttestation

    def __post_init__(self) -> None:
        _non_blank(self.grant_id, "attested grant identifier")
        if type(self.attestation) is not ArtifactAttestation:
            raise TypeError("attestation must be an ArtifactAttestation")


@dataclass(frozen=True, slots=True)
class GrantAttestationSet:
    """An immutable exact grant-ID to detached-attestation collection."""

    entries: tuple[GrantAttestation, ...] = ()

    def __post_init__(self) -> None:
        entries = _typed_tuple(
            self.entries,
            GrantAttestation,
            "grant attestations",
        )
        grant_ids: set[str] = set()
        for entry in entries:
            if entry.grant_id in grant_ids:
                raise ValueError(
                    "grant attestations must not contain duplicate grant IDs"
                )
            grant_ids.add(entry.grant_id)
        object.__setattr__(
            self,
            "entries",
            tuple(
                sorted(
                    entries,
                    key=lambda entry: entry.grant_id.encode("utf-8"),
                )
            ),
        )


def _canonical_identifiers(value: object, field_name: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError(f"{field_name} must be an iterable")
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        identifier = _non_blank(item, f"{field_name} identifier")
        if identifier in seen:
            raise ValueError(f"{field_name} must not contain duplicates")
        seen.add(identifier)
        result.append(identifier)
    return tuple(sorted(result, key=lambda item: item.encode("utf-8")))


@dataclass(frozen=True, slots=True)
class RevocationSet:
    """Explicit immutable grant revocations supplied to validation."""

    grant_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "grant_ids",
            _canonical_identifiers(self.grant_ids, "revoked grant identifiers"),
        )


@dataclass(frozen=True, slots=True)
class AuthorizationState:
    """All deterministic external state consumed by authority validation."""

    logical_time: int
    revocations: RevocationSet = field(default_factory=RevocationSet)

    def __post_init__(self) -> None:
        if type(self.logical_time) is not int:
            raise TypeError("logical_time must be an exact integer")
        if type(self.revocations) is not RevocationSet:
            raise TypeError("revocations must be a RevocationSet")


_VERIFIED_AUTHORITY_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class VerifiedAuthority:
    """Authority established only by successful deterministic validation."""

    grant_id: str
    principal: Principal
    scope: AuthorityScope
    validated_at: int
    chain_digest: Sha256Digest
    state_digest: Sha256Digest

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("VerifiedAuthority can only be created by validation")

    @classmethod
    def _from_validation(
        cls,
        *,
        grant_id: str,
        principal: Principal,
        scope: AuthorityScope,
        validated_at: int,
        chain_digest: Sha256Digest,
        state_digest: Sha256Digest,
        _token: object,
    ) -> VerifiedAuthority:
        if _token is not _VERIFIED_AUTHORITY_TOKEN:
            raise TypeError("VerifiedAuthority requires successful validation")
        _non_blank(grant_id, "verified grant identifier")
        if type(principal) is not Principal:
            raise TypeError("verified principal must be a Principal")
        if type(scope) is not AuthorityScope:
            raise TypeError("verified scope must be an AuthorityScope")
        if type(validated_at) is not int:
            raise TypeError("validated_at must be an exact integer")
        if type(chain_digest) is not Sha256Digest:
            raise TypeError("chain_digest must be a Sha256Digest")
        if type(state_digest) is not Sha256Digest:
            raise TypeError("state_digest must be a Sha256Digest")

        result = object.__new__(cls)
        object.__setattr__(result, "grant_id", grant_id)
        object.__setattr__(result, "principal", principal)
        object.__setattr__(result, "scope", scope)
        object.__setattr__(result, "validated_at", validated_at)
        object.__setattr__(result, "chain_digest", chain_digest)
        object.__setattr__(result, "state_digest", state_digest)
        return result


@dataclass(frozen=True, slots=True)
class AuthorityValidationResult:
    """Typed authority-validation outcome with deterministic evidence."""

    status: AuthorityValidationStatus
    chain_digest: Sha256Digest
    state_digest: Sha256Digest
    offending_grant_id: str | None = None
    verified_authority: VerifiedAuthority | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not AuthorityValidationStatus:
            raise TypeError("status must be an AuthorityValidationStatus")
        if type(self.chain_digest) is not Sha256Digest:
            raise TypeError("chain_digest must be a Sha256Digest")
        if type(self.state_digest) is not Sha256Digest:
            raise TypeError("state_digest must be a Sha256Digest")
        if self.offending_grant_id is not None:
            _non_blank(self.offending_grant_id, "offending grant identifier")
        if (
            self.verified_authority is not None
            and type(self.verified_authority) is not VerifiedAuthority
        ):
            raise TypeError("verified_authority must be a VerifiedAuthority or None")

        if self.status is AuthorityValidationStatus.VALID:
            if self.offending_grant_id is not None:
                raise ValueError("VALID results must not identify an offending grant")
            if self.verified_authority is None:
                raise ValueError("VALID results require verified authority")
            if self.verified_authority.chain_digest != self.chain_digest:
                raise ValueError("verified authority chain digest must match result")
            if self.verified_authority.state_digest != self.state_digest:
                raise ValueError("verified authority state digest must match result")
        else:
            if self.offending_grant_id is None:
                raise ValueError("invalid authority results require an offending grant")
            if self.verified_authority is not None:
                raise ValueError("invalid authority results cannot carry verified authority")


def _delegation_status_for_verification(
    status: ArtifactVerificationStatus,
) -> DelegationAuthenticationStatus | None:
    if status is ArtifactVerificationStatus.VERIFIED:
        return None
    if status is ArtifactVerificationStatus.UNKNOWN_KEY:
        return DelegationAuthenticationStatus.UNKNOWN_SIGNING_KEY
    if status is ArtifactVerificationStatus.KEY_NOT_TRUSTED_FOR_PURPOSE:
        return (
            DelegationAuthenticationStatus
            .KEY_NOT_TRUSTED_FOR_AUTHORITY_GRANT
        )
    if status in (
        ArtifactVerificationStatus.DIGEST_MISMATCH,
        ArtifactVerificationStatus.ARTIFACT_KIND_MISMATCH,
    ):
        return DelegationAuthenticationStatus.GRANT_ARTIFACT_MISMATCH
    if status in (
        ArtifactVerificationStatus.SIGNATURE_INVALID,
        ArtifactVerificationStatus.PURPOSE_MISMATCH,
        ArtifactVerificationStatus.SCHEME_UNSUPPORTED,
    ):
        return DelegationAuthenticationStatus.ATTESTATION_INVALID
    raise ValueError("unsupported artifact verification status")


@dataclass(frozen=True, slots=True)
class GrantAuthenticationEvidence:
    """Deterministic cryptographic-provenance evidence for one grant."""

    grant_id: str
    grantor: Principal
    is_root: bool
    root_principal_trusted: bool | None
    signing_key_id: SigningKeyId | None
    bound_principal: Principal | None
    verification: ArtifactVerificationResult | None
    status: DelegationAuthenticationStatus

    def __post_init__(self) -> None:
        _non_blank(self.grant_id, "authenticated grant identifier")
        if type(self.grantor) is not Principal:
            raise TypeError("grantor must be a Principal")
        if type(self.is_root) is not bool:
            raise TypeError("is_root must be a boolean")
        if self.root_principal_trusted is not None and type(
            self.root_principal_trusted
        ) is not bool:
            raise TypeError(
                "root_principal_trusted must be a boolean or None"
            )
        if self.is_root != (self.root_principal_trusted is not None):
            raise ValueError(
                "root trust evidence must be present exactly for root grants"
            )
        if (
            self.signing_key_id is not None
            and type(self.signing_key_id) is not SigningKeyId
        ):
            raise TypeError("signing_key_id must be a SigningKeyId or None")
        if (
            self.bound_principal is not None
            and type(self.bound_principal) is not Principal
        ):
            raise TypeError("bound_principal must be a Principal or None")
        if (
            self.verification is not None
            and type(self.verification) is not ArtifactVerificationResult
        ):
            raise TypeError(
                "verification must be an ArtifactVerificationResult or None"
            )
        if type(self.status) is not DelegationAuthenticationStatus:
            raise TypeError(
                "status must be a DelegationAuthenticationStatus"
            )
        if self.status in (
            DelegationAuthenticationStatus.STRUCTURAL_AUTHORITY_INVALID,
            DelegationAuthenticationStatus.UNKNOWN_GRANT_ATTESTATION,
        ):
            raise ValueError(
                "aggregate-only status is invalid for per-grant evidence"
            )

        if self.status is DelegationAuthenticationStatus.MISSING_ATTESTATION:
            if any(
                value is not None
                for value in (
                    self.signing_key_id,
                    self.bound_principal,
                    self.verification,
                )
            ):
                raise ValueError(
                    "missing-attestation evidence cannot contain signer data"
                )
            return

        if self.signing_key_id is None or self.verification is None:
            raise ValueError(
                "attested grant evidence requires signer and verification"
            )
        if self.signing_key_id != self.verification.attestation.key_id:
            raise ValueError(
                "signing key must equal the verification attestation key"
            )

        verification_failure = _delegation_status_for_verification(
            self.verification.status
        )
        if verification_failure is not None:
            if self.status is not verification_failure:
                raise ValueError(
                    "grant status does not match artifact verification"
                )
            return

        if self.bound_principal != self.grantor:
            expected = (
                DelegationAuthenticationStatus
                .SIGNER_KEY_NOT_BOUND_TO_GRANTOR
            )
        elif self.is_root and not self.root_principal_trusted:
            expected = DelegationAuthenticationStatus.UNTRUSTED_ROOT_PRINCIPAL
        else:
            expected = DelegationAuthenticationStatus.AUTHENTICATED
        if self.status is not expected:
            raise ValueError(
                "grant authentication status does not match its evidence"
            )


_AUTHENTICATED_DELEGATED_AUTHORITY_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class AuthenticatedDelegatedAuthority:
    """Delegated authority with structural and cryptographic provenance."""

    verified_authority: VerifiedAuthority
    authority_validation_digest: Sha256Digest
    grant_attestations_digest: Sha256Digest
    trust_store_digest: Sha256Digest
    principal_key_registry_digest: Sha256Digest
    trusted_authority_roots_digest: Sha256Digest
    grant_evidence: tuple[GrantAuthenticationEvidence, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError(
            "AuthenticatedDelegatedAuthority can only be created by "
            "delegation authentication"
        )

    @classmethod
    def _from_authentication(
        cls,
        *,
        verified_authority: VerifiedAuthority,
        authority_validation_digest: Sha256Digest,
        grant_attestations_digest: Sha256Digest,
        trust_store_digest: Sha256Digest,
        principal_key_registry_digest: Sha256Digest,
        trusted_authority_roots_digest: Sha256Digest,
        grant_evidence: object,
        _token: object,
    ) -> AuthenticatedDelegatedAuthority:
        if _token is not _AUTHENTICATED_DELEGATED_AUTHORITY_TOKEN:
            raise TypeError(
                "AuthenticatedDelegatedAuthority requires successful "
                "delegation authentication"
            )
        if type(verified_authority) is not VerifiedAuthority:
            raise TypeError(
                "verified_authority must be a VerifiedAuthority"
            )
        for field_name, digest in (
            ("authority_validation_digest", authority_validation_digest),
            ("grant_attestations_digest", grant_attestations_digest),
            ("trust_store_digest", trust_store_digest),
            (
                "principal_key_registry_digest",
                principal_key_registry_digest,
            ),
            (
                "trusted_authority_roots_digest",
                trusted_authority_roots_digest,
            ),
        ):
            if type(digest) is not Sha256Digest:
                raise TypeError(f"{field_name} must be a Sha256Digest")
        evidence = _typed_tuple(
            grant_evidence,
            GrantAuthenticationEvidence,
            "grant_evidence",
        )
        if not evidence or any(
            item.status is not DelegationAuthenticationStatus.AUTHENTICATED
            for item in evidence
        ):
            raise ValueError(
                "authenticated authority requires authenticated evidence "
                "for every grant"
            )

        result = object.__new__(cls)
        object.__setattr__(result, "verified_authority", verified_authority)
        object.__setattr__(
            result,
            "authority_validation_digest",
            authority_validation_digest,
        )
        object.__setattr__(
            result,
            "grant_attestations_digest",
            grant_attestations_digest,
        )
        object.__setattr__(result, "trust_store_digest", trust_store_digest)
        object.__setattr__(
            result,
            "principal_key_registry_digest",
            principal_key_registry_digest,
        )
        object.__setattr__(
            result,
            "trusted_authority_roots_digest",
            trusted_authority_roots_digest,
        )
        object.__setattr__(result, "grant_evidence", evidence)
        return result


_DELEGATION_AUTHENTICATION_RESULT_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class DelegationAuthenticationResult:
    """Typed result of structural and cryptographic chain validation."""

    status: DelegationAuthenticationStatus
    authority_validation: AuthorityValidationResult
    grant_attestations_digest: Sha256Digest
    trust_store_digest: Sha256Digest
    principal_key_registry_digest: Sha256Digest
    trusted_authority_roots_digest: Sha256Digest
    grant_evidence: tuple[GrantAuthenticationEvidence, ...]
    offending_grant_id: str | None
    authenticated_authority: AuthenticatedDelegatedAuthority | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError(
            "DelegationAuthenticationResult can only be created by "
            "delegation authentication"
        )

    @classmethod
    def _from_authentication(
        cls,
        *,
        status: DelegationAuthenticationStatus,
        authority_validation: AuthorityValidationResult,
        grant_attestations_digest: Sha256Digest,
        trust_store_digest: Sha256Digest,
        principal_key_registry_digest: Sha256Digest,
        trusted_authority_roots_digest: Sha256Digest,
        grant_evidence: object,
        offending_grant_id: str | None,
        authenticated_authority: AuthenticatedDelegatedAuthority | None,
        _token: object,
    ) -> DelegationAuthenticationResult:
        if _token is not _DELEGATION_AUTHENTICATION_RESULT_TOKEN:
            raise TypeError(
                "DelegationAuthenticationResult requires delegation "
                "authentication"
            )
        if type(status) is not DelegationAuthenticationStatus:
            raise TypeError(
                "status must be a DelegationAuthenticationStatus"
            )
        if type(authority_validation) is not AuthorityValidationResult:
            raise TypeError(
                "authority_validation must be an AuthorityValidationResult"
            )
        for field_name, digest in (
            ("grant_attestations_digest", grant_attestations_digest),
            ("trust_store_digest", trust_store_digest),
            (
                "principal_key_registry_digest",
                principal_key_registry_digest,
            ),
            (
                "trusted_authority_roots_digest",
                trusted_authority_roots_digest,
            ),
        ):
            if type(digest) is not Sha256Digest:
                raise TypeError(f"{field_name} must be a Sha256Digest")
        evidence = _typed_tuple(
            grant_evidence,
            GrantAuthenticationEvidence,
            "grant_evidence",
        )
        if offending_grant_id is not None:
            _non_blank(offending_grant_id, "offending grant identifier")
        if (
            authenticated_authority is not None
            and type(authenticated_authority)
            is not AuthenticatedDelegatedAuthority
        ):
            raise TypeError(
                "authenticated_authority must be an "
                "AuthenticatedDelegatedAuthority or None"
            )

        authenticated = (
            status is DelegationAuthenticationStatus.AUTHENTICATED
        )
        if authenticated != (authenticated_authority is not None):
            raise ValueError(
                "authenticated authority must be present exactly for "
                "AUTHENTICATED"
            )
        if authenticated:
            if authority_validation.status is not AuthorityValidationStatus.VALID:
                raise ValueError(
                    "authenticated delegation requires VALID authority"
                )
            if offending_grant_id is not None:
                raise ValueError(
                    "authenticated delegation cannot name an offending grant"
                )
            if not evidence or any(
                item.status
                is not DelegationAuthenticationStatus.AUTHENTICATED
                for item in evidence
            ):
                raise ValueError(
                    "authenticated result requires authenticated grant evidence"
                )
            if (
                authenticated_authority.verified_authority
                != authority_validation.verified_authority
            ):
                raise ValueError(
                    "authenticated authority must preserve validation authority"
                )
            for authority_digest, result_digest in (
                (
                    authenticated_authority.grant_attestations_digest,
                    grant_attestations_digest,
                ),
                (
                    authenticated_authority.trust_store_digest,
                    trust_store_digest,
                ),
                (
                    authenticated_authority.principal_key_registry_digest,
                    principal_key_registry_digest,
                ),
                (
                    authenticated_authority.trusted_authority_roots_digest,
                    trusted_authority_roots_digest,
                ),
            ):
                if authority_digest != result_digest:
                    raise ValueError(
                        "authenticated authority trust-input digests must "
                        "match the result"
                    )
            if authenticated_authority.grant_evidence != evidence:
                raise ValueError(
                    "authenticated authority must preserve grant evidence"
                )
        else:
            if offending_grant_id is None:
                raise ValueError(
                    "failed delegation authentication requires an offending "
                    "grant"
                )
            if (
                status
                is DelegationAuthenticationStatus.STRUCTURAL_AUTHORITY_INVALID
                and authority_validation.status
                is AuthorityValidationStatus.VALID
            ):
                raise ValueError(
                    "structural failure requires invalid authority validation"
                )
            if (
                status
                is not DelegationAuthenticationStatus
                .STRUCTURAL_AUTHORITY_INVALID
                and authority_validation.status
                is not AuthorityValidationStatus.VALID
            ):
                raise ValueError(
                    "cryptographic failure requires structurally valid authority"
                )

        result = object.__new__(cls)
        for field_name, value in (
            ("status", status),
            ("authority_validation", authority_validation),
            ("grant_attestations_digest", grant_attestations_digest),
            ("trust_store_digest", trust_store_digest),
            (
                "principal_key_registry_digest",
                principal_key_registry_digest,
            ),
            (
                "trusted_authority_roots_digest",
                trusted_authority_roots_digest,
            ),
            ("grant_evidence", evidence),
            ("offending_grant_id", offending_grant_id),
            ("authenticated_authority", authenticated_authority),
        ):
            object.__setattr__(result, field_name, value)
        return result


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
class AuthorityContext:
    """Policy-visible authority-related context, not delegated authority."""

    identifier: str
    attributes: _Fields = field(default=(), compare=False, hash=False)
    _typed_attributes: _TypedFields = field(init=False, repr=False)

    def __post_init__(self) -> None:
        _non_blank(self.identifier, "authority-context identifier")
        attributes = _canonical_fields(
            self.attributes,
            "authority-context attributes",
        )
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
    authority_context: AuthorityContext | None

    def __post_init__(self) -> None:
        if type(self.subject) is not Subject:
            raise TypeError("subject must be a Subject")
        if type(self.action) is not Action:
            raise TypeError("action must be an Action")
        if type(self.resource) is not Resource:
            raise TypeError("resource must be a Resource")
        if type(self.context) is not RequestContext:
            raise TypeError("context must be a RequestContext")
        if (
            self.authority_context is not None
            and type(self.authority_context) is not AuthorityContext
        ):
            raise TypeError(
                "authority_context must be an AuthorityContext or None"
            )


@dataclass(frozen=True, slots=True)
class SubjectAuthorityBindingResult:
    """Deterministic evidence relating one request to an authority holder."""

    status: SubjectAuthorityBindingStatus
    request_digest: Sha256Digest
    authority_digest: Sha256Digest
    request_subject: Subject
    binding: SubjectPrincipalBinding
    authority_principal: Principal
    effective_grant_id: str

    def __post_init__(self) -> None:
        if type(self.status) is not SubjectAuthorityBindingStatus:
            raise TypeError(
                "status must be a SubjectAuthorityBindingStatus"
            )
        if type(self.request_digest) is not Sha256Digest:
            raise TypeError("request_digest must be a Sha256Digest")
        if type(self.authority_digest) is not Sha256Digest:
            raise TypeError("authority_digest must be a Sha256Digest")
        if type(self.request_subject) is not Subject:
            raise TypeError("request_subject must be a Subject")
        if type(self.binding) is not SubjectPrincipalBinding:
            raise TypeError("binding must be a SubjectPrincipalBinding")
        if type(self.authority_principal) is not Principal:
            raise TypeError("authority_principal must be a Principal")
        _non_blank(self.effective_grant_id, "effective grant identifier")

        if self.request_subject != self.binding.subject:
            expected_status = SubjectAuthorityBindingStatus.SUBJECT_MISMATCH
        elif self.binding.principal != self.authority_principal:
            expected_status = SubjectAuthorityBindingStatus.PRINCIPAL_MISMATCH
        else:
            expected_status = SubjectAuthorityBindingStatus.BOUND

        if self.status is not expected_status:
            raise ValueError(
                "binding status does not match the compared Subject and Principal"
            )


@dataclass(frozen=True, slots=True)
class AuthorityBoundEvaluation:
    """Evidence for one effective authority context upper bound."""

    name: str
    upper_bound: int
    present: bool
    supplied_value: _Scalar = field(compare=False, hash=False)
    status: AuthorityApplicabilityStatus
    _typed_supplied_value: _TypedScalar = field(init=False, repr=False)

    def __post_init__(self) -> None:
        _non_blank(self.name, "authority bound name")
        if type(self.upper_bound) is not int:
            raise TypeError("authority upper bound must be an exact integer")
        if type(self.present) is not bool:
            raise TypeError("authority bound presence must be a boolean")
        if self.supplied_value is not None and type(self.supplied_value) not in (
            str,
            int,
            bool,
        ):
            raise TypeError(
                "supplied authority-bound values must be str, int, bool, or None"
            )
        if type(self.supplied_value) is str:
            _valid_string(self.supplied_value, "supplied authority-bound value")
        if type(self.status) is not AuthorityApplicabilityStatus:
            raise TypeError("bound status must be an AuthorityApplicabilityStatus")

        if not self.present:
            if self.supplied_value is not None:
                raise ValueError("a missing authority bound cannot have a value")
            expected_status = AuthorityApplicabilityStatus.MISSING_CONTEXT
        elif type(self.supplied_value) is not int:
            expected_status = AuthorityApplicabilityStatus.TYPE_ERROR
        elif self.supplied_value > self.upper_bound:
            expected_status = AuthorityApplicabilityStatus.BOUND_EXCEEDED
        else:
            expected_status = AuthorityApplicabilityStatus.APPLICABLE

        if self.status is not expected_status:
            raise ValueError("bound status does not match the supplied value")

        type_names = {
            str: "string",
            int: "integer",
            bool: "boolean",
            type(None): "null",
        }
        object.__setattr__(
            self,
            "_typed_supplied_value",
            (type_names[type(self.supplied_value)], self.supplied_value),
        )


def _canonical_bound_evaluations(
    value: object,
) -> tuple[AuthorityBoundEvaluation, ...]:
    evaluations = _typed_tuple(
        value,
        AuthorityBoundEvaluation,
        "bound_evaluations",
    )
    seen: set[str] = set()
    for evaluation in evaluations:
        if evaluation.name in seen:
            raise ValueError("bound_evaluations must not contain duplicate names")
        seen.add(evaluation.name)
    return tuple(
        sorted(
            evaluations,
            key=lambda evaluation: evaluation.name.encode("utf-8"),
        )
    )


@dataclass(frozen=True, slots=True)
class AuthorityApplicabilityResult:
    """Deterministic evidence binding effective authority to one request."""

    status: AuthorityApplicabilityStatus
    request_digest: Sha256Digest
    authority_digest: Sha256Digest
    chain_digest: Sha256Digest
    state_digest: Sha256Digest
    effective_grant_id: str
    expected_action: Action
    request_action: Action
    action_matches: bool
    expected_resource: Resource
    request_resource: Resource
    resource_matches: bool
    bound_evaluations: tuple[AuthorityBoundEvaluation, ...] = ()

    def __post_init__(self) -> None:
        if type(self.status) is not AuthorityApplicabilityStatus:
            raise TypeError("status must be an AuthorityApplicabilityStatus")
        for field_name, digest in (
            ("request_digest", self.request_digest),
            ("authority_digest", self.authority_digest),
            ("chain_digest", self.chain_digest),
            ("state_digest", self.state_digest),
        ):
            if type(digest) is not Sha256Digest:
                raise TypeError(f"{field_name} must be a Sha256Digest")
        _non_blank(self.effective_grant_id, "effective grant identifier")
        if type(self.expected_action) is not Action:
            raise TypeError("expected_action must be an Action")
        if type(self.request_action) is not Action:
            raise TypeError("request_action must be an Action")
        if type(self.action_matches) is not bool:
            raise TypeError("action_matches must be a boolean")
        if type(self.expected_resource) is not Resource:
            raise TypeError("expected_resource must be a Resource")
        if type(self.request_resource) is not Resource:
            raise TypeError("request_resource must be a Resource")
        if type(self.resource_matches) is not bool:
            raise TypeError("resource_matches must be a boolean")
        if self.action_matches != (self.expected_action == self.request_action):
            raise ValueError("action_matches does not match the compared Actions")
        if self.resource_matches != (
            self.expected_resource == self.request_resource
        ):
            raise ValueError("resource_matches does not match the compared Resources")

        evaluations = _canonical_bound_evaluations(self.bound_evaluations)
        object.__setattr__(self, "bound_evaluations", evaluations)

        bound_statuses = tuple(evaluation.status for evaluation in evaluations)
        if not self.action_matches:
            expected_status = AuthorityApplicabilityStatus.ACTION_MISMATCH
        elif not self.resource_matches:
            expected_status = AuthorityApplicabilityStatus.RESOURCE_MISMATCH
        elif AuthorityApplicabilityStatus.MISSING_CONTEXT in bound_statuses:
            expected_status = AuthorityApplicabilityStatus.MISSING_CONTEXT
        elif AuthorityApplicabilityStatus.TYPE_ERROR in bound_statuses:
            expected_status = AuthorityApplicabilityStatus.TYPE_ERROR
        elif AuthorityApplicabilityStatus.BOUND_EXCEEDED in bound_statuses:
            expected_status = AuthorityApplicabilityStatus.BOUND_EXCEEDED
        else:
            expected_status = AuthorityApplicabilityStatus.APPLICABLE

        if self.status is not expected_status:
            raise ValueError(
                "applicability status does not match comparison evidence"
            )


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
    """A named approval condition with an exact Principal allowlist."""

    code: str
    allowed_principals: tuple[Principal, ...]
    parameters: _Fields = field(default=(), compare=False, hash=False)
    _typed_parameters: _TypedFields = field(init=False, repr=False)

    def __post_init__(self) -> None:
        _non_blank(self.code, "approval requirement code")
        principals = _typed_tuple(
            self.allowed_principals,
            Principal,
            "allowed_principals",
        )
        if not principals:
            raise ValueError(
                "approval requirements must allow at least one Principal"
            )
        identifiers: set[str] = set()
        for principal in principals:
            if principal.identifier in identifiers:
                raise ValueError(
                    "allowed_principals must not contain duplicates"
                )
            identifiers.add(principal.identifier)
        object.__setattr__(
            self,
            "allowed_principals",
            tuple(
                sorted(
                    principals,
                    key=lambda principal: principal.identifier.encode("utf-8"),
                )
            ),
        )
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
        tuple(
            principal.identifier.encode("utf-8")
            for principal in requirement.allowed_principals
        ),
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
class ApproverAuthorizationResult:
    """Deterministic evidence authorizing one approval attempt."""

    status: ApproverAuthorizationStatus
    actor: Subject
    binding: ApproverSubjectPrincipalBinding
    required_requirement: ApprovalRequirement
    attempted_requirement: ApprovalRequirement

    def __post_init__(self) -> None:
        if type(self.status) is not ApproverAuthorizationStatus:
            raise TypeError("status must be an ApproverAuthorizationStatus")
        if type(self.actor) is not Subject:
            raise TypeError("actor must be a Subject")
        if type(self.binding) is not ApproverSubjectPrincipalBinding:
            raise TypeError(
                "binding must be an ApproverSubjectPrincipalBinding"
            )
        if type(self.required_requirement) is not ApprovalRequirement:
            raise TypeError(
                "required_requirement must be an ApprovalRequirement"
            )
        if type(self.attempted_requirement) is not ApprovalRequirement:
            raise TypeError(
                "attempted_requirement must be an ApprovalRequirement"
            )

        if self.required_requirement != self.attempted_requirement:
            expected_status = ApproverAuthorizationStatus.REQUIREMENT_MISMATCH
        elif self.actor != self.binding.subject:
            expected_status = ApproverAuthorizationStatus.SUBJECT_MISMATCH
        elif (
            self.binding.principal
            not in self.required_requirement.allowed_principals
        ):
            expected_status = (
                ApproverAuthorizationStatus.PRINCIPAL_NOT_ALLOWED
            )
        else:
            expected_status = ApproverAuthorizationStatus.AUTHORIZED

        if self.status is not expected_status:
            raise ValueError(
                "approver authorization status does not match its evidence"
            )


@dataclass(frozen=True, slots=True)
class ApprovalRequirementState:
    """The immutable state and logical-time evidence for one requirement."""

    requirement: ApprovalRequirement
    status: ApprovalRequirementStatus
    authorization: ApproverAuthorizationResult | None
    logical_time: int

    def __post_init__(self) -> None:
        if type(self.requirement) is not ApprovalRequirement:
            raise TypeError("requirement must be an ApprovalRequirement")
        if type(self.status) is not ApprovalRequirementStatus:
            raise TypeError("status must be an ApprovalRequirementStatus")
        if (
            self.authorization is not None
            and type(self.authorization) is not ApproverAuthorizationResult
        ):
            raise TypeError(
                "authorization must be an ApproverAuthorizationResult or None"
            )
        if type(self.logical_time) is not int:
            raise TypeError("logical_time must be an exact integer")

        requires_authorization = self.status in (
            ApprovalRequirementStatus.APPROVED,
            ApprovalRequirementStatus.REJECTED,
        )
        if requires_authorization != (self.authorization is not None):
            raise ValueError(
                "authorization must be present exactly for approved or "
                "rejected requirements"
            )
        if self.authorization is not None:
            if (
                self.authorization.status
                is not ApproverAuthorizationStatus.AUTHORIZED
            ):
                raise ValueError(
                    "requirement state authorization must be AUTHORIZED"
                )
            if (
                self.authorization.required_requirement != self.requirement
                or self.authorization.attempted_requirement
                != self.requirement
            ):
                raise ValueError(
                    "requirement state authorization must bind the exact "
                    "requirement"
                )

    @property
    def decided_by(self) -> Principal | None:
        """Return the authorized approver or rejector Principal, if any."""

        if self.authorization is None:
            return None
        return self.authorization.binding.principal


def _canonical_approval_requirement_states(
    value: object,
) -> tuple[ApprovalRequirementState, ...]:
    states = _typed_tuple(
        value,
        ApprovalRequirementState,
        "requirement_states",
    )
    if not states:
        raise ValueError("requirement_states must contain at least one state")
    requirements: list[ApprovalRequirement] = []
    for state in states:
        if state.requirement in requirements:
            raise ValueError(
                "requirement_states must not contain duplicate requirements"
            )
        requirements.append(state.requirement)
    return tuple(
        sorted(
            states,
            key=lambda state: _approval_requirement_sort_key(
                state.requirement
            ),
        )
    )


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


_TRUSTED_POLICY_BUNDLE_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class TrustedPolicyBundle:
    """A policy bundle with successful exact-purpose trust evidence."""

    bundle: PolicyBundle
    attestation: ArtifactAttestation
    verification: ArtifactVerificationResult

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError(
            "TrustedPolicyBundle can only be created by verification"
        )

    @classmethod
    def _from_verification(
        cls,
        *,
        bundle: PolicyBundle,
        attestation: ArtifactAttestation,
        verification: ArtifactVerificationResult,
        _token: object,
    ) -> TrustedPolicyBundle:
        if _token is not _TRUSTED_POLICY_BUNDLE_TOKEN:
            raise TypeError(
                "TrustedPolicyBundle requires successful verification"
            )
        if type(bundle) is not PolicyBundle:
            raise TypeError("bundle must be a PolicyBundle")
        if type(attestation) is not ArtifactAttestation:
            raise TypeError("attestation must be an ArtifactAttestation")
        if type(verification) is not ArtifactVerificationResult:
            raise TypeError(
                "verification must be an ArtifactVerificationResult"
            )
        if verification.status is not ArtifactVerificationStatus.VERIFIED:
            raise ValueError("trusted policy requires VERIFIED evidence")
        if verification.attestation != attestation:
            raise ValueError(
                "trusted policy must contain the exact verified attestation"
            )
        if verification.expected_purpose is not ArtifactPurpose.POLICY_BUNDLE:
            raise ValueError("trusted policy requires POLICY_BUNDLE purpose")
        if (
            verification.expected_artifact_kind
            is not ArtifactKind.POLICY_BUNDLE
        ):
            raise ValueError("trusted policy requires POLICY_BUNDLE kind")

        result = object.__new__(cls)
        object.__setattr__(result, "bundle", bundle)
        object.__setattr__(result, "attestation", attestation)
        object.__setattr__(result, "verification", verification)
        return result


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
    request_digest: Sha256Digest
    rule_evaluations: tuple[RuleEvaluation, ...] = ()
    authority_applicability: AuthorityApplicabilityResult | None = None
    subject_authority_binding: SubjectAuthorityBindingResult | None = None

    def __post_init__(self) -> None:
        if type(self.policy_bundle_digest) is not Sha256Digest:
            raise TypeError("policy_bundle_digest must be a Sha256Digest")
        if type(self.request_digest) is not Sha256Digest:
            raise TypeError("request_digest must be a Sha256Digest")
        if (
            self.authority_applicability is not None
            and type(self.authority_applicability)
            is not AuthorityApplicabilityResult
        ):
            raise TypeError(
                "authority_applicability must be an "
                "AuthorityApplicabilityResult or None"
            )
        if (
            self.authority_applicability is not None
            and self.authority_applicability.request_digest
            != self.request_digest
        ):
            raise ValueError(
                "authority applicability must bind the evidence request digest"
            )
        if (
            self.subject_authority_binding is not None
            and type(self.subject_authority_binding)
            is not SubjectAuthorityBindingResult
        ):
            raise TypeError(
                "subject_authority_binding must be a "
                "SubjectAuthorityBindingResult or None"
            )
        if (
            self.subject_authority_binding is not None
            and self.subject_authority_binding.request_digest
            != self.request_digest
        ):
            raise ValueError(
                "subject-authority binding must bind the evidence request digest"
            )
        if (
            self.subject_authority_binding is not None
            and self.authority_applicability is not None
        ):
            if (
                self.subject_authority_binding.authority_digest
                != self.authority_applicability.authority_digest
            ):
                raise ValueError(
                    "binding and applicability must identify the same authority"
                )
            if (
                self.subject_authority_binding.effective_grant_id
                != self.authority_applicability.effective_grant_id
            ):
                raise ValueError(
                    "binding and applicability must identify the same grant"
                )
        object.__setattr__(
            self,
            "rule_evaluations",
            _canonical_rule_evaluations(self.rule_evaluations),
        )

    @property
    def authority_chain_digest(self) -> Sha256Digest | None:
        """Return the exact validated delegation-chain digest, if supplied."""

        if self.authority_applicability is None:
            return None
        return self.authority_applicability.chain_digest

    @property
    def authority_state_digest(self) -> Sha256Digest | None:
        """Return the exact validation-state digest, if supplied."""

        if self.authority_applicability is None:
            return None
        return self.authority_applicability.state_digest

    @property
    def effective_grant_id(self) -> str | None:
        """Return the effective leaf Grant identifier, if supplied."""

        if self.authority_applicability is None:
            return None
        return self.authority_applicability.effective_grant_id

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
            binding = self.evidence.subject_authority_binding
            if (
                binding is None
                or binding.status is not SubjectAuthorityBindingStatus.BOUND
            ):
                raise ValueError(
                    "non-deny decisions require successful subject-authority binding"
                )
            applicability = self.evidence.authority_applicability
            if (
                applicability is None
                or applicability.status
                is not AuthorityApplicabilityStatus.APPLICABLE
            ):
                raise ValueError(
                    "non-deny decisions require applicable validated authority"
                )


_TRUSTED_AUTHORIZATION_RESULT_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class TrustedAuthorizationResult:
    """A policy Decision reached through authenticated trust wrappers."""

    request_digest: Sha256Digest
    policy_bundle_digest: Sha256Digest
    trusted_policy_digest: Sha256Digest
    verified_authority_digest: Sha256Digest
    authenticated_authority_digest: Sha256Digest
    decision: Decision

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError(
            "TrustedAuthorizationResult can only be created by trusted "
            "authorization"
        )

    @classmethod
    def _from_trusted_authorization(
        cls,
        *,
        request_digest: Sha256Digest,
        policy_bundle_digest: Sha256Digest,
        trusted_policy_digest: Sha256Digest,
        verified_authority_digest: Sha256Digest,
        authenticated_authority_digest: Sha256Digest,
        decision: Decision,
        _token: object,
    ) -> TrustedAuthorizationResult:
        if _token is not _TRUSTED_AUTHORIZATION_RESULT_TOKEN:
            raise TypeError(
                "TrustedAuthorizationResult requires trusted authorization"
            )
        for field_name, digest in (
            ("request_digest", request_digest),
            ("policy_bundle_digest", policy_bundle_digest),
            ("trusted_policy_digest", trusted_policy_digest),
            ("verified_authority_digest", verified_authority_digest),
            (
                "authenticated_authority_digest",
                authenticated_authority_digest,
            ),
        ):
            if type(digest) is not Sha256Digest:
                raise TypeError(f"{field_name} must be a Sha256Digest")
        if type(decision) is not Decision:
            raise TypeError("decision must be a Decision")
        if decision.evidence.request_digest != request_digest:
            raise ValueError("decision must bind the trusted request")
        if decision.evidence.policy_bundle_digest != policy_bundle_digest:
            raise ValueError("decision must bind the trusted policy bundle")
        applicability = decision.evidence.authority_applicability
        if (
            applicability is None
            or applicability.authority_digest != verified_authority_digest
        ):
            raise ValueError(
                "trusted decision must bind the authenticated authority"
            )

        result = object.__new__(cls)
        for field_name, value in (
            ("request_digest", request_digest),
            ("policy_bundle_digest", policy_bundle_digest),
            ("trusted_policy_digest", trusted_policy_digest),
            ("verified_authority_digest", verified_authority_digest),
            (
                "authenticated_authority_digest",
                authenticated_authority_digest,
            ),
            ("decision", decision),
        ):
            object.__setattr__(result, field_name, value)
        return result


_DECISION_RECEIPT_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class DecisionReceipt:
    """Content-bound identities for one complete authorization evaluation."""

    request_digest: Sha256Digest
    policy_bundle_digest: Sha256Digest
    validated_authority_digest: Sha256Digest | None
    delegation_chain_digest: Sha256Digest | None
    authorization_state_digest: Sha256Digest | None
    subject_principal_binding_evidence_digest: Sha256Digest | None
    authority_applicability_evidence_digest: Sha256Digest | None
    decision_digest: Sha256Digest
    outcome: Outcome
    approval_requirements: tuple[ApprovalRequirement, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError(
            "DecisionReceipt can only be created from a Decision"
        )

    @classmethod
    def _from_evaluation(
        cls,
        *,
        request_digest: Sha256Digest,
        policy_bundle_digest: Sha256Digest,
        validated_authority_digest: Sha256Digest | None,
        delegation_chain_digest: Sha256Digest | None,
        authorization_state_digest: Sha256Digest | None,
        subject_principal_binding_evidence_digest: Sha256Digest | None,
        authority_applicability_evidence_digest: Sha256Digest | None,
        decision_digest: Sha256Digest,
        outcome: Outcome,
        approval_requirements: object,
        _token: object,
    ) -> DecisionReceipt:
        if _token is not _DECISION_RECEIPT_TOKEN:
            raise TypeError("DecisionReceipt requires a completed evaluation")

        for field_name, digest in (
            ("request_digest", request_digest),
            ("policy_bundle_digest", policy_bundle_digest),
            ("decision_digest", decision_digest),
        ):
            if type(digest) is not Sha256Digest:
                raise TypeError(f"{field_name} must be a Sha256Digest")

        optional_digests = (
            ("validated_authority_digest", validated_authority_digest),
            ("delegation_chain_digest", delegation_chain_digest),
            ("authorization_state_digest", authorization_state_digest),
            (
                "subject_principal_binding_evidence_digest",
                subject_principal_binding_evidence_digest,
            ),
            (
                "authority_applicability_evidence_digest",
                authority_applicability_evidence_digest,
            ),
        )
        for field_name, digest in optional_digests:
            if digest is not None and type(digest) is not Sha256Digest:
                raise TypeError(
                    f"{field_name} must be a Sha256Digest or None"
                )

        if type(outcome) is not Outcome:
            raise TypeError("outcome must be an Outcome")
        requirements = _canonical_approval_requirements(
            approval_requirements
        )
        approval_required = outcome is Outcome.APPROVAL_REQUIRED
        if approval_required != bool(requirements):
            raise ValueError(
                "receipt approval requirements must be present exactly when "
                "approval is required"
            )

        if (
            subject_principal_binding_evidence_digest is not None
            and validated_authority_digest is None
        ):
            raise ValueError(
                "binding evidence requires validated authority identity"
            )
        applicability_fields = (
            authority_applicability_evidence_digest,
            validated_authority_digest,
            delegation_chain_digest,
            authorization_state_digest,
        )
        if authority_applicability_evidence_digest is not None and any(
            digest is None for digest in applicability_fields
        ):
            raise ValueError(
                "applicability evidence requires authority, chain, and state "
                "identity"
            )
        if outcome is not Outcome.DENY and any(
            digest is None
            for digest in (
                validated_authority_digest,
                delegation_chain_digest,
                authorization_state_digest,
                subject_principal_binding_evidence_digest,
                authority_applicability_evidence_digest,
            )
        ):
            raise ValueError(
                "non-deny receipts require complete successful authority "
                "evidence"
            )

        result = object.__new__(cls)
        object.__setattr__(result, "request_digest", request_digest)
        object.__setattr__(
            result,
            "policy_bundle_digest",
            policy_bundle_digest,
        )
        object.__setattr__(
            result,
            "validated_authority_digest",
            validated_authority_digest,
        )
        object.__setattr__(
            result,
            "delegation_chain_digest",
            delegation_chain_digest,
        )
        object.__setattr__(
            result,
            "authorization_state_digest",
            authorization_state_digest,
        )
        object.__setattr__(
            result,
            "subject_principal_binding_evidence_digest",
            subject_principal_binding_evidence_digest,
        )
        object.__setattr__(
            result,
            "authority_applicability_evidence_digest",
            authority_applicability_evidence_digest,
        )
        object.__setattr__(result, "decision_digest", decision_digest)
        object.__setattr__(result, "outcome", outcome)
        object.__setattr__(result, "approval_requirements", requirements)
        return result


_PENDING_APPROVAL_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class PendingApproval:
    """One immutable receipt-bound approval lifecycle state."""

    receipt: DecisionReceipt
    receipt_digest: Sha256Digest
    requirement_states: tuple[ApprovalRequirementState, ...]
    logical_time: int
    consumed_at: int | None
    execution_permit_digest: Sha256Digest | None
    status: ApprovalStatus

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError(
            "PendingApproval can only be created by approval transitions"
        )

    @classmethod
    def _from_transition(
        cls,
        *,
        receipt: DecisionReceipt,
        receipt_digest: Sha256Digest,
        requirement_states: object,
        logical_time: int,
        consumed_at: int | None,
        execution_permit_digest: Sha256Digest | None,
        _token: object,
    ) -> PendingApproval:
        if _token is not _PENDING_APPROVAL_TOKEN:
            raise TypeError("PendingApproval requires an approval transition")
        if type(receipt) is not DecisionReceipt:
            raise TypeError("receipt must be a DecisionReceipt")
        if receipt.outcome is not Outcome.APPROVAL_REQUIRED:
            raise ValueError(
                "pending approval requires an APPROVAL_REQUIRED receipt"
            )
        if type(receipt_digest) is not Sha256Digest:
            raise TypeError("receipt_digest must be a Sha256Digest")
        if type(logical_time) is not int:
            raise TypeError("logical_time must be an exact integer")

        states = _canonical_approval_requirement_states(
            requirement_states
        )
        if tuple(state.requirement for state in states) != (
            receipt.approval_requirements
        ):
            raise ValueError(
                "requirement states must exactly match receipt requirements"
            )
        if any(state.logical_time > logical_time for state in states):
            raise ValueError(
                "requirement state time cannot exceed approval logical time"
            )
        statuses = tuple(state.status for state in states)
        if consumed_at is not None:
            if type(consumed_at) is not int:
                raise TypeError("consumed_at must be an exact integer or None")
            if consumed_at != logical_time:
                raise ValueError(
                    "consumed_at must equal the approval logical time"
                )
            if not all(
                status is ApprovalRequirementStatus.APPROVED
                for status in statuses
            ):
                raise ValueError(
                    "only fully approved requirements can be consumed"
                )
            if type(execution_permit_digest) is not Sha256Digest:
                raise TypeError(
                    "consumed approval requires an execution permit digest"
                )
            status = ApprovalStatus.CONSUMED
        else:
            if execution_permit_digest is not None:
                raise ValueError(
                    "unconsumed approval cannot carry an execution permit digest"
                )
            if max(state.logical_time for state in states) != logical_time:
                raise ValueError(
                    "approval logical time must equal its latest state time"
                )
            if ApprovalRequirementStatus.REJECTED in statuses:
                status = ApprovalStatus.REJECTED
            elif ApprovalRequirementStatus.EXPIRED in statuses:
                status = ApprovalStatus.EXPIRED
            elif all(
                item is ApprovalRequirementStatus.APPROVED
                for item in statuses
            ):
                status = ApprovalStatus.APPROVED
            else:
                status = ApprovalStatus.PENDING

        result = object.__new__(cls)
        object.__setattr__(result, "receipt", receipt)
        object.__setattr__(result, "receipt_digest", receipt_digest)
        object.__setattr__(result, "requirement_states", states)
        object.__setattr__(result, "logical_time", logical_time)
        object.__setattr__(result, "consumed_at", consumed_at)
        object.__setattr__(
            result,
            "execution_permit_digest",
            execution_permit_digest,
        )
        object.__setattr__(result, "status", status)
        return result

    @property
    def approval_requirements(self) -> tuple[ApprovalRequirement, ...]:
        """Return the complete receipt-defined approval requirements."""

        return tuple(
            state.requirement for state in self.requirement_states
        )


_EXECUTION_PERMIT_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class ExecutionPermit:
    """Fresh internally consistent authority to consume one approval."""

    original_receipt_digest: Sha256Digest
    approved_state_digest: Sha256Digest
    current_request_digest: Sha256Digest
    current_policy_bundle_digest: Sha256Digest
    current_delegation_chain_digest: Sha256Digest
    current_authorization_state_digest: Sha256Digest
    current_validated_authority_digest: Sha256Digest
    subject_authority_binding: SubjectAuthorityBindingResult
    authority_applicability: AuthorityApplicabilityResult
    decision: Decision

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError(
            "ExecutionPermit can only be created by successful revalidation"
        )

    @classmethod
    def _from_revalidation(
        cls,
        *,
        original_receipt_digest: Sha256Digest,
        approved_state_digest: Sha256Digest,
        current_request_digest: Sha256Digest,
        current_policy_bundle_digest: Sha256Digest,
        current_delegation_chain_digest: Sha256Digest,
        current_authorization_state_digest: Sha256Digest,
        current_validated_authority_digest: Sha256Digest,
        subject_authority_binding: SubjectAuthorityBindingResult,
        authority_applicability: AuthorityApplicabilityResult,
        decision: Decision,
        _token: object,
    ) -> ExecutionPermit:
        if _token is not _EXECUTION_PERMIT_TOKEN:
            raise TypeError("ExecutionPermit requires successful revalidation")
        for field_name, digest in (
            ("original_receipt_digest", original_receipt_digest),
            ("approved_state_digest", approved_state_digest),
            ("current_request_digest", current_request_digest),
            ("current_policy_bundle_digest", current_policy_bundle_digest),
            (
                "current_delegation_chain_digest",
                current_delegation_chain_digest,
            ),
            (
                "current_authorization_state_digest",
                current_authorization_state_digest,
            ),
            (
                "current_validated_authority_digest",
                current_validated_authority_digest,
            ),
        ):
            if type(digest) is not Sha256Digest:
                raise TypeError(f"{field_name} must be a Sha256Digest")
        if type(subject_authority_binding) is not SubjectAuthorityBindingResult:
            raise TypeError(
                "subject_authority_binding must be a "
                "SubjectAuthorityBindingResult"
            )
        if (
            subject_authority_binding.status
            is not SubjectAuthorityBindingStatus.BOUND
        ):
            raise ValueError("execution permit requires bound holder evidence")
        if type(authority_applicability) is not AuthorityApplicabilityResult:
            raise TypeError(
                "authority_applicability must be an "
                "AuthorityApplicabilityResult"
            )
        if (
            authority_applicability.status
            is not AuthorityApplicabilityStatus.APPLICABLE
        ):
            raise ValueError(
                "execution permit requires applicable authority evidence"
            )
        if type(decision) is not Decision:
            raise TypeError("decision must be a Decision")
        if decision.outcome is not Outcome.APPROVAL_REQUIRED:
            raise ValueError(
                "execution permit requires a fresh APPROVAL_REQUIRED decision"
            )
        if decision.evidence.request_digest != current_request_digest:
            raise ValueError("decision must bind the current request")
        if (
            decision.evidence.policy_bundle_digest
            != current_policy_bundle_digest
        ):
            raise ValueError("decision must bind the current policy bundle")
        if decision.evidence.subject_authority_binding != (
            subject_authority_binding
        ):
            raise ValueError("decision must contain the exact holder evidence")
        if decision.evidence.authority_applicability != authority_applicability:
            raise ValueError(
                "decision must contain the exact applicability evidence"
            )
        if (
            authority_applicability.request_digest
            != current_request_digest
        ):
            raise ValueError("applicability must bind the current request")
        if (
            authority_applicability.authority_digest
            != current_validated_authority_digest
        ):
            raise ValueError("applicability must bind the current authority")
        if (
            authority_applicability.chain_digest
            != current_delegation_chain_digest
        ):
            raise ValueError("applicability must bind the current chain")
        if (
            authority_applicability.state_digest
            != current_authorization_state_digest
        ):
            raise ValueError(
                "applicability must bind the current authorization state"
            )

        result = object.__new__(cls)
        for field_name, value in (
            ("original_receipt_digest", original_receipt_digest),
            ("approved_state_digest", approved_state_digest),
            ("current_request_digest", current_request_digest),
            ("current_policy_bundle_digest", current_policy_bundle_digest),
            (
                "current_delegation_chain_digest",
                current_delegation_chain_digest,
            ),
            (
                "current_authorization_state_digest",
                current_authorization_state_digest,
            ),
            (
                "current_validated_authority_digest",
                current_validated_authority_digest,
            ),
            ("subject_authority_binding", subject_authority_binding),
            ("authority_applicability", authority_applicability),
            ("decision", decision),
        ):
            object.__setattr__(result, field_name, value)
        return result


_EXECUTION_AUTHORIZATION_RESULT_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class ExecutionAuthorizationResult:
    """Typed evidence from complete fresh execution revalidation."""

    status: ExecutionAuthorizationStatus
    original_receipt_digest: Sha256Digest
    approved_state_digest: Sha256Digest
    current_request_digest: Sha256Digest
    current_policy_bundle_digest: Sha256Digest
    current_delegation_chain_digest: Sha256Digest
    current_authorization_state_digest: Sha256Digest
    authority_validation: AuthorityValidationResult
    subject_authority_binding: SubjectAuthorityBindingResult | None
    authority_applicability: AuthorityApplicabilityResult | None
    decision: Decision
    execution_permit: ExecutionPermit | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError(
            "ExecutionAuthorizationResult can only be created by revalidation"
        )

    @classmethod
    def _from_revalidation(
        cls,
        *,
        status: ExecutionAuthorizationStatus,
        original_receipt_digest: Sha256Digest,
        approved_state_digest: Sha256Digest,
        current_request_digest: Sha256Digest,
        current_policy_bundle_digest: Sha256Digest,
        current_delegation_chain_digest: Sha256Digest,
        current_authorization_state_digest: Sha256Digest,
        authority_validation: AuthorityValidationResult,
        subject_authority_binding: SubjectAuthorityBindingResult | None,
        authority_applicability: AuthorityApplicabilityResult | None,
        decision: Decision,
        execution_permit: ExecutionPermit | None,
        _token: object,
    ) -> ExecutionAuthorizationResult:
        if _token is not _EXECUTION_AUTHORIZATION_RESULT_TOKEN:
            raise TypeError(
                "ExecutionAuthorizationResult requires revalidation"
            )
        if type(status) is not ExecutionAuthorizationStatus:
            raise TypeError("status must be an ExecutionAuthorizationStatus")
        for field_name, digest in (
            ("original_receipt_digest", original_receipt_digest),
            ("approved_state_digest", approved_state_digest),
            ("current_request_digest", current_request_digest),
            ("current_policy_bundle_digest", current_policy_bundle_digest),
            (
                "current_delegation_chain_digest",
                current_delegation_chain_digest,
            ),
            (
                "current_authorization_state_digest",
                current_authorization_state_digest,
            ),
        ):
            if type(digest) is not Sha256Digest:
                raise TypeError(f"{field_name} must be a Sha256Digest")
        if type(authority_validation) is not AuthorityValidationResult:
            raise TypeError(
                "authority_validation must be an AuthorityValidationResult"
            )
        if authority_validation.chain_digest != current_delegation_chain_digest:
            raise ValueError("validation must bind the current chain")
        if authority_validation.state_digest != current_authorization_state_digest:
            raise ValueError("validation must bind the current state")
        if (
            subject_authority_binding is not None
            and type(subject_authority_binding)
            is not SubjectAuthorityBindingResult
        ):
            raise TypeError(
                "subject_authority_binding must be a "
                "SubjectAuthorityBindingResult or None"
            )
        if (
            authority_applicability is not None
            and type(authority_applicability)
            is not AuthorityApplicabilityResult
        ):
            raise TypeError(
                "authority_applicability must be an "
                "AuthorityApplicabilityResult or None"
            )
        if type(decision) is not Decision:
            raise TypeError("decision must be a Decision")
        if decision.evidence.request_digest != current_request_digest:
            raise ValueError("decision must bind the current request")
        if (
            decision.evidence.policy_bundle_digest
            != current_policy_bundle_digest
        ):
            raise ValueError("decision must bind the current policy bundle")
        if decision.evidence.subject_authority_binding != (
            subject_authority_binding
        ):
            raise ValueError("result must preserve exact holder evidence")
        if decision.evidence.authority_applicability != authority_applicability:
            raise ValueError("result must preserve exact applicability evidence")

        authorized = status is ExecutionAuthorizationStatus.AUTHORIZED
        if authorized != (execution_permit is not None):
            raise ValueError(
                "execution_permit must be present exactly for AUTHORIZED"
            )
        if execution_permit is not None:
            if type(execution_permit) is not ExecutionPermit:
                raise TypeError("execution_permit must be an ExecutionPermit")
            if (
                execution_permit.original_receipt_digest
                != original_receipt_digest
                or execution_permit.approved_state_digest
                != approved_state_digest
                or execution_permit.current_request_digest
                != current_request_digest
                or execution_permit.current_policy_bundle_digest
                != current_policy_bundle_digest
                or execution_permit.current_delegation_chain_digest
                != current_delegation_chain_digest
                or execution_permit.current_authorization_state_digest
                != current_authorization_state_digest
                or execution_permit.decision != decision
            ):
                raise ValueError(
                    "execution permit must bind the exact revalidation result"
                )

        result = object.__new__(cls)
        for field_name, value in (
            ("status", status),
            ("original_receipt_digest", original_receipt_digest),
            ("approved_state_digest", approved_state_digest),
            ("current_request_digest", current_request_digest),
            ("current_policy_bundle_digest", current_policy_bundle_digest),
            (
                "current_delegation_chain_digest",
                current_delegation_chain_digest,
            ),
            (
                "current_authorization_state_digest",
                current_authorization_state_digest,
            ),
            ("authority_validation", authority_validation),
            ("subject_authority_binding", subject_authority_binding),
            ("authority_applicability", authority_applicability),
            ("decision", decision),
            ("execution_permit", execution_permit),
        ):
            object.__setattr__(result, field_name, value)
        return result


_TRUSTED_EXECUTION_AUTHORIZATION_RESULT_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False)
class TrustedExecutionAuthorizationResult:
    """Trusted wrapper around fresh authenticated execution revalidation."""

    status: TrustedExecutionAuthorizationStatus
    current_request_digest: Sha256Digest
    policy_bundle_digest: Sha256Digest
    trusted_policy_digest: Sha256Digest
    delegation_authentication: DelegationAuthenticationResult
    execution_authorization: ExecutionAuthorizationResult | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError(
            "TrustedExecutionAuthorizationResult can only be created by "
            "trusted execution revalidation"
        )

    @classmethod
    def _from_trusted_revalidation(
        cls,
        *,
        status: TrustedExecutionAuthorizationStatus,
        current_request_digest: Sha256Digest,
        policy_bundle_digest: Sha256Digest,
        trusted_policy_digest: Sha256Digest,
        delegation_authentication: DelegationAuthenticationResult,
        execution_authorization: ExecutionAuthorizationResult | None,
        _token: object,
    ) -> TrustedExecutionAuthorizationResult:
        if _token is not _TRUSTED_EXECUTION_AUTHORIZATION_RESULT_TOKEN:
            raise TypeError(
                "TrustedExecutionAuthorizationResult requires trusted "
                "execution revalidation"
            )
        if type(status) is not TrustedExecutionAuthorizationStatus:
            raise TypeError(
                "status must be a TrustedExecutionAuthorizationStatus"
            )
        if type(current_request_digest) is not Sha256Digest:
            raise TypeError("current_request_digest must be a Sha256Digest")
        if type(policy_bundle_digest) is not Sha256Digest:
            raise TypeError("policy_bundle_digest must be a Sha256Digest")
        if type(trusted_policy_digest) is not Sha256Digest:
            raise TypeError("trusted_policy_digest must be a Sha256Digest")
        if (
            type(delegation_authentication)
            is not DelegationAuthenticationResult
        ):
            raise TypeError(
                "delegation_authentication must be a "
                "DelegationAuthenticationResult"
            )
        if (
            execution_authorization is not None
            and type(execution_authorization)
            is not ExecutionAuthorizationResult
        ):
            raise TypeError(
                "execution_authorization must be an "
                "ExecutionAuthorizationResult or None"
            )

        authentication_succeeded = (
            delegation_authentication.status
            is DelegationAuthenticationStatus.AUTHENTICATED
        )
        if not authentication_succeeded:
            expected = (
                TrustedExecutionAuthorizationStatus
                .DELEGATION_AUTHENTICATION_FAILED
            )
            if execution_authorization is not None:
                raise ValueError(
                    "failed delegation authentication cannot carry "
                    "execution revalidation"
                )
        else:
            if execution_authorization is None:
                raise ValueError(
                    "authenticated delegation requires execution revalidation"
                )
            expected = (
                TrustedExecutionAuthorizationStatus.AUTHORIZED
                if execution_authorization.status
                is ExecutionAuthorizationStatus.AUTHORIZED
                else TrustedExecutionAuthorizationStatus
                .EXECUTION_REVALIDATION_FAILED
            )
            if (
                execution_authorization.current_request_digest
                != current_request_digest
            ):
                raise ValueError(
                    "execution revalidation must bind the current request"
                )
            if (
                execution_authorization.current_policy_bundle_digest
                != policy_bundle_digest
            ):
                raise ValueError(
                    "execution revalidation must bind the trusted policy"
                )
            if (
                execution_authorization.authority_validation
                != delegation_authentication.authority_validation
            ):
                raise ValueError(
                    "execution revalidation must use the authenticated "
                    "delegation validation"
                )
        if status is not expected:
            raise ValueError(
                "trusted execution status does not match nested evidence"
            )

        result = object.__new__(cls)
        object.__setattr__(result, "status", status)
        object.__setattr__(
            result,
            "current_request_digest",
            current_request_digest,
        )
        object.__setattr__(
            result,
            "policy_bundle_digest",
            policy_bundle_digest,
        )
        object.__setattr__(
            result,
            "trusted_policy_digest",
            trusted_policy_digest,
        )
        object.__setattr__(
            result,
            "delegation_authentication",
            delegation_authentication,
        )
        object.__setattr__(
            result,
            "execution_authorization",
            execution_authorization,
        )
        return result

    @property
    def execution_permit(self) -> ExecutionPermit | None:
        """Return the nested permit when trusted revalidation authorizes."""

        if self.execution_authorization is None:
            return None
        return self.execution_authorization.execution_permit
