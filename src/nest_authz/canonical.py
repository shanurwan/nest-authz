"""Deterministic canonical bytes and content digests for domain objects."""

from __future__ import annotations

from collections.abc import Iterable
from hashlib import sha256

from .domain import (
    Action,
    ApprovalRequirement,
    Authority,
    AuthorizationRequest,
    ConditionStatus,
    Decision,
    DecisionEvidence,
    Obligation,
    Outcome,
    Reason,
    RequestContext,
    Resource,
    Sha256Digest,
    Subject,
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
    if value_type is RequestContext:
        return _encode_record(
            "nest-authz/request-context@1",
            (("attributes", _encode_scalar_map(value.attributes)),),
        )
    if value_type is Authority:
        return _encode_record(
            "nest-authz/authority@1",
            (
                ("identifier", _encode_string(value.identifier)),
                ("attributes", _encode_scalar_map(value.attributes)),
            ),
        )
    if value_type is AuthorizationRequest:
        return _encode_record(
            "nest-authz/authorization-request@1",
            (
                ("subject", _encode_domain(value.subject)),
                ("action", _encode_domain(value.action)),
                ("resource", _encode_domain(value.resource)),
                ("context", _encode_domain(value.context)),
                ("authority", _encode_optional_domain(value.authority)),
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
            "nest-authz/approval-requirement@1",
            (
                ("code", _encode_string(value.code)),
                ("parameters", _encode_scalar_map(value.parameters)),
            ),
        )
    if value_type is DecisionEvidence:
        return _encode_record(
            "nest-authz/decision-evidence@2",
            (
                (
                    "policy_bundle_digest",
                    _encode_domain(value.policy_bundle_digest),
                ),
                ("matched_policy_id", _encode_scalar(value.matched_policy_id)),
                (
                    "matched_authority",
                    _encode_optional_domain(value.matched_authority),
                ),
                (
                    "condition_results",
                    _encode_condition_status_map(value.condition_results),
                ),
            ),
        )
    if value_type is Decision:
        return _encode_record(
            "nest-authz/decision@1",
            (
                ("outcome", _encode_domain(value.outcome)),
                ("reasons", _encode_sequence(value.reasons)),
                ("evidence", _encode_domain(value.evidence)),
                ("obligations", _encode_sequence(value.obligations)),
                (
                    "approval_requirement",
                    _encode_optional_domain(value.approval_requirement),
                ),
            ),
        )

    raise TypeError("value is not a supported canonical domain type")
