"""Pure deterministic delegated-authority validation."""

from __future__ import annotations

from .canonical import sha256_digest
from .domain import (
    _VERIFIED_AUTHORITY_TOKEN,
    AuthorityGrant,
    AuthorityScope,
    AuthorityValidationResult,
    AuthorityValidationStatus,
    AuthorizationState,
    DelegationChain,
    VerifiedAuthority,
)


class AuthorityValidationError(RuntimeError):
    """An impossible internal validator state at the trust boundary."""


def _find_grant(
    grants: tuple[AuthorityGrant, ...],
    identifier: str,
) -> AuthorityGrant | None:
    for grant in grants:
        if grant.identifier == identifier:
            return grant
    return None


def _duplicate_grant_id(
    grants: tuple[AuthorityGrant, ...],
) -> str | None:
    seen: list[str] = []
    for grant in grants:
        if grant.identifier in seen:
            return grant.identifier
        seen.append(grant.identifier)
    return None


def _reference_cycle(
    grants: tuple[AuthorityGrant, ...],
) -> str | None:
    for start in grants:
        path: list[str] = []
        current: AuthorityGrant | None = start
        while current is not None:
            if current.identifier in path:
                return current.identifier
            path.append(current.identifier)
            if current.parent_grant_id is None:
                break
            current = _find_grant(grants, current.parent_grant_id)
    return None


def _principal_cycle(
    grants: tuple[AuthorityGrant, ...],
) -> str | None:
    principal_path = [grants[0].grantor.identifier]
    for grant in grants:
        if grant.grantee.identifier in principal_path:
            return grant.identifier
        principal_path.append(grant.grantee.identifier)
    return None


def _bound(scope: AuthorityScope, name: str) -> int | None:
    for candidate_name, value in scope.context_upper_bounds:
        if candidate_name == name:
            return value
    return None


def _is_attenuation(child: AuthorityScope, parent: AuthorityScope) -> bool:
    if child.action != parent.action or child.resource != parent.resource:
        return False
    for name, parent_bound in parent.context_upper_bounds:
        child_bound = _bound(child, name)
        if child_bound is None or child_bound > parent_bound:
            return False
    return True


def validate_authority(
    chain: DelegationChain,
    state: AuthorizationState,
) -> AuthorityValidationResult:
    """Validate a complete delegation chain using only supplied state."""

    if type(chain) is not DelegationChain:
        raise TypeError("chain must be a DelegationChain")
    if type(state) is not AuthorizationState:
        raise TypeError("state must be an AuthorizationState")

    chain_digest = sha256_digest(chain)
    state_digest = sha256_digest(state)
    grants = chain.grants

    def failure(
        status: AuthorityValidationStatus,
        offending_grant_id: str,
    ) -> AuthorityValidationResult:
        return AuthorityValidationResult(
            status=status,
            chain_digest=chain_digest,
            state_digest=state_digest,
            offending_grant_id=offending_grant_id,
        )

    duplicate = _duplicate_grant_id(grants)
    if duplicate is not None:
        return failure(AuthorityValidationStatus.INVALID_CHAIN, duplicate)

    cycle = _reference_cycle(grants)
    if cycle is not None:
        return failure(AuthorityValidationStatus.CYCLE, cycle)

    root = grants[0]
    if root.parent_grant_id is not None:
        return failure(AuthorityValidationStatus.BROKEN_PROVENANCE, root.identifier)

    for parent, child in zip(grants, grants[1:], strict=False):
        if child.parent_grant_id != parent.identifier:
            return failure(
                AuthorityValidationStatus.BROKEN_PROVENANCE,
                child.identifier,
            )
        if parent.grantee != child.grantor:
            return failure(
                AuthorityValidationStatus.BROKEN_PROVENANCE,
                child.identifier,
            )

    cycle = _principal_cycle(grants)
    if cycle is not None:
        return failure(AuthorityValidationStatus.CYCLE, cycle)

    for parent, child in zip(grants, grants[1:], strict=False):
        if not _is_attenuation(child.scope, parent.scope):
            return failure(
                AuthorityValidationStatus.BROADENED_AUTHORITY,
                child.identifier,
            )

    for grant in grants:
        if grant.identifier in state.revocations.grant_ids:
            return failure(AuthorityValidationStatus.REVOKED, grant.identifier)

    for grant in grants:
        if state.logical_time < grant.valid_from:
            return failure(
                AuthorityValidationStatus.NOT_YET_VALID,
                grant.identifier,
            )

    for grant in grants:
        if state.logical_time >= grant.valid_until:
            return failure(AuthorityValidationStatus.EXPIRED, grant.identifier)

    leaf = grants[-1]
    verified = VerifiedAuthority._from_validation(
        grant_id=leaf.identifier,
        principal=leaf.grantee,
        scope=leaf.scope,
        validated_at=state.logical_time,
        chain_digest=chain_digest,
        state_digest=state_digest,
        _token=_VERIFIED_AUTHORITY_TOKEN,
    )
    return AuthorityValidationResult(
        status=AuthorityValidationStatus.VALID,
        chain_digest=chain_digest,
        state_digest=state_digest,
        verified_authority=verified,
    )
