"""Pure authentication of structurally validated delegation provenance."""

from __future__ import annotations

from .attestation import verify_artifact
from .canonical import sha256_digest
from .delegation import validate_authority
from .domain import (
    _AUTHENTICATED_DELEGATED_AUTHORITY_TOKEN,
    _DELEGATION_AUTHENTICATION_RESULT_TOKEN,
    ArtifactPurpose,
    ArtifactVerificationStatus,
    AuthenticatedDelegatedAuthority,
    AuthorityValidationResult,
    AuthorityValidationStatus,
    AuthorizationState,
    DelegationAuthenticationResult,
    DelegationAuthenticationStatus,
    DelegationChain,
    GrantAttestation,
    GrantAttestationSet,
    GrantAuthenticationEvidence,
    Principal,
    PrincipalKeyRegistry,
    Sha256Digest,
    SigningKeyId,
    TrustedAuthorityRoots,
    TrustStore,
)


def _attestation_for(
    attestations: GrantAttestationSet,
    grant_id: str,
) -> GrantAttestation | None:
    for entry in attestations.entries:
        if entry.grant_id == grant_id:
            return entry
    return None


def _principal_for_key(
    registry: PrincipalKeyRegistry,
    key_id: SigningKeyId,
) -> Principal | None:
    for binding in registry.bindings:
        if binding.key_id == key_id:
            return binding.principal
    return None


def _verification_failure_status(
    status: ArtifactVerificationStatus,
) -> DelegationAuthenticationStatus | None:
    if status is ArtifactVerificationStatus.VERIFIED:
        return None
    if status is ArtifactVerificationStatus.UNKNOWN_KEY:
        return DelegationAuthenticationStatus.UNKNOWN_SIGNING_KEY
    if status is ArtifactVerificationStatus.KEY_NOT_TRUSTED_FOR_PURPOSE:
        return DelegationAuthenticationStatus.KEY_NOT_TRUSTED_FOR_AUTHORITY_GRANT
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
    raise RuntimeError("unsupported artifact verification status")


def _result(
    *,
    status: DelegationAuthenticationStatus,
    authority_validation: AuthorityValidationResult,
    grant_attestations_digest: Sha256Digest,
    trust_store_digest: Sha256Digest,
    principal_key_registry_digest: Sha256Digest,
    trusted_authority_roots_digest: Sha256Digest,
    grant_evidence: object = (),
    offending_grant_id: str | None = None,
    authenticated_authority: AuthenticatedDelegatedAuthority | None = None,
) -> DelegationAuthenticationResult:
    return DelegationAuthenticationResult._from_authentication(
        status=status,
        authority_validation=authority_validation,
        grant_attestations_digest=grant_attestations_digest,
        trust_store_digest=trust_store_digest,
        principal_key_registry_digest=principal_key_registry_digest,
        trusted_authority_roots_digest=trusted_authority_roots_digest,
        grant_evidence=grant_evidence,
        offending_grant_id=offending_grant_id,
        authenticated_authority=authenticated_authority,
        _token=_DELEGATION_AUTHENTICATION_RESULT_TOKEN,
    )


def authenticate_delegation_chain(
    chain: DelegationChain,
    state: AuthorizationState,
    grant_attestations: GrantAttestationSet,
    trust_store: TrustStore,
    principal_key_registry: PrincipalKeyRegistry,
    trusted_authority_roots: TrustedAuthorityRoots,
) -> DelegationAuthenticationResult:
    """Authenticate every grantor in one currently valid delegation chain."""

    if type(chain) is not DelegationChain:
        raise TypeError("chain must be a DelegationChain")
    if type(state) is not AuthorizationState:
        raise TypeError("state must be an AuthorizationState")
    if type(grant_attestations) is not GrantAttestationSet:
        raise TypeError("grant_attestations must be a GrantAttestationSet")
    if type(trust_store) is not TrustStore:
        raise TypeError("trust_store must be a TrustStore")
    if type(principal_key_registry) is not PrincipalKeyRegistry:
        raise TypeError("principal_key_registry must be a PrincipalKeyRegistry")
    if type(trusted_authority_roots) is not TrustedAuthorityRoots:
        raise TypeError("trusted_authority_roots must be TrustedAuthorityRoots")

    authority_validation = validate_authority(chain, state)
    grant_attestations_digest = sha256_digest(grant_attestations)
    trust_store_digest = sha256_digest(trust_store)
    principal_key_registry_digest = sha256_digest(principal_key_registry)
    trusted_authority_roots_digest = sha256_digest(trusted_authority_roots)

    if authority_validation.status is not AuthorityValidationStatus.VALID:
        return _result(
            status=(DelegationAuthenticationStatus.STRUCTURAL_AUTHORITY_INVALID),
            authority_validation=authority_validation,
            grant_attestations_digest=grant_attestations_digest,
            trust_store_digest=trust_store_digest,
            principal_key_registry_digest=principal_key_registry_digest,
            trusted_authority_roots_digest=trusted_authority_roots_digest,
            offending_grant_id=authority_validation.offending_grant_id,
        )

    chain_ids = tuple(grant.identifier for grant in chain.grants)
    for supplied_entry in grant_attestations.entries:
        if supplied_entry.grant_id not in chain_ids:
            return _result(
                status=(DelegationAuthenticationStatus.UNKNOWN_GRANT_ATTESTATION),
                authority_validation=authority_validation,
                grant_attestations_digest=grant_attestations_digest,
                trust_store_digest=trust_store_digest,
                principal_key_registry_digest=(principal_key_registry_digest),
                trusted_authority_roots_digest=(trusted_authority_roots_digest),
                offending_grant_id=supplied_entry.grant_id,
            )

    evidence: list[GrantAuthenticationEvidence] = []
    for index, grant in enumerate(chain.grants):
        is_root = index == 0
        root_principal_trusted = (
            grant.grantor in trusted_authority_roots.principals if is_root else None
        )
        grant_entry = _attestation_for(grant_attestations, grant.identifier)
        if grant_entry is None:
            evidence.append(
                GrantAuthenticationEvidence(
                    grant_id=grant.identifier,
                    grantor=grant.grantor,
                    is_root=is_root,
                    root_principal_trusted=root_principal_trusted,
                    signing_key_id=None,
                    bound_principal=None,
                    verification=None,
                    status=(DelegationAuthenticationStatus.MISSING_ATTESTATION),
                )
            )
            continue

        verification = verify_artifact(
            grant,
            grant_entry.attestation,
            trust_store,
            ArtifactPurpose.AUTHORITY_GRANT,
        )
        key_id = grant_entry.attestation.key_id
        bound_principal = _principal_for_key(
            principal_key_registry,
            key_id,
        )
        status = _verification_failure_status(verification.status)
        if status is None:
            if bound_principal != grant.grantor:
                status = DelegationAuthenticationStatus.SIGNER_KEY_NOT_BOUND_TO_GRANTOR
            elif is_root and not root_principal_trusted:
                status = DelegationAuthenticationStatus.UNTRUSTED_ROOT_PRINCIPAL
            else:
                status = DelegationAuthenticationStatus.AUTHENTICATED

        evidence.append(
            GrantAuthenticationEvidence(
                grant_id=grant.identifier,
                grantor=grant.grantor,
                is_root=is_root,
                root_principal_trusted=root_principal_trusted,
                signing_key_id=key_id,
                bound_principal=bound_principal,
                verification=verification,
                status=status,
            )
        )

    failure = next(
        (
            item
            for item in evidence
            if item.status is not DelegationAuthenticationStatus.AUTHENTICATED
        ),
        None,
    )
    if failure is not None:
        return _result(
            status=failure.status,
            authority_validation=authority_validation,
            grant_attestations_digest=grant_attestations_digest,
            trust_store_digest=trust_store_digest,
            principal_key_registry_digest=principal_key_registry_digest,
            trusted_authority_roots_digest=trusted_authority_roots_digest,
            grant_evidence=evidence,
            offending_grant_id=failure.grant_id,
        )

    verified_authority = authority_validation.verified_authority
    if verified_authority is None:
        raise RuntimeError("VALID authority did not contain verified authority")
    authenticated_authority = AuthenticatedDelegatedAuthority._from_authentication(
        verified_authority=verified_authority,
        authority_validation_digest=sha256_digest(authority_validation),
        grant_attestations_digest=grant_attestations_digest,
        trust_store_digest=trust_store_digest,
        principal_key_registry_digest=principal_key_registry_digest,
        trusted_authority_roots_digest=trusted_authority_roots_digest,
        grant_evidence=evidence,
        _token=_AUTHENTICATED_DELEGATED_AUTHORITY_TOKEN,
    )
    return _result(
        status=DelegationAuthenticationStatus.AUTHENTICATED,
        authority_validation=authority_validation,
        grant_attestations_digest=grant_attestations_digest,
        trust_store_digest=trust_store_digest,
        principal_key_registry_digest=principal_key_registry_digest,
        trusted_authority_roots_digest=trusted_authority_roots_digest,
        grant_evidence=evidence,
        authenticated_authority=authenticated_authority,
    )
