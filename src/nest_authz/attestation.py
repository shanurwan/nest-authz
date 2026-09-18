"""Detached Ed25519 attestations over exact canonical artifact identities."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey as CryptographyEd25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey as CryptographyEd25519PublicKey,
)

from .canonical import sha256_digest
from .domain import (
    _ARTIFACT_VERIFICATION_RESULT_TOKEN,
    _TRUSTED_POLICY_BUNDLE_TOKEN,
    ArtifactAttestation,
    ArtifactKind,
    ArtifactPurpose,
    ArtifactSignature,
    ArtifactVerificationResult,
    ArtifactVerificationStatus,
    AuthorityGrant,
    DecisionReceipt,
    ExecutionPermit,
    PolicyBundle,
    Sha256Digest,
    SignatureScheme,
    SigningKeyId,
    TrustedKey,
    TrustedPolicyBundle,
    TrustStore,
)

_ATTESTATION_PREAMBLE = b"NEST-AUTHZ-ATTESTATION\x00\x01"
_MAX_FIELD_LENGTH = (1 << 32) - 1


class ArtifactVerificationError(RuntimeError):
    """A typed failure to create a trusted artifact wrapper."""

    def __init__(self, result: ArtifactVerificationResult) -> None:
        self.result = result
        super().__init__(f"artifact verification failed: {result.status.value}")


def _message_field(tag: bytes, value: bytes) -> bytes:
    if len(tag) != 1:
        raise ValueError("attestation field tags must contain one byte")
    if len(value) > _MAX_FIELD_LENGTH:
        raise ValueError("attestation message field is too large")
    return tag + len(value).to_bytes(4, byteorder="big") + value


def attestation_signing_message(
    scheme: SignatureScheme,
    purpose: ArtifactPurpose,
    artifact_kind: ArtifactKind,
    artifact_digest: Sha256Digest,
) -> bytes:
    """Return the exact version-1 domain-separated signing message."""

    if type(scheme) is not SignatureScheme:
        raise TypeError("scheme must be a SignatureScheme")
    if type(purpose) is not ArtifactPurpose:
        raise TypeError("purpose must be an ArtifactPurpose")
    if type(artifact_kind) is not ArtifactKind:
        raise TypeError("artifact_kind must be an ArtifactKind")
    if type(artifact_digest) is not Sha256Digest:
        raise TypeError("artifact_digest must be a Sha256Digest")

    return b"".join(
        (
            _ATTESTATION_PREAMBLE,
            _message_field(b"S", scheme.value.encode("utf-8")),
            _message_field(b"P", purpose.value.encode("utf-8")),
            _message_field(b"K", artifact_kind.value.encode("utf-8")),
            _message_field(b"D", artifact_digest.value),
        )
    )


def _artifact_kind_and_purpose(
    artifact: object,
) -> tuple[ArtifactKind, ArtifactPurpose]:
    artifact_type = type(artifact)
    if artifact_type is PolicyBundle:
        return ArtifactKind.POLICY_BUNDLE, ArtifactPurpose.POLICY_BUNDLE
    if artifact_type is AuthorityGrant:
        return ArtifactKind.AUTHORITY_GRANT, ArtifactPurpose.AUTHORITY_GRANT
    if artifact_type is DecisionReceipt:
        return ArtifactKind.DECISION_RECEIPT, ArtifactPurpose.DECISION_RECEIPT
    if artifact_type is ExecutionPermit:
        return ArtifactKind.EXECUTION_PERMIT, ArtifactPurpose.EXECUTION_PERMIT
    raise TypeError("artifact type is not supported for attestation")


def artifact_signing_message(
    artifact: object,
    purpose: ArtifactPurpose,
) -> bytes:
    """Compute the signing message from one supported artifact itself."""

    artifact_kind, required_purpose = _artifact_kind_and_purpose(artifact)
    if type(purpose) is not ArtifactPurpose:
        raise TypeError("purpose must be an ArtifactPurpose")
    if purpose is not required_purpose:
        raise ValueError("purpose does not match the artifact kind's version-1 purpose")
    return attestation_signing_message(
        SignatureScheme.ED25519,
        purpose,
        artifact_kind,
        sha256_digest(artifact),
    )


def sign_artifact(
    artifact: object,
    private_key: CryptographyEd25519PrivateKey,
    key_id: SigningKeyId,
    purpose: ArtifactPurpose,
) -> ArtifactAttestation:
    """Sign one supported artifact using an operational Ed25519 private key."""

    artifact_kind, required_purpose = _artifact_kind_and_purpose(artifact)
    if not isinstance(private_key, CryptographyEd25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    if type(key_id) is not SigningKeyId:
        raise TypeError("key_id must be a SigningKeyId")
    if type(purpose) is not ArtifactPurpose:
        raise TypeError("purpose must be an ArtifactPurpose")
    if purpose is not required_purpose:
        raise ValueError("purpose does not match the artifact kind's version-1 purpose")

    artifact_digest = sha256_digest(artifact)
    message = attestation_signing_message(
        SignatureScheme.ED25519,
        purpose,
        artifact_kind,
        artifact_digest,
    )
    signature = private_key.sign(message)
    return ArtifactAttestation(
        scheme=SignatureScheme.ED25519,
        key_id=key_id,
        purpose=purpose,
        artifact_kind=artifact_kind,
        artifact_digest=artifact_digest,
        signature=ArtifactSignature(signature),
    )


def _trusted_key(
    trust_store: TrustStore,
    key_id: SigningKeyId,
) -> TrustedKey | None:
    for trusted_key in trust_store.trusted_keys:
        if trusted_key.key_id == key_id:
            return trusted_key
    return None


def verify_artifact(
    artifact: object,
    attestation: ArtifactAttestation,
    trust_store: TrustStore,
    expected_purpose: ArtifactPurpose,
) -> ArtifactVerificationResult:
    """Verify one artifact against an explicit immutable trust store."""

    expected_kind, required_purpose = _artifact_kind_and_purpose(artifact)
    if type(attestation) is not ArtifactAttestation:
        raise TypeError("attestation must be an ArtifactAttestation")
    if type(trust_store) is not TrustStore:
        raise TypeError("trust_store must be a TrustStore")
    if type(expected_purpose) is not ArtifactPurpose:
        raise TypeError("expected_purpose must be an ArtifactPurpose")
    if expected_purpose is not required_purpose:
        raise ValueError(
            "expected_purpose does not match the artifact's version-1 purpose"
        )

    artifact_digest = sha256_digest(artifact)
    trusted_key = _trusted_key(trust_store, attestation.key_id)

    if attestation.artifact_kind is not expected_kind:
        status = ArtifactVerificationStatus.ARTIFACT_KIND_MISMATCH
    elif attestation.purpose is not expected_purpose:
        status = ArtifactVerificationStatus.PURPOSE_MISMATCH
    elif attestation.scheme is not SignatureScheme.ED25519:
        status = ArtifactVerificationStatus.SCHEME_UNSUPPORTED
    elif attestation.artifact_digest != artifact_digest:
        status = ArtifactVerificationStatus.DIGEST_MISMATCH
    elif trusted_key is None:
        status = ArtifactVerificationStatus.UNKNOWN_KEY
    else:
        message = attestation_signing_message(
            attestation.scheme,
            attestation.purpose,
            attestation.artifact_kind,
            attestation.artifact_digest,
        )
        try:
            public_key = CryptographyEd25519PublicKey.from_public_bytes(
                trusted_key.public_key.value
            )
            public_key.verify(attestation.signature.value, message)
        except (InvalidSignature, ValueError):
            status = ArtifactVerificationStatus.SIGNATURE_INVALID
        else:
            if expected_purpose not in trusted_key.allowed_purposes:
                status = ArtifactVerificationStatus.KEY_NOT_TRUSTED_FOR_PURPOSE
            else:
                status = ArtifactVerificationStatus.VERIFIED

    return ArtifactVerificationResult._from_verification(
        status=status,
        artifact_digest=artifact_digest,
        attestation=attestation,
        expected_purpose=expected_purpose,
        expected_artifact_kind=expected_kind,
        _token=_ARTIFACT_VERIFICATION_RESULT_TOKEN,
    )


def verify_policy_bundle(
    bundle: PolicyBundle,
    attestation: ArtifactAttestation,
    trust_store: TrustStore,
) -> TrustedPolicyBundle:
    """Create a trusted policy wrapper only after complete verification."""

    if type(bundle) is not PolicyBundle:
        raise TypeError("bundle must be a PolicyBundle")
    verification = verify_artifact(
        bundle,
        attestation,
        trust_store,
        ArtifactPurpose.POLICY_BUNDLE,
    )
    if verification.status is not ArtifactVerificationStatus.VERIFIED:
        raise ArtifactVerificationError(verification)
    return TrustedPolicyBundle._from_verification(
        bundle=bundle,
        attestation=attestation,
        verification=verification,
        _token=_TRUSTED_POLICY_BUNDLE_TOKEN,
    )
