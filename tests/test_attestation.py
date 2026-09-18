import ast
import importlib
import inspect
import os
import subprocess
import sys
import unittest
from dataclasses import replace

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nest_authz import (
    Action,
    ApprovalRequirement,
    ApproverSubjectPrincipalBinding,
    ArtifactKind,
    ArtifactPurpose,
    ArtifactSignature,
    ArtifactVerificationError,
    ArtifactVerificationStatus,
    AuthorityGrant,
    AuthorityScope,
    AuthorizationRequest,
    AuthorizationState,
    Condition,
    ConditionOperator,
    DelegationChain,
    Ed25519PublicKey,
    FieldNamespace,
    FieldReference,
    Policy,
    PolicyBundle,
    Principal,
    RequestContext,
    Resource,
    Rule,
    RuleEffect,
    Sha256Digest,
    SignatureScheme,
    SigningKeyId,
    Subject,
    SubjectPrincipalBinding,
    TrustedKey,
    TrustedPolicyBundle,
    TrustStore,
    approve_requirement,
    artifact_signing_message,
    attestation_signing_message,
    canonical_bytes,
    check_approver_authorization,
    create_decision_receipt,
    create_pending_approval,
    evaluate,
    revalidate_for_execution,
    sha256_digest,
    sign_artifact,
    validate_authority,
    verify_artifact,
    verify_policy_bundle,
)

_GOLDEN_MESSAGE_HEX = (
    "4e4553542d415554485a2d4154544553544154494f4e0001"
    "530000000745443235353139"
    "500000000d504f4c4943595f42554e444c45"
    "4b0000000d504f4c4943595f42554e444c45"
    "4400000020000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)


def _policy_bundle(identifier="policy:messages", effect=RuleEffect.PERMIT):
    condition = Condition(
        "action_matches",
        FieldReference(FieldNamespace.ACTION, "name"),
        ConditionOperator.EQUALS,
        "message.send",
    )
    requirements = (
        (
            ApprovalRequirement(
                "OWNER_APPROVAL",
                (Principal("principal:approver"),),
            ),
        )
        if effect is RuleEffect.APPROVAL_REQUIRED
        else ()
    )
    return PolicyBundle(
        (
            Policy(
                identifier,
                (
                    Rule(
                        "rule:messages",
                        effect,
                        (condition,),
                        approval_requirements=requirements,
                    ),
                ),
            ),
        )
    )


def _authority_grant(identifier="grant:messages"):
    return AuthorityGrant(
        identifier,
        Principal("issuer:root"),
        Principal("principal:agent"),
        AuthorityScope(Action("message.send"), Resource("room:general")),
        None,
        0,
        100,
    )


def _public_key(private_key):
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return Ed25519PublicKey(raw)


def _trusted_key(private_key, key_id, purposes):
    return TrustedKey(key_id, _public_key(private_key), purposes)


def _approval_values(amount=1):
    request = AuthorizationRequest(
        Subject("agent:1"),
        Action("message.send"),
        Resource("room:general"),
        RequestContext((("amount", amount),)),
        None,
    )
    grant = _authority_grant()
    chain = DelegationChain((grant,))
    state = AuthorizationState(10)
    authority = validate_authority(chain, state).verified_authority
    binding = SubjectPrincipalBinding(
        request.subject,
        Principal("principal:agent"),
    )
    bundle = _policy_bundle(effect=RuleEffect.APPROVAL_REQUIRED)
    decision = evaluate(request, bundle, authority, binding)
    receipt = create_decision_receipt(decision)
    pending = create_pending_approval(receipt, 10)
    requirement = receipt.approval_requirements[0]
    actor = Subject("approver:owner")
    approver_binding = ApproverSubjectPrincipalBinding(
        actor,
        Principal("principal:approver"),
    )
    authorization = check_approver_authorization(
        actor,
        approver_binding,
        requirement,
        requirement,
    )
    approved = approve_requirement(
        pending,
        requirement,
        authorization,
        11,
    )
    return {
        "request": request,
        "bundle": bundle,
        "chain": chain,
        "state": state,
        "binding": binding,
        "receipt": receipt,
        "approved": approved,
    }


def _execution_permit(values, logical_time=10):
    result = revalidate_for_execution(
        values["receipt"],
        values["approved"],
        values["request"],
        values["bundle"],
        values["chain"],
        AuthorizationState(logical_time),
        values["binding"],
    )
    if result.execution_permit is None:
        raise AssertionError(f"revalidation failed: {result.status}")
    return result.execution_permit


class ArtifactAttestationTests(unittest.TestCase):
    def test_signature_and_verification_enums_are_closed(self):
        self.assertEqual(tuple(SignatureScheme), (SignatureScheme.ED25519,))
        self.assertEqual(
            set(ArtifactVerificationStatus),
            {
                ArtifactVerificationStatus.VERIFIED,
                ArtifactVerificationStatus.DIGEST_MISMATCH,
                ArtifactVerificationStatus.SIGNATURE_INVALID,
                ArtifactVerificationStatus.UNKNOWN_KEY,
                ArtifactVerificationStatus.KEY_NOT_TRUSTED_FOR_PURPOSE,
                ArtifactVerificationStatus.ARTIFACT_KIND_MISMATCH,
                ArtifactVerificationStatus.PURPOSE_MISMATCH,
                ArtifactVerificationStatus.SCHEME_UNSUPPORTED,
            },
        )

    def test_blank_signing_key_identifier_is_rejected(self):
        with self.assertRaises(ValueError):
            SigningKeyId("  ")

    def test_valid_policy_bundle_signature_verifies(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:policy")
        bundle = _policy_bundle()
        attestation = sign_artifact(
            bundle,
            private_key,
            key_id,
            ArtifactPurpose.POLICY_BUNDLE,
        )
        store = TrustStore(
            (
                _trusted_key(
                    private_key,
                    key_id,
                    (ArtifactPurpose.POLICY_BUNDLE,),
                ),
            )
        )

        result = verify_artifact(
            bundle,
            attestation,
            store,
            ArtifactPurpose.POLICY_BUNDLE,
        )

        self.assertIs(result.status, ArtifactVerificationStatus.VERIFIED)
        self.assertEqual(result.artifact_digest, sha256_digest(bundle))
        self.assertEqual(result.attestation.key_id, key_id)

    def test_tampered_policy_bundle_is_digest_mismatch(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:policy")
        original = _policy_bundle("policy:original")
        changed = _policy_bundle("policy:changed")
        attestation = sign_artifact(
            original,
            private_key,
            key_id,
            ArtifactPurpose.POLICY_BUNDLE,
        )
        store = TrustStore(
            (
                _trusted_key(
                    private_key,
                    key_id,
                    (ArtifactPurpose.POLICY_BUNDLE,),
                ),
            )
        )

        result = verify_artifact(
            changed,
            attestation,
            store,
            ArtifactPurpose.POLICY_BUNDLE,
        )

        self.assertIs(
            result.status,
            ArtifactVerificationStatus.DIGEST_MISMATCH,
        )

    def test_unknown_key_is_not_trusted(self):
        private_key = Ed25519PrivateKey.generate()
        bundle = _policy_bundle()
        attestation = sign_artifact(
            bundle,
            private_key,
            SigningKeyId("key:mallory"),
            ArtifactPurpose.POLICY_BUNDLE,
        )

        result = verify_artifact(
            bundle,
            attestation,
            TrustStore(),
            ArtifactPurpose.POLICY_BUNDLE,
        )

        self.assertIs(result.status, ArtifactVerificationStatus.UNKNOWN_KEY)

    def test_known_key_with_wrong_purpose_is_not_authorized(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:known")
        bundle = _policy_bundle()
        attestation = sign_artifact(
            bundle,
            private_key,
            key_id,
            ArtifactPurpose.POLICY_BUNDLE,
        )
        store = TrustStore(
            (
                _trusted_key(
                    private_key,
                    key_id,
                    (ArtifactPurpose.AUTHORITY_GRANT,),
                ),
            )
        )

        result = verify_artifact(
            bundle,
            attestation,
            store,
            ArtifactPurpose.POLICY_BUNDLE,
        )

        self.assertIs(
            result.status,
            ArtifactVerificationStatus.KEY_NOT_TRUSTED_FOR_PURPOSE,
        )

    def test_policy_key_cannot_authenticate_authority_grant(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:policy-only")
        grant = _authority_grant()
        attestation = sign_artifact(
            grant,
            private_key,
            key_id,
            ArtifactPurpose.AUTHORITY_GRANT,
        )
        store = TrustStore(
            (
                _trusted_key(
                    private_key,
                    key_id,
                    (ArtifactPurpose.POLICY_BUNDLE,),
                ),
            )
        )

        result = verify_artifact(
            grant,
            attestation,
            store,
            ArtifactPurpose.AUTHORITY_GRANT,
        )

        self.assertIs(
            result.status,
            ArtifactVerificationStatus.KEY_NOT_TRUSTED_FOR_PURPOSE,
        )

    def test_authority_key_cannot_authenticate_policy_bundle(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:authority-only")
        bundle = _policy_bundle()
        attestation = sign_artifact(
            bundle,
            private_key,
            key_id,
            ArtifactPurpose.POLICY_BUNDLE,
        )
        store = TrustStore(
            (
                _trusted_key(
                    private_key,
                    key_id,
                    (ArtifactPurpose.AUTHORITY_GRANT,),
                ),
            )
        )

        result = verify_artifact(
            bundle,
            attestation,
            store,
            ArtifactPurpose.POLICY_BUNDLE,
        )

        self.assertIs(
            result.status,
            ArtifactVerificationStatus.KEY_NOT_TRUSTED_FOR_PURPOSE,
        )

    def test_wrong_artifact_kind_fails_before_signature_reuse(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:policy")
        bundle = _policy_bundle()
        attestation = sign_artifact(
            bundle,
            private_key,
            key_id,
            ArtifactPurpose.POLICY_BUNDLE,
        )
        store = TrustStore(
            (
                _trusted_key(
                    private_key,
                    key_id,
                    (
                        ArtifactPurpose.POLICY_BUNDLE,
                        ArtifactPurpose.AUTHORITY_GRANT,
                    ),
                ),
            )
        )

        result = verify_artifact(
            _authority_grant(),
            attestation,
            store,
            ArtifactPurpose.AUTHORITY_GRANT,
        )

        self.assertIs(
            result.status,
            ArtifactVerificationStatus.ARTIFACT_KIND_MISMATCH,
        )

    def test_malformed_public_key_is_rejected(self):
        for value in (b"", b"x" * 31, b"x" * 33):
            with self.subTest(length=len(value)):
                with self.assertRaisesRegex(ValueError, "exactly 32 bytes"):
                    Ed25519PublicKey(value)
        with self.assertRaises(TypeError):
            Ed25519PublicKey(bytearray(32))

    def test_malformed_signature_is_rejected(self):
        for value in (b"", b"x" * 63, b"x" * 65):
            with self.subTest(length=len(value)):
                with self.assertRaisesRegex(ValueError, "exactly 64 bytes"):
                    ArtifactSignature(value)
        with self.assertRaises(TypeError):
            ArtifactSignature(bytearray(64))

    def test_duplicate_trust_store_key_id_is_rejected(self):
        first = Ed25519PrivateKey.generate()
        second = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:duplicate")

        with self.assertRaisesRegex(ValueError, "duplicate key"):
            TrustStore(
                (
                    _trusted_key(
                        first,
                        key_id,
                        (ArtifactPurpose.POLICY_BUNDLE,),
                    ),
                    _trusted_key(
                        second,
                        key_id,
                        (ArtifactPurpose.AUTHORITY_GRANT,),
                    ),
                )
            )

    def test_valid_decision_receipt_attestation_verifies(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:receipt")
        receipt = _approval_values()["receipt"]
        attestation = sign_artifact(
            receipt,
            private_key,
            key_id,
            ArtifactPurpose.DECISION_RECEIPT,
        )
        store = TrustStore(
            (
                _trusted_key(
                    private_key,
                    key_id,
                    (ArtifactPurpose.DECISION_RECEIPT,),
                ),
            )
        )

        result = verify_artifact(
            receipt,
            attestation,
            store,
            ArtifactPurpose.DECISION_RECEIPT,
        )

        self.assertIs(result.status, ArtifactVerificationStatus.VERIFIED)

    def test_valid_execution_permit_attestation_verifies(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:execution")
        permit = _execution_permit(_approval_values())
        attestation = sign_artifact(
            permit,
            private_key,
            key_id,
            ArtifactPurpose.EXECUTION_PERMIT,
        )
        store = TrustStore(
            (
                _trusted_key(
                    private_key,
                    key_id,
                    (ArtifactPurpose.EXECUTION_PERMIT,),
                ),
            )
        )

        result = verify_artifact(
            permit,
            attestation,
            store,
            ArtifactPurpose.EXECUTION_PERMIT,
        )

        self.assertIs(result.status, ArtifactVerificationStatus.VERIFIED)

    def test_changing_receipt_content_invalidates_old_attestation(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:receipt")
        original = _approval_values(amount=1)["receipt"]
        changed = _approval_values(amount=2)["receipt"]
        attestation = sign_artifact(
            original,
            private_key,
            key_id,
            ArtifactPurpose.DECISION_RECEIPT,
        )
        store = TrustStore(
            (
                _trusted_key(
                    private_key,
                    key_id,
                    (ArtifactPurpose.DECISION_RECEIPT,),
                ),
            )
        )

        result = verify_artifact(
            changed,
            attestation,
            store,
            ArtifactPurpose.DECISION_RECEIPT,
        )

        self.assertIs(
            result.status,
            ArtifactVerificationStatus.DIGEST_MISMATCH,
        )

    def test_changing_execution_permit_invalidates_old_attestation(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:execution")
        values = _approval_values()
        original = _execution_permit(values, logical_time=10)
        changed = _execution_permit(values, logical_time=11)
        attestation = sign_artifact(
            original,
            private_key,
            key_id,
            ArtifactPurpose.EXECUTION_PERMIT,
        )
        store = TrustStore(
            (
                _trusted_key(
                    private_key,
                    key_id,
                    (ArtifactPurpose.EXECUTION_PERMIT,),
                ),
            )
        )

        result = verify_artifact(
            changed,
            attestation,
            store,
            ArtifactPurpose.EXECUTION_PERMIT,
        )

        self.assertNotEqual(sha256_digest(original), sha256_digest(changed))
        self.assertIs(
            result.status,
            ArtifactVerificationStatus.DIGEST_MISMATCH,
        )

    def test_same_semantic_artifact_produces_same_signing_message(self):
        first = _policy_bundle()
        second = PolicyBundle(tuple(reversed(first.policies)))

        self.assertEqual(first, second)
        self.assertEqual(
            artifact_signing_message(first, ArtifactPurpose.POLICY_BUNDLE),
            artifact_signing_message(second, ArtifactPurpose.POLICY_BUNDLE),
        )

    def test_signing_message_golden_vector_is_fixed(self):
        message = attestation_signing_message(
            SignatureScheme.ED25519,
            ArtifactPurpose.POLICY_BUNDLE,
            ArtifactKind.POLICY_BUNDLE,
            Sha256Digest(bytes(range(32))),
        )

        self.assertEqual(len(message), 109)
        self.assertEqual(message.hex(), _GOLDEN_MESSAGE_HEX)

    def test_python_hash_seed_does_not_change_signing_message(self):
        script = "\n".join(
            (
                "from nest_authz import *",
                "c = Condition('action', FieldReference(FieldNamespace.ACTION, 'name'), ConditionOperator.EQUALS, 'message.send')",
                "b = PolicyBundle((Policy('policy:messages', (Rule('rule:messages', RuleEffect.PERMIT, (c,)),)),))",
                "print(artifact_signing_message(b, ArtifactPurpose.POLICY_BUNDLE).hex())",
            )
        )
        outputs = []
        for seed in ("17", "987123"):
            environment = os.environ.copy()
            environment["PYTHONHASHSEED"] = seed
            completed = subprocess.run(
                [sys.executable, "-c", script],
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            )
            outputs.append(completed.stdout)

        self.assertEqual(outputs[0], outputs[1])

    def test_signature_invalid_is_distinct_from_digest_mismatch(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:policy")
        bundle = _policy_bundle()
        valid = sign_artifact(
            bundle,
            private_key,
            key_id,
            ArtifactPurpose.POLICY_BUNDLE,
        )
        changed_bytes = bytearray(valid.signature.value)
        changed_bytes[0] ^= 1
        invalid = replace(
            valid,
            signature=ArtifactSignature(bytes(changed_bytes)),
        )
        store = TrustStore(
            (
                _trusted_key(
                    private_key,
                    key_id,
                    (ArtifactPurpose.POLICY_BUNDLE,),
                ),
            )
        )

        result = verify_artifact(
            bundle,
            invalid,
            store,
            ArtifactPurpose.POLICY_BUNDLE,
        )

        self.assertIs(
            result.status,
            ArtifactVerificationStatus.SIGNATURE_INVALID,
        )

    def test_purpose_mismatch_is_explicit(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:policy")
        bundle = _policy_bundle()
        valid = sign_artifact(
            bundle,
            private_key,
            key_id,
            ArtifactPurpose.POLICY_BUNDLE,
        )
        mismatched = replace(
            valid,
            purpose=ArtifactPurpose.AUTHORITY_GRANT,
        )

        result = verify_artifact(
            bundle,
            mismatched,
            TrustStore(),
            ArtifactPurpose.POLICY_BUNDLE,
        )

        self.assertIs(
            result.status,
            ArtifactVerificationStatus.PURPOSE_MISMATCH,
        )

    def test_only_explicit_artifact_allowlist_is_signable(self):
        with self.assertRaisesRegex(TypeError, "not supported"):
            sign_artifact(
                Subject("agent:1"),
                Ed25519PrivateKey.generate(),
                SigningKeyId("key:subject"),
                ArtifactPurpose.POLICY_BUNDLE,
            )

    def test_private_key_is_not_canonicalized_or_stored(self):
        private_key = Ed25519PrivateKey.generate()
        attestation = sign_artifact(
            _policy_bundle(),
            private_key,
            SigningKeyId("key:policy"),
            ArtifactPurpose.POLICY_BUNDLE,
        )

        with self.assertRaises(TypeError):
            canonical_bytes(private_key)
        self.assertFalse(hasattr(attestation, "private_key"))

    def test_trust_store_order_is_nonsemantic_and_copied(self):
        first_private = Ed25519PrivateKey.generate()
        second_private = Ed25519PrivateKey.generate()
        first = _trusted_key(
            first_private,
            SigningKeyId("key:a"),
            (ArtifactPurpose.POLICY_BUNDLE,),
        )
        second = _trusted_key(
            second_private,
            SigningKeyId("key:b"),
            (
                ArtifactPurpose.EXECUTION_PERMIT,
                ArtifactPurpose.AUTHORITY_GRANT,
            ),
        )
        source = [second, first]
        left = TrustStore(source)
        right = TrustStore((first, second))
        source.append(first)

        self.assertEqual(left, right)
        self.assertEqual(left.trusted_keys, (first, second))
        self.assertEqual(
            second.allowed_purposes,
            (
                ArtifactPurpose.AUTHORITY_GRANT,
                ArtifactPurpose.EXECUTION_PERMIT,
            ),
        )
        self.assertEqual(canonical_bytes(left), canonical_bytes(right))


class TrustedPolicyIntegrationTests(unittest.TestCase):
    def test_verified_policy_produces_trusted_wrapper(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:policy")
        bundle = _policy_bundle()
        attestation = sign_artifact(
            bundle,
            private_key,
            key_id,
            ArtifactPurpose.POLICY_BUNDLE,
        )
        store = TrustStore(
            (
                _trusted_key(
                    private_key,
                    key_id,
                    (ArtifactPurpose.POLICY_BUNDLE,),
                ),
            )
        )

        trusted = verify_policy_bundle(bundle, attestation, store)

        self.assertIsInstance(trusted, TrustedPolicyBundle)
        self.assertEqual(trusted.bundle, bundle)
        self.assertIs(
            trusted.verification.status,
            ArtifactVerificationStatus.VERIFIED,
        )

    def test_trusted_policy_wrapper_cannot_be_ordinarily_fabricated(self):
        with self.assertRaisesRegex(TypeError, "created by verification"):
            TrustedPolicyBundle()

    def test_self_signed_attacker_policy_is_rejected(self):
        mallory_key = Ed25519PrivateKey.generate()
        bundle = _policy_bundle("policy:mallory-permit")
        attestation = sign_artifact(
            bundle,
            mallory_key,
            SigningKeyId("key:mallory"),
            ArtifactPurpose.POLICY_BUNDLE,
        )

        result = verify_artifact(
            bundle,
            attestation,
            TrustStore(),
            ArtifactPurpose.POLICY_BUNDLE,
        )

        self.assertIs(result.status, ArtifactVerificationStatus.UNKNOWN_KEY)
        with self.assertRaises(ArtifactVerificationError) as caught:
            verify_policy_bundle(bundle, attestation, TrustStore())
        self.assertEqual(caught.exception.result, result)

    def test_valid_signature_is_insufficient_for_wrong_key_purpose(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:authority")
        bundle = _policy_bundle("policy:malicious-permit")
        attestation = sign_artifact(
            bundle,
            private_key,
            key_id,
            ArtifactPurpose.POLICY_BUNDLE,
        )
        message = artifact_signing_message(
            bundle,
            ArtifactPurpose.POLICY_BUNDLE,
        )
        private_key.public_key().verify(attestation.signature.value, message)
        store = TrustStore(
            (
                _trusted_key(
                    private_key,
                    key_id,
                    (ArtifactPurpose.AUTHORITY_GRANT,),
                ),
            )
        )

        result = verify_artifact(
            bundle,
            attestation,
            store,
            ArtifactPurpose.POLICY_BUNDLE,
        )

        self.assertIs(
            result.status,
            ArtifactVerificationStatus.KEY_NOT_TRUSTED_FOR_PURPOSE,
        )
        with self.assertRaises(ArtifactVerificationError):
            verify_policy_bundle(bundle, attestation, store)

    def test_signature_for_artifact_a_cannot_authenticate_artifact_b(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:policy")
        first = _policy_bundle("policy:a")
        second = _policy_bundle("policy:b")
        attestation = sign_artifact(
            first,
            private_key,
            key_id,
            ArtifactPurpose.POLICY_BUNDLE,
        )
        store = TrustStore(
            (
                _trusted_key(
                    private_key,
                    key_id,
                    (ArtifactPurpose.POLICY_BUNDLE,),
                ),
            )
        )

        result = verify_artifact(
            second,
            attestation,
            store,
            ArtifactPurpose.POLICY_BUNDLE,
        )

        self.assertIs(
            result.status,
            ArtifactVerificationStatus.DIGEST_MISMATCH,
        )

    def test_cross_kind_replay_changes_the_signed_message(self):
        private_key = Ed25519PrivateKey.generate()
        bundle = _policy_bundle()
        attestation = sign_artifact(
            bundle,
            private_key,
            SigningKeyId("key:policy"),
            ArtifactPurpose.POLICY_BUNDLE,
        )
        replay = replace(
            attestation,
            artifact_kind=ArtifactKind.AUTHORITY_GRANT,
        )
        original_message = attestation_signing_message(
            replay.scheme,
            replay.purpose,
            ArtifactKind.POLICY_BUNDLE,
            replay.artifact_digest,
        )
        replay_message = attestation_signing_message(
            replay.scheme,
            replay.purpose,
            replay.artifact_kind,
            replay.artifact_digest,
        )

        self.assertNotEqual(original_message, replay_message)
        with self.assertRaises(InvalidSignature):
            private_key.public_key().verify(
                replay.signature.value,
                replay_message,
            )
        result = verify_artifact(
            bundle,
            replay,
            TrustStore(),
            ArtifactPurpose.POLICY_BUNDLE,
        )
        self.assertIs(
            result.status,
            ArtifactVerificationStatus.ARTIFACT_KIND_MISMATCH,
        )

    def test_new_public_records_have_stable_canonical_schemas(self):
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:policy")
        bundle = _policy_bundle()
        trusted_key = _trusted_key(
            private_key,
            key_id,
            (ArtifactPurpose.POLICY_BUNDLE,),
        )
        store = TrustStore((trusted_key,))
        attestation = sign_artifact(
            bundle,
            private_key,
            key_id,
            ArtifactPurpose.POLICY_BUNDLE,
        )
        verification = verify_artifact(
            bundle,
            attestation,
            store,
            ArtifactPurpose.POLICY_BUNDLE,
        )
        trusted = verify_policy_bundle(bundle, attestation, store)
        values_and_schemas = (
            (key_id, b"nest-authz/signing-key-id@1"),
            (trusted_key.public_key, b"nest-authz/ed25519-public-key@1"),
            (attestation.signature, b"nest-authz/artifact-signature@1"),
            (attestation.scheme, b"nest-authz/signature-scheme@1"),
            (attestation.purpose, b"nest-authz/artifact-purpose@1"),
            (attestation.artifact_kind, b"nest-authz/artifact-kind@1"),
            (trusted_key, b"nest-authz/trusted-key@1"),
            (store, b"nest-authz/trust-store@1"),
            (attestation, b"nest-authz/artifact-attestation@1"),
            (
                verification.status,
                b"nest-authz/artifact-verification-status@1",
            ),
            (
                verification,
                b"nest-authz/artifact-verification-result@1",
            ),
            (trusted, b"nest-authz/trusted-policy-bundle@1"),
        )

        for value, schema in values_and_schemas:
            with self.subTest(schema=schema):
                self.assertIn(schema, canonical_bytes(value))
                self.assertEqual(canonical_bytes(value), canonical_bytes(value))
                self.assertEqual(sha256_digest(value), sha256_digest(value))

    def test_verification_reads_no_clock_network_filesystem_or_environment(self):
        module = importlib.import_module("nest_authz.attestation")
        tree = ast.parse(inspect.getsource(module))
        prohibited_import_roots = {
            "datetime",
            "os",
            "pathlib",
            "random",
            "secrets",
            "socket",
            "sqlite3",
            "subprocess",
            "time",
            "urllib",
            "uuid",
        }
        imported_roots = set()
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.split(".", maxsplit=1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                imported_roots.add((node.module or "").split(".", maxsplit=1)[0])
            elif isinstance(node, ast.Name):
                names.add(node.id)

        self.assertTrue(prohibited_import_roots.isdisjoint(imported_roots))
        self.assertNotIn("open", names)


if __name__ == "__main__":
    unittest.main()
