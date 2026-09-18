import ast
import inspect
import os
import subprocess
import sys
import textwrap
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import nest_authz.authenticated_delegation as authentication_module
import nest_authz.trusted as trusted_module
from nest_authz import (
    Action,
    ApprovalRequirement,
    ApproverSubjectPrincipalBinding,
    ArtifactKind,
    ArtifactPurpose,
    ArtifactSignature,
    ArtifactVerificationError,
    AuthorityGrant,
    AuthorityScope,
    AuthorizationRequest,
    AuthorizationState,
    Condition,
    ConditionOperator,
    DelegationAuthenticationStatus,
    DelegationChain,
    Ed25519PublicKey,
    FieldNamespace,
    FieldReference,
    GrantAttestation,
    GrantAttestationSet,
    Outcome,
    Policy,
    PolicyBundle,
    Principal,
    PrincipalKeyBinding,
    PrincipalKeyRegistry,
    RequestContext,
    Resource,
    RevocationSet,
    Rule,
    RuleEffect,
    SigningKeyId,
    Subject,
    SubjectPrincipalBinding,
    TrustedAuthorityRoots,
    TrustedExecutionAuthorizationStatus,
    TrustedKey,
    TrustStore,
    approve_requirement,
    authenticate_delegation_chain,
    authorize_trusted,
    canonical_bytes,
    check_approver_authorization,
    create_decision_receipt,
    create_pending_approval,
    revalidate_trusted_for_execution,
    sha256_digest,
    sign_artifact,
    validate_authority,
    verify_policy_bundle,
)

_ALICE = "principal:alice"
_AGENT_A = "principal:agent-a"
_AGENT_B = "principal:agent-b"
_AGENT_C = "principal:agent-c"
_MALLORY = "principal:mallory"


def _scope(max_amount=5000, *, action="payments.transfer", resource="account:alice"):
    return AuthorityScope(
        Action(action),
        Resource(resource),
        (("amount", max_amount),),
    )


def _grant(
    identifier,
    grantor,
    grantee,
    *,
    parent=None,
    max_amount=5000,
    action="payments.transfer",
    resource="account:alice",
    valid_from=0,
    valid_until=200,
):
    return AuthorityGrant(
        identifier,
        Principal(grantor),
        Principal(grantee),
        _scope(max_amount, action=action, resource=resource),
        parent,
        valid_from,
        valid_until,
    )


def _root_chain():
    return DelegationChain((_grant("grant:g1", _ALICE, _AGENT_A),))


def _one_hop_chain(*, child_amount=1000):
    root = _grant("grant:g1", _ALICE, _AGENT_A)
    child = _grant(
        "grant:g2",
        _AGENT_A,
        _AGENT_B,
        parent=root.identifier,
        max_amount=child_amount,
    )
    return DelegationChain((root, child))


def _multi_hop_chain():
    root = _grant("grant:g1", _ALICE, _AGENT_A)
    child = _grant(
        "grant:g2",
        _AGENT_A,
        _AGENT_B,
        parent=root.identifier,
        max_amount=2000,
    )
    leaf = _grant(
        "grant:g3",
        _AGENT_B,
        _AGENT_C,
        parent=child.identifier,
        max_amount=500,
    )
    return DelegationChain((root, child, leaf))


def _public_key(private_key):
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return Ed25519PublicKey(raw)


class _KeyMaterial:
    def __init__(self):
        self.private_keys = {
            principal: Ed25519PrivateKey.generate()
            for principal in (_ALICE, _AGENT_A, _AGENT_B, _AGENT_C, _MALLORY)
        }
        self.key_ids = {
            principal: SigningKeyId("key:" + principal.split(":", 1)[1])
            for principal in self.private_keys
        }

    def binding(self, principal):
        return PrincipalKeyBinding(
            Principal(principal),
            self.key_ids[principal],
        )

    def registry(self, principals=None):
        selected = principals or tuple(self.private_keys)
        return PrincipalKeyRegistry(tuple(self.binding(item) for item in selected))

    def trusted_key(self, principal, purposes=(ArtifactPurpose.AUTHORITY_GRANT,)):
        return TrustedKey(
            self.key_ids[principal],
            _public_key(self.private_keys[principal]),
            purposes,
        )

    def store(self, principals=None, *, purposes=None):
        selected = principals or tuple(self.private_keys)
        return TrustStore(
            tuple(
                self.trusted_key(
                    principal,
                    purposes
                    if purposes is not None
                    else (ArtifactPurpose.AUTHORITY_GRANT,),
                )
                for principal in selected
            )
        )

    def attestations(self, chain, signer_overrides=None, artifacts=None):
        signer_overrides = signer_overrides or {}
        artifacts = artifacts or {}
        return GrantAttestationSet(
            tuple(
                GrantAttestation(
                    grant.identifier,
                    sign_artifact(
                        artifacts.get(grant.identifier, grant),
                        self.private_keys[
                            signer_overrides.get(
                                grant.identifier,
                                grant.grantor.identifier,
                            )
                        ],
                        self.key_ids[
                            signer_overrides.get(
                                grant.identifier,
                                grant.grantor.identifier,
                            )
                        ],
                        ArtifactPurpose.AUTHORITY_GRANT,
                    ),
                )
                for grant in chain.grants
            )
        )


def _authenticate(
    chain,
    keys,
    *,
    state=None,
    attestations=None,
    store=None,
    registry=None,
    roots=None,
):
    return authenticate_delegation_chain(
        chain,
        state or AuthorizationState(100),
        attestations or keys.attestations(chain),
        store or keys.store(),
        registry or keys.registry(),
        roots or TrustedAuthorityRoots((Principal(_ALICE),)),
    )


def _policy_bundle(effect=RuleEffect.PERMIT, identifier="policy:transfers"):
    requirement = ApprovalRequirement(
        "MANAGER_APPROVAL",
        (Principal("principal:approver"),),
    )
    return PolicyBundle(
        (
            Policy(
                identifier,
                (
                    Rule(
                        "rule:transfer",
                        effect,
                        (
                            Condition(
                                "action_is_transfer",
                                FieldReference(FieldNamespace.ACTION, "name"),
                                ConditionOperator.EQUALS,
                                "payments.transfer",
                            ),
                        ),
                        approval_requirements=(
                            (requirement,)
                            if effect is RuleEffect.APPROVAL_REQUIRED
                            else ()
                        ),
                    ),
                ),
            ),
        )
    )


def _trusted_policy(bundle):
    private_key = Ed25519PrivateKey.generate()
    key_id = SigningKeyId("key:policy")
    attestation = sign_artifact(
        bundle,
        private_key,
        key_id,
        ArtifactPurpose.POLICY_BUNDLE,
    )
    store = TrustStore(
        (
            TrustedKey(
                key_id,
                _public_key(private_key),
                (ArtifactPurpose.POLICY_BUNDLE,),
            ),
        )
    )
    return verify_policy_bundle(bundle, attestation, store)


def _request(subject="agent:b", amount=500):
    return AuthorizationRequest(
        Subject(subject),
        Action("payments.transfer"),
        Resource("account:alice"),
        RequestContext((("amount", amount),)),
        None,
    )


class AuthenticatedDelegationTests(unittest.TestCase):
    def assert_status(self, result, expected, offending=None):
        self.assertIs(result.status, expected)
        self.assertEqual(result.offending_grant_id, offending)
        if expected is DelegationAuthenticationStatus.AUTHENTICATED:
            self.assertIsNotNone(result.authenticated_authority)
        else:
            self.assertIsNone(result.authenticated_authority)

    def test_01_trusted_root_single_grant_authenticates(self):
        keys = _KeyMaterial()
        result = _authenticate(_root_chain(), keys)
        self.assert_status(result, DelegationAuthenticationStatus.AUTHENTICATED)
        self.assertEqual(
            result.authenticated_authority.verified_authority.grant_id, "grant:g1"
        )
        self.assertTrue(result.grant_evidence[0].root_principal_trusted)

    def test_02_valid_signed_one_hop_delegation_authenticates(self):
        keys = _KeyMaterial()
        result = _authenticate(_one_hop_chain(), keys)
        self.assert_status(result, DelegationAuthenticationStatus.AUTHENTICATED)
        self.assertEqual(
            tuple(item.status for item in result.grant_evidence),
            (DelegationAuthenticationStatus.AUTHENTICATED,) * 2,
        )

    def test_03_valid_signed_multi_hop_delegation_authenticates(self):
        keys = _KeyMaterial()
        result = _authenticate(_multi_hop_chain(), keys)
        self.assert_status(result, DelegationAuthenticationStatus.AUTHENTICATED)
        self.assertEqual(
            result.authenticated_authority.verified_authority.principal,
            Principal(_AGENT_C),
        )

    def test_04_root_signed_by_key_bound_to_wrong_principal_fails(self):
        keys = _KeyMaterial()
        chain = _root_chain()
        attestations = keys.attestations(chain, {"grant:g1": _MALLORY})
        result = _authenticate(chain, keys, attestations=attestations)
        self.assert_status(
            result,
            DelegationAuthenticationStatus.SIGNER_KEY_NOT_BOUND_TO_GRANTOR,
            "grant:g1",
        )
        self.assertEqual(result.grant_evidence[0].bound_principal, Principal(_MALLORY))

    def test_05_child_signed_by_key_bound_to_wrong_principal_fails(self):
        keys = _KeyMaterial()
        chain = _one_hop_chain()
        attestations = keys.attestations(chain, {"grant:g2": _AGENT_B})
        result = _authenticate(chain, keys, attestations=attestations)
        self.assert_status(
            result,
            DelegationAuthenticationStatus.SIGNER_KEY_NOT_BOUND_TO_GRANTOR,
            "grant:g2",
        )

    def test_06_unknown_signing_key_fails(self):
        keys = _KeyMaterial()
        chain = _root_chain()
        result = _authenticate(
            chain,
            keys,
            store=TrustStore(),
        )
        self.assert_status(
            result,
            DelegationAuthenticationStatus.UNKNOWN_SIGNING_KEY,
            "grant:g1",
        )

    def test_07_known_key_with_wrong_trust_purpose_fails(self):
        keys = _KeyMaterial()
        chain = _root_chain()
        store = keys.store((_ALICE,), purposes=(ArtifactPurpose.POLICY_BUNDLE,))
        result = _authenticate(chain, keys, store=store)
        self.assert_status(
            result,
            DelegationAuthenticationStatus.KEY_NOT_TRUSTED_FOR_AUTHORITY_GRANT,
            "grant:g1",
        )

    def test_08_missing_root_attestation_fails(self):
        keys = _KeyMaterial()
        result = _authenticate(
            _root_chain(),
            keys,
            attestations=GrantAttestationSet(),
        )
        self.assert_status(
            result,
            DelegationAuthenticationStatus.MISSING_ATTESTATION,
            "grant:g1",
        )

    def test_09_missing_child_attestation_fails(self):
        keys = _KeyMaterial()
        chain = _one_hop_chain()
        root_entry = keys.attestations(chain).entries[0]
        result = _authenticate(
            chain,
            keys,
            attestations=GrantAttestationSet((root_entry,)),
        )
        self.assert_status(
            result,
            DelegationAuthenticationStatus.MISSING_ATTESTATION,
            "grant:g2",
        )

    def test_10_tampered_grant_fails_attestation_verification(self):
        keys = _KeyMaterial()
        original = _root_chain()
        attestations = keys.attestations(original)
        tampered = DelegationChain((replace(original.grants[0], scope=_scope(4000)),))
        result = _authenticate(tampered, keys, attestations=attestations)
        self.assert_status(
            result,
            DelegationAuthenticationStatus.GRANT_ARTIFACT_MISMATCH,
            "grant:g1",
        )

    def test_11_wrong_artifact_kind_attestation_fails(self):
        keys = _KeyMaterial()
        chain = _root_chain()
        entry = keys.attestations(chain).entries[0]
        wrong = replace(entry.attestation, artifact_kind=ArtifactKind.POLICY_BUNDLE)
        result = _authenticate(
            chain,
            keys,
            attestations=GrantAttestationSet((GrantAttestation("grant:g1", wrong),)),
        )
        self.assert_status(
            result,
            DelegationAuthenticationStatus.GRANT_ARTIFACT_MISMATCH,
            "grant:g1",
        )

    def test_12_untrusted_root_principal_fails(self):
        keys = _KeyMaterial()
        result = _authenticate(
            _root_chain(),
            keys,
            roots=TrustedAuthorityRoots((Principal(_AGENT_A),)),
        )
        self.assert_status(
            result,
            DelegationAuthenticationStatus.UNTRUSTED_ROOT_PRINCIPAL,
            "grant:g1",
        )

    def test_13_child_principal_cannot_originate_unrelated_root(self):
        keys = _KeyMaterial()
        chain = DelegationChain((_grant("grant:new-root", _AGENT_B, _AGENT_C),))
        result = _authenticate(chain, keys)
        self.assert_status(
            result,
            DelegationAuthenticationStatus.UNTRUSTED_ROOT_PRINCIPAL,
            "grant:new-root",
        )

    def test_14_structural_invalidity_cannot_be_rescued_by_signatures(self):
        keys = _KeyMaterial()
        root = _grant("grant:g1", _ALICE, _AGENT_A)
        child = _grant(
            "grant:g2", _AGENT_B, _AGENT_C, parent="grant:g1", max_amount=1000
        )
        chain = DelegationChain((root, child))
        result = _authenticate(chain, keys)
        self.assert_status(
            result,
            DelegationAuthenticationStatus.STRUCTURAL_AUTHORITY_INVALID,
            "grant:g2",
        )

    def test_15_widened_child_scope_fails_despite_valid_signatures(self):
        keys = _KeyMaterial()
        chain = _one_hop_chain(child_amount=10000)
        result = _authenticate(chain, keys)
        self.assert_status(
            result,
            DelegationAuthenticationStatus.STRUCTURAL_AUTHORITY_INVALID,
            "grant:g2",
        )

    def test_16_revoked_parent_fails_despite_valid_signatures(self):
        keys = _KeyMaterial()
        result = _authenticate(
            _one_hop_chain(),
            keys,
            state=AuthorizationState(100, RevocationSet(("grant:g1",))),
        )
        self.assert_status(
            result,
            DelegationAuthenticationStatus.STRUCTURAL_AUTHORITY_INVALID,
            "grant:g1",
        )

    def test_17_expired_parent_fails_despite_valid_signatures(self):
        keys = _KeyMaterial()
        result = _authenticate(
            _one_hop_chain(),
            keys,
            state=AuthorizationState(200),
        )
        self.assert_status(
            result,
            DelegationAuthenticationStatus.STRUCTURAL_AUTHORITY_INVALID,
            "grant:g1",
        )

    def test_18_valid_mallory_signature_for_alice_grant_fails_binding(self):
        keys = _KeyMaterial()
        chain = _root_chain()
        result = _authenticate(
            chain,
            keys,
            attestations=keys.attestations(chain, {"grant:g1": _MALLORY}),
            store=keys.store((_MALLORY,)),
            registry=keys.registry((_MALLORY,)),
        )
        self.assert_status(
            result,
            DelegationAuthenticationStatus.SIGNER_KEY_NOT_BOUND_TO_GRANTOR,
            "grant:g1",
        )

    def test_19_agent_a_key_can_sign_agent_a_to_agent_b(self):
        keys = _KeyMaterial()
        result = _authenticate(_one_hop_chain(), keys)
        self.assertIs(
            result.grant_evidence[1].status,
            DelegationAuthenticationStatus.AUTHENTICATED,
        )
        self.assertEqual(result.grant_evidence[1].bound_principal, Principal(_AGENT_A))

    def test_20_agent_b_key_cannot_sign_agent_a_to_agent_b(self):
        keys = _KeyMaterial()
        chain = _one_hop_chain()
        result = _authenticate(
            chain,
            keys,
            attestations=keys.attestations(chain, {"grant:g2": _AGENT_B}),
        )
        self.assert_status(
            result,
            DelegationAuthenticationStatus.SIGNER_KEY_NOT_BOUND_TO_GRANTOR,
            "grant:g2",
        )

    def test_21_duplicate_and_conflicting_principal_key_bindings_rejected(self):
        keys = _KeyMaterial()
        alice = keys.binding(_ALICE)
        with self.assertRaises(ValueError):
            PrincipalKeyRegistry((alice, alice))
        with self.assertRaises(ValueError):
            PrincipalKeyRegistry(
                (alice, PrincipalKeyBinding(Principal(_ALICE), keys.key_ids[_AGENT_A]))
            )
        with self.assertRaises(ValueError):
            PrincipalKeyRegistry(
                (alice, PrincipalKeyBinding(Principal(_AGENT_A), keys.key_ids[_ALICE]))
            )

    def test_22_registry_and_root_order_do_not_change_canonical_identity(self):
        keys = _KeyMaterial()
        bindings = (
            keys.binding(_ALICE),
            keys.binding(_AGENT_A),
            keys.binding(_AGENT_B),
        )
        first = PrincipalKeyRegistry(bindings)
        second = PrincipalKeyRegistry(tuple(reversed(bindings)))
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(sha256_digest(first), sha256_digest(second))
        roots_a = TrustedAuthorityRoots((Principal(_ALICE), Principal(_AGENT_A)))
        roots_b = TrustedAuthorityRoots(tuple(reversed(roots_a.principals)))
        self.assertEqual(sha256_digest(roots_a), sha256_digest(roots_b))

    def test_23_repeated_authenticated_validation_is_equal(self):
        keys = _KeyMaterial()
        chain = _one_hop_chain()
        attestations = keys.attestations(chain)
        store = keys.store()
        registry = keys.registry()
        roots = TrustedAuthorityRoots((Principal(_ALICE),))
        first = _authenticate(
            chain,
            keys,
            attestations=attestations,
            store=store,
            registry=registry,
            roots=roots,
        )
        second = _authenticate(
            chain,
            keys,
            attestations=attestations,
            store=store,
            registry=registry,
            roots=roots,
        )
        self.assertEqual(first, second)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))

    def test_24_pythonhashseed_does_not_alter_authenticated_result(self):
        code = textwrap.dedent(
            """
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from nest_authz import *
            private = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
            key_id = SigningKeyId('key:alice')
            public = Ed25519PublicKey(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
            grant = AuthorityGrant('grant:g1', Principal('principal:alice'), Principal('principal:agent-a'), AuthorityScope(Action('payments.transfer'), Resource('account:alice'), (('amount', 5000),)), None, 0, 200)
            chain = DelegationChain((grant,))
            attestation = sign_artifact(grant, private, key_id, ArtifactPurpose.AUTHORITY_GRANT)
            result = authenticate_delegation_chain(chain, AuthorizationState(100), GrantAttestationSet((GrantAttestation('grant:g1', attestation),)), TrustStore((TrustedKey(key_id, public, (ArtifactPurpose.AUTHORITY_GRANT,)),)), PrincipalKeyRegistry((PrincipalKeyBinding(Principal('principal:alice'), key_id),)), TrustedAuthorityRoots((Principal('principal:alice'),)))
            print(result.status.value)
            print(canonical_bytes(result).hex())
            print(sha256_digest(result))
            """
        )
        outputs = []
        for seed in ("1", "987654"):
            environment = os.environ.copy()
            environment["PYTHONHASHSEED"] = seed
            outputs.append(
                subprocess.check_output(
                    [sys.executable, "-c", code],
                    env=environment,
                    text=True,
                )
            )
        self.assertEqual(outputs[0], outputs[1])
        self.assertTrue(outputs[0].startswith("AUTHENTICATED\n"))

    def test_25_trusted_entrypoint_rejects_raw_policy_bundle(self):
        keys = _KeyMaterial()
        authenticated = _authenticate(_one_hop_chain(), keys).authenticated_authority
        with self.assertRaises(TypeError):
            authorize_trusted(
                _request(),
                _policy_bundle(),
                authenticated,
                SubjectPrincipalBinding(Subject("agent:b"), Principal(_AGENT_B)),
            )

    def test_26_trusted_entrypoint_rejects_structurally_only_authority(self):
        chain = _one_hop_chain()
        verified = validate_authority(chain, AuthorizationState(100)).verified_authority
        with self.assertRaises(TypeError):
            authorize_trusted(
                _request(),
                _trusted_policy(_policy_bundle()),
                verified,
                SubjectPrincipalBinding(Subject("agent:b"), Principal(_AGENT_B)),
            )

    def test_27_trusted_entrypoint_accepts_both_trusted_wrappers(self):
        keys = _KeyMaterial()
        authenticated = _authenticate(_one_hop_chain(), keys).authenticated_authority
        request = _request()
        trusted_policy = _trusted_policy(_policy_bundle())
        result = authorize_trusted(
            request,
            trusted_policy,
            authenticated,
            SubjectPrincipalBinding(request.subject, Principal(_AGENT_B)),
        )
        self.assertIs(result.decision.outcome, Outcome.PERMIT)
        self.assertEqual(result.request_digest, sha256_digest(request))
        self.assertEqual(
            result.authenticated_authority_digest, sha256_digest(authenticated)
        )

    def test_28_self_signed_mallory_policy_cannot_enter_trusted_path(self):
        bundle = _policy_bundle()
        private_key = Ed25519PrivateKey.generate()
        key_id = SigningKeyId("key:mallory-policy")
        attestation = sign_artifact(
            bundle, private_key, key_id, ArtifactPurpose.POLICY_BUNDLE
        )
        with self.assertRaises(ArtifactVerificationError):
            verify_policy_bundle(bundle, attestation, TrustStore())

    def test_29_trusted_policy_plus_unauthenticated_delegation_cannot_permit(self):
        chain = _one_hop_chain()
        merely_valid = validate_authority(
            chain, AuthorizationState(100)
        ).verified_authority
        with self.assertRaises(TypeError):
            authorize_trusted(
                _request(),
                _trusted_policy(_policy_bundle()),
                merely_valid,
                SubjectPrincipalBinding(Subject("agent:b"), Principal(_AGENT_B)),
            )

    def test_30_trusted_delegation_plus_untrusted_policy_cannot_permit(self):
        keys = _KeyMaterial()
        authenticated = _authenticate(_one_hop_chain(), keys).authenticated_authority
        with self.assertRaises(TypeError):
            authorize_trusted(
                _request(),
                _policy_bundle(),
                authenticated,
                SubjectPrincipalBinding(Subject("agent:b"), Principal(_AGENT_B)),
            )

    def test_31_globally_trusted_mallory_key_cannot_sign_for_alice(self):
        keys = _KeyMaterial()
        chain = _root_chain()
        result = _authenticate(
            chain,
            keys,
            attestations=keys.attestations(chain, {"grant:g1": _MALLORY}),
            store=keys.store((_ALICE, _MALLORY)),
        )
        self.assert_status(
            result,
            DelegationAuthenticationStatus.SIGNER_KEY_NOT_BOUND_TO_GRANTOR,
            "grant:g1",
        )

    def test_32_agent_b_new_root_requires_explicit_root_trust(self):
        keys = _KeyMaterial()
        chain = DelegationChain((_grant("grant:b-root", _AGENT_B, _AGENT_C),))
        denied = _authenticate(chain, keys)
        allowed = _authenticate(
            chain,
            keys,
            roots=TrustedAuthorityRoots((Principal(_AGENT_B),)),
        )
        self.assert_status(
            denied,
            DelegationAuthenticationStatus.UNTRUSTED_ROOT_PRINCIPAL,
            "grant:b-root",
        )
        self.assert_status(allowed, DelegationAuthenticationStatus.AUTHENTICATED)

    def test_33_valid_signatures_do_not_rescue_multi_hop_scope_widening(self):
        keys = _KeyMaterial()
        root = _grant("grant:g1", _ALICE, _AGENT_A, max_amount=5000)
        child = _grant(
            "grant:g2", _AGENT_A, _AGENT_B, parent="grant:g1", max_amount=1000
        )
        leaf = _grant(
            "grant:g3", _AGENT_B, _AGENT_C, parent="grant:g2", max_amount=2000
        )
        chain = DelegationChain((root, child, leaf))
        result = _authenticate(chain, keys)
        self.assert_status(
            result,
            DelegationAuthenticationStatus.STRUCTURAL_AUTHORITY_INVALID,
            "grant:g3",
        )

    def test_34_replacing_signed_child_artifact_fails(self):
        keys = _KeyMaterial()
        original = _one_hop_chain()
        attestations = keys.attestations(original)
        replacement = replace(original.grants[1], scope=_scope(900))
        chain = DelegationChain((original.grants[0], replacement))
        result = _authenticate(chain, keys, attestations=attestations)
        self.assert_status(
            result, DelegationAuthenticationStatus.GRANT_ARTIFACT_MISMATCH, "grant:g2"
        )

    def test_35_attestation_collection_rejects_duplicates_and_unknown_entries(self):
        keys = _KeyMaterial()
        chain = _root_chain()
        entry = keys.attestations(chain).entries[0]
        with self.assertRaises(ValueError):
            GrantAttestationSet((entry, entry))
        unknown = GrantAttestation("grant:unknown", entry.attestation)
        result = _authenticate(
            chain, keys, attestations=GrantAttestationSet((entry, unknown))
        )
        self.assert_status(
            result,
            DelegationAuthenticationStatus.UNKNOWN_GRANT_ATTESTATION,
            "grant:unknown",
        )

    def test_36_factory_protected_authenticated_authority_cannot_be_fabricated(self):
        from nest_authz import AuthenticatedDelegatedAuthority

        with self.assertRaises(TypeError):
            AuthenticatedDelegatedAuthority()

    def test_37_grant_attestation_order_is_nonsemantic(self):
        keys = _KeyMaterial()
        chain = _one_hop_chain()
        entries = keys.attestations(chain).entries
        first = GrantAttestationSet(entries)
        second = GrantAttestationSet(tuple(reversed(entries)))
        self.assertEqual(first, second)
        self.assertEqual(sha256_digest(first), sha256_digest(second))

    def test_38_trusted_execution_revalidation_reauthenticates_current_chain(self):
        keys = _KeyMaterial()
        chain = _one_hop_chain()
        state = AuthorizationState(100)
        attestations = keys.attestations(chain)
        store = keys.store()
        registry = keys.registry()
        roots = TrustedAuthorityRoots((Principal(_ALICE),))
        authenticated = _authenticate(
            chain,
            keys,
            state=state,
            attestations=attestations,
            store=store,
            registry=registry,
            roots=roots,
        ).authenticated_authority
        request = _request()
        bundle = _policy_bundle(RuleEffect.APPROVAL_REQUIRED)
        trusted_policy = _trusted_policy(bundle)
        binding = SubjectPrincipalBinding(request.subject, Principal(_AGENT_B))
        trusted_decision = authorize_trusted(
            request, trusted_policy, authenticated, binding
        )
        receipt = create_decision_receipt(trusted_decision.decision)
        pending = create_pending_approval(receipt, 100)
        requirement = receipt.approval_requirements[0]
        actor = Subject("approver:manager")
        approval_authorization = check_approver_authorization(
            actor,
            ApproverSubjectPrincipalBinding(actor, Principal("principal:approver")),
            requirement,
            requirement,
        )
        approved = approve_requirement(
            pending, requirement, approval_authorization, 101
        )

        result = revalidate_trusted_for_execution(
            receipt,
            approved,
            request,
            trusted_policy,
            chain,
            AuthorizationState(110),
            binding,
            attestations,
            store,
            registry,
            roots,
        )

        self.assertIs(result.status, TrustedExecutionAuthorizationStatus.AUTHORIZED)
        self.assertIsNotNone(result.execution_permit)

    def test_39_trusted_execution_revalidation_rejects_current_revocation(self):
        keys = _KeyMaterial()
        chain = _one_hop_chain()
        state = AuthorizationState(100)
        attestations = keys.attestations(chain)
        store = keys.store()
        registry = keys.registry()
        roots = TrustedAuthorityRoots((Principal(_ALICE),))
        authenticated = _authenticate(
            chain,
            keys,
            state=state,
            attestations=attestations,
            store=store,
            registry=registry,
            roots=roots,
        ).authenticated_authority
        request = _request()
        bundle = _policy_bundle(RuleEffect.APPROVAL_REQUIRED)
        trusted_policy = _trusted_policy(bundle)
        binding = SubjectPrincipalBinding(request.subject, Principal(_AGENT_B))
        decision = authorize_trusted(
            request, trusted_policy, authenticated, binding
        ).decision
        receipt = create_decision_receipt(decision)
        pending = create_pending_approval(receipt, 100)
        requirement = receipt.approval_requirements[0]
        actor = Subject("approver:manager")
        authorization = check_approver_authorization(
            actor,
            ApproverSubjectPrincipalBinding(actor, Principal("principal:approver")),
            requirement,
            requirement,
        )
        approved = approve_requirement(pending, requirement, authorization, 101)
        result = revalidate_trusted_for_execution(
            receipt,
            approved,
            request,
            trusted_policy,
            chain,
            AuthorizationState(110, RevocationSet(("grant:g1",))),
            binding,
            attestations,
            store,
            registry,
            roots,
        )
        self.assertIs(
            result.status,
            TrustedExecutionAuthorizationStatus.DELEGATION_AUTHENTICATION_FAILED,
        )
        self.assertIsNone(result.execution_permit)

    def test_40_authentication_source_has_no_ambient_io_or_custom_crypto(self):
        forbidden_modules = {
            "datetime",
            "http",
            "os",
            "pathlib",
            "random",
            "requests",
            "secrets",
            "socket",
            "sqlite3",
            "time",
            "urllib",
        }
        forbidden_calls = {"open", "eval", "exec", "getattr"}
        for module in (authentication_module, trusted_module):
            tree = ast.parse(inspect.getsource(module))
            imports = {
                alias.name.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            }
            imports.update(
                node.module.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            )
            calls = {
                node.func.id
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            self.assertTrue(imports.isdisjoint(forbidden_modules))
            self.assertTrue(calls.isdisjoint(forbidden_calls))
            self.assertNotIn("Ed25519PrivateKey", inspect.getsource(module))

    def test_41_invalid_grant_signature_is_typed_attestation_failure(self):
        keys = _KeyMaterial()
        chain = _root_chain()
        entry = keys.attestations(chain).entries[0]
        invalid = replace(
            entry.attestation,
            signature=ArtifactSignature(b"\x00" * 64),
        )
        result = _authenticate(
            chain,
            keys,
            attestations=GrantAttestationSet((GrantAttestation("grant:g1", invalid),)),
        )
        self.assert_status(
            result,
            DelegationAuthenticationStatus.ATTESTATION_INVALID,
            "grant:g1",
        )


if __name__ == "__main__":
    unittest.main()
