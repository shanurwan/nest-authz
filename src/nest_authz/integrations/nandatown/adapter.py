"""Translation boundary between Nanda Town identities and NEST AuthZ.

This module contains no Nanda Town imports. Simulator registration and trace
emission live in :mod:`nest_authz.integrations.nandatown.plugin` so importing
the NEST AuthZ core never requires the simulator.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nest_authz import (
    Action,
    ApprovalRequirement,
    ArtifactPurpose,
    AuthenticatedDelegatedAuthority,
    AuthorityGrant,
    AuthorityScope,
    AuthorizationRequest,
    AuthorizationState,
    Condition,
    ConditionOperator,
    DelegationAuthenticationResult,
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
    Rule,
    RuleEffect,
    SigningKeyId,
    Subject,
    SubjectPrincipalBinding,
    TrustedAuthorityRoots,
    TrustedAuthorizationResult,
    TrustedKey,
    TrustedPolicyBundle,
    TrustStore,
    authenticate_delegation_chain,
    authorize_trusted,
    sign_artifact,
    verify_policy_bundle,
)

# TEST-ONLY / PUBLIC DEMO MATERIAL. These deterministic Ed25519 seeds are
# intentionally published so repeat scenario runs produce the same artifact
# identities. They provide no secrecy and MUST NEVER be reused operationally.
_DEMO_ONLY_POLICY_KEY_SEED = bytes.fromhex("11" * 32)
_DEMO_ONLY_ALICE_KEY_SEED = bytes.fromhex("22" * 32)
_DEMO_ONLY_FINANCE_KEY_SEED = bytes.fromhex("33" * 32)


def _nonblank(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be a string")
    value.encode("utf-8", errors="strict")
    if not value.strip():
        raise ValueError(f"{field_name} must not be blank")
    return value


def _public_key(private_key: Ed25519PrivateKey) -> Ed25519PublicKey:
    return Ed25519PublicKey(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )


@dataclass(frozen=True, slots=True)
class NandaAuthorityProfile:
    """Exact configured authority and holder binding for one Town agent."""

    identifier: str
    agent_name: str
    chain: DelegationChain
    grant_attestations: GrantAttestationSet
    subject_binding: SubjectPrincipalBinding

    def __post_init__(self) -> None:
        _nonblank(self.identifier, "authority profile identifier")
        _nonblank(self.agent_name, "Nanda Town agent name")
        if type(self.chain) is not DelegationChain:
            raise TypeError("chain must be a DelegationChain")
        if type(self.grant_attestations) is not GrantAttestationSet:
            raise TypeError("grant_attestations must be a GrantAttestationSet")
        if type(self.subject_binding) is not SubjectPrincipalBinding:
            raise TypeError("subject_binding must be a SubjectPrincipalBinding")


@dataclass(frozen=True, slots=True)
class NandaSecurityMaterial:
    """Immutable trusted inputs used by the deterministic demo adapter."""

    trusted_policy: TrustedPolicyBundle
    trust_store: TrustStore
    principal_key_registry: PrincipalKeyRegistry
    trusted_authority_roots: TrustedAuthorityRoots
    authority_profiles: tuple[NandaAuthorityProfile, ...]
    approval_requirement: ApprovalRequirement

    def __post_init__(self) -> None:
        if type(self.trusted_policy) is not TrustedPolicyBundle:
            raise TypeError("trusted_policy must be a TrustedPolicyBundle")
        if type(self.trust_store) is not TrustStore:
            raise TypeError("trust_store must be a TrustStore")
        if type(self.principal_key_registry) is not PrincipalKeyRegistry:
            raise TypeError("principal_key_registry must be a PrincipalKeyRegistry")
        if type(self.trusted_authority_roots) is not TrustedAuthorityRoots:
            raise TypeError("trusted_authority_roots must be TrustedAuthorityRoots")
        profiles = tuple(self.authority_profiles)
        if any(type(item) is not NandaAuthorityProfile for item in profiles):
            raise TypeError("authority_profiles must contain NandaAuthorityProfile")
        identifiers = tuple(item.identifier for item in profiles)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("authority profile identifiers must be unique")
        object.__setattr__(
            self,
            "authority_profiles",
            tuple(
                sorted(
                    profiles,
                    key=lambda item: item.identifier.encode("utf-8"),
                )
            ),
        )
        if type(self.approval_requirement) is not ApprovalRequirement:
            raise TypeError("approval_requirement must be an ApprovalRequirement")

    def profile(
        self,
        identifier: str,
        agent_name: str,
    ) -> NandaAuthorityProfile | None:
        """Resolve only an exact configured profile/agent pair."""

        for profile in self.authority_profiles:
            if profile.identifier == identifier and profile.agent_name == agent_name:
                return profile
        return None


@dataclass(frozen=True, slots=True)
class NandaAuthorizationResult:
    """Typed adapter result without weakening the trusted core result."""

    request: AuthorizationRequest
    outcome: Outcome
    status: str
    authority_profile: NandaAuthorityProfile | None
    delegation_authentication: DelegationAuthenticationResult | None
    authenticated_authority: AuthenticatedDelegatedAuthority | None
    trusted_authorization: TrustedAuthorizationResult | None

    def __post_init__(self) -> None:
        if type(self.request) is not AuthorizationRequest:
            raise TypeError("request must be an AuthorizationRequest")
        if type(self.outcome) is not Outcome:
            raise TypeError("outcome must be an Outcome")
        _nonblank(self.status, "adapter authorization status")
        if self.trusted_authorization is not None:
            if type(self.trusted_authorization) is not TrustedAuthorizationResult:
                raise TypeError(
                    "trusted_authorization must be a TrustedAuthorizationResult"
                )
            if self.outcome is not self.trusted_authorization.decision.outcome:
                raise ValueError(
                    "adapter outcome must equal the trusted decision outcome"
                )
        elif self.outcome is not Outcome.DENY:
            raise ValueError(
                "an adapter result without trusted authorization must deny"
            )


class NandaTownAuthorizationAdapter:
    """Translate Town inputs and invoke NEST's existing trusted path."""

    def __init__(self, material: NandaSecurityMaterial) -> None:
        if type(material) is not NandaSecurityMaterial:
            raise TypeError("material must be NandaSecurityMaterial")
        self.material = material

    def authorize_action(
        self,
        *,
        agent_name: str,
        authority_profile: str,
        action: str,
        resource: str,
        context: Mapping[str, str | int | bool | None],
        state: AuthorizationState,
    ) -> NandaAuthorizationResult:
        """Authorize one exact Town action through all NEST trust gates."""

        agent_name = _nonblank(agent_name, "Nanda Town agent name")
        authority_profile = _nonblank(
            authority_profile,
            "authority profile identifier",
        )
        if not isinstance(context, Mapping):
            raise TypeError("context must be a mapping")
        if type(state) is not AuthorizationState:
            raise TypeError("state must be an AuthorizationState")

        request = AuthorizationRequest(
            subject=Subject(f"agent:{agent_name}"),
            action=Action(action),
            resource=Resource(resource),
            context=RequestContext(tuple(context.items())),
            authority_context=None,
        )
        profile = self.material.profile(authority_profile, agent_name)
        if profile is None:
            return NandaAuthorizationResult(
                request=request,
                outcome=Outcome.DENY,
                status="AUTHORITY_PROFILE_NOT_CONFIGURED",
                authority_profile=None,
                delegation_authentication=None,
                authenticated_authority=None,
                trusted_authorization=None,
            )

        authentication = authenticate_delegation_chain(
            profile.chain,
            state,
            profile.grant_attestations,
            self.material.trust_store,
            self.material.principal_key_registry,
            self.material.trusted_authority_roots,
        )
        authenticated = authentication.authenticated_authority
        if (
            authentication.status is not DelegationAuthenticationStatus.AUTHENTICATED
            or authenticated is None
        ):
            return NandaAuthorizationResult(
                request=request,
                outcome=Outcome.DENY,
                status=authentication.status.value,
                authority_profile=profile,
                delegation_authentication=authentication,
                authenticated_authority=None,
                trusted_authorization=None,
            )

        trusted_result = authorize_trusted(
            request,
            self.material.trusted_policy,
            authenticated,
            profile.subject_binding,
        )
        return NandaAuthorizationResult(
            request=request,
            outcome=trusted_result.decision.outcome,
            status="TRUSTED_AUTHORIZATION_COMPLETE",
            authority_profile=profile,
            delegation_authentication=authentication,
            authenticated_authority=authenticated,
            trusted_authorization=trusted_result,
        )


def _policy_bundle(
    approval_requirement: ApprovalRequirement,
) -> PolicyBundle:
    action = FieldReference(FieldNamespace.ACTION, "name")
    resource = FieldReference(FieldNamespace.RESOURCE, "identifier")
    amount = FieldReference(FieldNamespace.CONTEXT, "amount")
    permit = Rule(
        "rule:permit-up-to-1000",
        RuleEffect.PERMIT,
        (
            Condition(
                "permit:action",
                action,
                ConditionOperator.EQUALS,
                "payments.transfer",
            ),
            Condition(
                "permit:resource",
                resource,
                ConditionOperator.EQUALS,
                "account:alice",
            ),
            Condition(
                "permit:amount",
                amount,
                ConditionOperator.INTEGER_LESS_THAN_OR_EQUAL,
                1000,
            ),
        ),
    )
    approval = Rule(
        "rule:approval-over-1000",
        RuleEffect.APPROVAL_REQUIRED,
        (
            Condition(
                "approval:action",
                action,
                ConditionOperator.EQUALS,
                "payments.transfer",
            ),
            Condition(
                "approval:resource",
                resource,
                ConditionOperator.EQUALS,
                "account:alice",
            ),
            Condition(
                "approval:amount",
                amount,
                ConditionOperator.INTEGER_GREATER_THAN,
                1000,
            ),
        ),
        approval_requirements=(approval_requirement,),
    )
    return PolicyBundle((Policy("policy:nandatown-transfers", (permit, approval)),))


def build_demo_security_material() -> NandaSecurityMaterial:
    """Build deterministic, public, test-only security fixtures."""

    alice = Principal("principal:alice")
    finance = Principal("principal:finance-agent")
    payment_subagent = Principal("principal:payment-subagent")
    manager = Principal("principal:authorized-manager")

    approval_requirement = ApprovalRequirement(
        "MANAGER_APPROVAL",
        (manager,),
    )
    bundle = _policy_bundle(approval_requirement)

    policy_private = Ed25519PrivateKey.from_private_bytes(_DEMO_ONLY_POLICY_KEY_SEED)
    alice_private = Ed25519PrivateKey.from_private_bytes(_DEMO_ONLY_ALICE_KEY_SEED)
    finance_private = Ed25519PrivateKey.from_private_bytes(_DEMO_ONLY_FINANCE_KEY_SEED)
    policy_key_id = SigningKeyId("key:demo-policy")
    alice_key_id = SigningKeyId("key:demo-alice")
    finance_key_id = SigningKeyId("key:demo-finance-agent")
    trust_store = TrustStore(
        (
            TrustedKey(
                policy_key_id,
                _public_key(policy_private),
                (ArtifactPurpose.POLICY_BUNDLE,),
            ),
            TrustedKey(
                alice_key_id,
                _public_key(alice_private),
                (ArtifactPurpose.AUTHORITY_GRANT,),
            ),
            TrustedKey(
                finance_key_id,
                _public_key(finance_private),
                (ArtifactPurpose.AUTHORITY_GRANT,),
            ),
        )
    )
    trusted_policy = verify_policy_bundle(
        bundle,
        sign_artifact(
            bundle,
            policy_private,
            policy_key_id,
            ArtifactPurpose.POLICY_BUNDLE,
        ),
        trust_store,
    )

    base_scope = AuthorityScope(
        Action("payments.transfer"),
        Resource("account:alice"),
        (("amount", 5000),),
    )
    child_scope = AuthorityScope(
        Action("payments.transfer"),
        Resource("account:alice"),
        (("amount", 1000),),
    )
    g1 = AuthorityGrant(
        "grant:alice-finance",
        alice,
        finance,
        base_scope,
        None,
        0,
        100_000,
    )
    g2 = AuthorityGrant(
        "grant:finance-payment-subagent",
        finance,
        payment_subagent,
        child_scope,
        g1.identifier,
        0,
        100_000,
    )
    # A separately authenticated post-revocation authority. It is not a reset
    # or mutation of G1; it gives the replay subcase a still-valid chain after
    # the scenario has permanently revoked G1.
    g3 = AuthorityGrant(
        "grant:alice-finance-refresh",
        alice,
        finance,
        base_scope,
        None,
        0,
        100_000,
    )

    def grant_attestation(
        grant: AuthorityGrant,
        private_key: Ed25519PrivateKey,
        key_id: SigningKeyId,
    ) -> GrantAttestation:
        return GrantAttestation(
            grant.identifier,
            sign_artifact(
                grant,
                private_key,
                key_id,
                ArtifactPurpose.AUTHORITY_GRANT,
            ),
        )

    g1_attestation = grant_attestation(g1, alice_private, alice_key_id)
    g2_attestation = grant_attestation(
        g2,
        finance_private,
        finance_key_id,
    )
    g3_attestation = grant_attestation(g3, alice_private, alice_key_id)

    profiles = (
        NandaAuthorityProfile(
            "finance-primary",
            "finance-agent",
            DelegationChain((g1,)),
            GrantAttestationSet((g1_attestation,)),
            SubjectPrincipalBinding(
                Subject("agent:finance-agent"),
                finance,
            ),
        ),
        NandaAuthorityProfile(
            "finance-refresh",
            "finance-agent",
            DelegationChain((g3,)),
            GrantAttestationSet((g3_attestation,)),
            SubjectPrincipalBinding(
                Subject("agent:finance-agent"),
                finance,
            ),
        ),
        NandaAuthorityProfile(
            "payment-subagent",
            "payment-subagent",
            DelegationChain((g1, g2)),
            GrantAttestationSet((g1_attestation, g2_attestation)),
            SubjectPrincipalBinding(
                Subject("agent:payment-subagent"),
                payment_subagent,
            ),
        ),
    )
    return NandaSecurityMaterial(
        trusted_policy=trusted_policy,
        trust_store=trust_store,
        principal_key_registry=PrincipalKeyRegistry(
            (
                PrincipalKeyBinding(alice, alice_key_id),
                PrincipalKeyBinding(finance, finance_key_id),
            )
        ),
        trusted_authority_roots=TrustedAuthorityRoots((alice,)),
        authority_profiles=profiles,
        approval_requirement=approval_requirement,
    )
