# ADR 0011: Authenticated Delegation Chains

- Status: Accepted
- Date: 2026-09-18
- Amends: ADR 0005 and ADR 0010 at the authenticated-authority trust boundary

## Context

ADR 0005 proves structural delegation provenance, scope attenuation,
caller-supplied revocation state, and caller-supplied logical-time validity.
ADR 0010 proves that a key in an explicit `TrustStore` signed the exact
domain-separated content identity of an `AuthorityGrant` and is authorized for
the `AUTHORITY_GRANT` purpose.

Those two proofs are independent. Neither proves that the signing key belongs
to the `Principal` named as `AuthorityGrant.grantor`. A globally trusted but
unrelated authority key could otherwise sign a grant that claims another
Principal as grantor. Version 1 requires the structural and cryptographic
provenance paths to agree exactly.

This decision introduces no HTTP, persistence, database, network key
discovery, external PKI, DID/JWT verification, NandaTown integration,
distributed execution, key rotation, or threshold signature scheme.

## Principal-to-Key Binding

`PrincipalKeyBinding` contains exactly one typed `Principal` and one typed
`SigningKeyId`. It is configured data; ownership is never inferred from key
names, Principal strings, prefixes, grant contents, or identifier similarity.

`PrincipalKeyRegistry` is an immutable explicitly supplied collection of those
bindings. Version 1 deliberately defines a one-to-one relation:

- one Principal may have exactly one configured signing key;
- one signing key may be bound to exactly one Principal; and
- duplicate exact bindings, conflicting bindings for one Principal, and one key
  assigned to multiple Principals are rejected.

Binding order is non-semantic. Construction defensively copies and sorts by
strict UTF-8 Principal identifier bytes. The version-1 restriction avoids
ambiguous signer ownership and keeps key rotation out of scope. Supporting
multiple active keys per Principal requires a later explicit model.

The registry is trusted caller-supplied security state. It establishes only a
configured Principal/key association. It does not prove DID control, JWT
identity, certificate chains, external identity-provider assertions, human
identity, or private-key custody.

## Trusted Root Authority

`TrustedAuthorityRoots` is an immutable exact set of `Principal` values that
may originate a root grant. Ordering is non-semantic and canonicalized by
strict UTF-8 Principal identifier bytes. Duplicates are rejected. An empty set
is a valid trust-nobody configuration.

The first grant in a `DelegationChain` is a root only because the structural
validator establishes that it is first and has no parent. Authentication then
requires all of the following:

1. the root grantor is exactly present in `TrustedAuthorityRoots`;
2. the root has exactly one detached attestation in the supplied collection;
3. the attestation verifies over the exact root `AuthorityGrant`;
4. the signing key is present in `TrustStore` and trusted for
   `AUTHORITY_GRANT`; and
5. `PrincipalKeyRegistry` binds that exact signing key ID to the root grantor.

Possession of any trusted key does not make a Principal a trusted root. Root
issuance and key-purpose trust are separate configuration decisions.

## Detached Grant-Attestation Collection

`GrantAttestation` associates one nonblank semantic grant identifier with one
detached `ArtifactAttestation`. `GrantAttestationSet` is an immutable mapping
represented as a canonically sorted tuple.

The set rejects duplicate grant identifiers at construction. Authentication
also rejects:

- an attestation missing for any grant in the chain;
- an entry naming a grant outside the chain;
- an attestation whose artifact kind is not `AUTHORITY_GRANT`;
- an attestation whose purpose is not `AUTHORITY_GRANT`;
- an attested digest different from the exact grant digest; and
- any signature or key-purpose verification failure.

AuthorityGrant itself remains unsigned data. Attestations stay detached, so a
grant never contains the signature over its own content identity.

## Child-Grant Authentication

For each non-root child, the existing validator must first prove:

- the parent reference names the immediately preceding grant;
- `parent.grantee == child.grantor`;
- the child scope preserves or narrows the parent scope;
- the chain is acyclic and otherwise structurally valid; and
- every relevant grant is current and unrevoked under supplied state.

Authentication then requires the child's exact attestation to verify with a
key trusted for `AUTHORITY_GRANT`, and the registry must bind that exact key ID
to `child.grantor`.

Consequently, a child Principal may delegate only authority it structurally
received, using a signing key explicitly bound to that child Principal. A
trusted but unrelated key cannot sign on the child's behalf.

## Authentication Status and Evidence

`DelegationAuthenticationStatus` contains:

- `AUTHENTICATED`
- `MISSING_ATTESTATION`
- `ATTESTATION_INVALID`
- `SIGNER_KEY_NOT_BOUND_TO_GRANTOR`
- `UNTRUSTED_ROOT_PRINCIPAL`
- `UNKNOWN_SIGNING_KEY`
- `KEY_NOT_TRUSTED_FOR_AUTHORITY_GRANT`
- `GRANT_ARTIFACT_MISMATCH`
- `STRUCTURAL_AUTHORITY_INVALID`
- `UNKNOWN_GRANT_ATTESTATION`

`GrantAuthenticationEvidence` records, for each known chain grant:

- grant identifier;
- logical grantor;
- root/non-root classification;
- explicit trusted-root membership evidence for a root;
- signing key ID when an attestation exists;
- configured bound Principal when one exists;
- complete `ArtifactVerificationResult` when verification was attempted; and
- the per-grant authentication status.

All known chain grants are considered root-to-leaf so evidence is complete and
independent of early-exit optimization. Aggregate failure is the first
non-`AUTHENTICATED` grant in semantic chain order. Before that per-grant pass,
an extra collection entry not naming a chain grant produces
`UNKNOWN_GRANT_ATTESTATION`; the first such ID is selected by canonical UTF-8
grant-ID order.

Artifact-verification statuses map as follows:

| Artifact verification | Delegation authentication |
| --- | --- |
| `VERIFIED` | continue to Principal/key and root checks |
| `UNKNOWN_KEY` | `UNKNOWN_SIGNING_KEY` |
| `KEY_NOT_TRUSTED_FOR_PURPOSE` | `KEY_NOT_TRUSTED_FOR_AUTHORITY_GRANT` |
| `DIGEST_MISMATCH`, `ARTIFACT_KIND_MISMATCH` | `GRANT_ARTIFACT_MISMATCH` |
| `SIGNATURE_INVALID`, `PURPOSE_MISMATCH`, `SCHEME_UNSUPPORTED` | `ATTESTATION_INVALID` |

This mapping preserves the complete nested verification evidence, so the
coarser chain status does not erase the underlying cause.

## Composition Algorithm

The pure operation is:

```text
authenticate_delegation_chain(
    chain,
    state,
    grant_attestations,
    trust_store,
    principal_key_registry,
    trusted_authority_roots,
) -> DelegationAuthenticationResult
```

Its deterministic sequence is:

1. call the existing `validate_authority(chain, state)`;
2. if validation is not `VALID`, return `STRUCTURAL_AUTHORITY_INVALID` and do
   not allow signatures to rescue the chain;
3. reject an attestation entry for an unknown grant;
4. for every grant root-to-leaf, require one entry and call the existing
   `verify_artifact(..., AUTHORITY_GRANT)`;
5. map cryptographic verification failure to the typed chain status;
6. resolve the signing key ID in `PrincipalKeyRegistry` and require the bound
   Principal to equal the grantor;
7. for the root, additionally require exact root membership; and
8. produce `AuthenticatedDelegatedAuthority` only if every grant is
   `AUTHENTICATED`.

No attenuation, provenance, revocation, time, SHA-256, or Ed25519 algorithm is
duplicated. The operation composes the existing validators.

## AuthenticatedDelegatedAuthority

`AuthenticatedDelegatedAuthority` is immutable and factory-protected. It
contains:

- the successful structural `VerifiedAuthority`;
- the digest of the complete `AuthorityValidationResult`;
- the exact grant-attestation-set digest;
- the exact `TrustStore` digest;
- the exact Principal-key-registry digest;
- the exact trusted-roots digest; and
- complete per-grant authentication evidence.

Its content identity is `sha256_digest(authenticated_authority)`. Ordinary
construction is blocked. Only successful structural/current validation,
cryptographic verification, exact grantor/key binding, and root trust can
produce it.

The name means authenticated relative to the explicitly supplied local trust
configuration. It does not prove an external human identity, DID ownership,
certificate path, or authenticity/freshness of the caller-supplied trust and
authorization state.

## Root and Child Distinction

Given trusted root `principal:alice` with `key:alice`:

- Alice may issue `Alice -> Agent A` when G1 is signed by `key:alice`.
- Agent A may issue `Agent A -> Agent B` only after G1 structurally delegates
  authority to Agent A and G2 is signed by a key bound to Agent A.
- Agent B owning a legitimate signing key does not authorize Agent B to create
  an unrelated root. Agent B must be independently listed in
  `TrustedAuthorityRoots` for that root to authenticate.

## Trusted Authorization Entrypoint

The existing `evaluate()` remains the low-level deterministic semantic policy
engine. It accepts unsigned `PolicyBundle` and structurally validated
`VerifiedAuthority` so policy semantics remain independently testable.

The production-oriented trust-boundary operation is:

```text
authorize_trusted(
    request,
    trusted_policy_bundle,
    authenticated_delegated_authority,
    subject_principal_binding,
) -> TrustedAuthorizationResult
```

It accepts exact `TrustedPolicyBundle` and
`AuthenticatedDelegatedAuthority` values only, then calls `evaluate()` with
their protected underlying values. Raw `PolicyBundle`, a signed-but-untrusted
policy, raw `VerifiedAuthority`, or structurally valid but unauthenticated
delegation cannot enter this path.

`TrustedAuthorizationResult` content-binds the request digest, trusted-policy
wrapper digest, authenticated-delegation digest, and complete low-level
Decision. Existing request, holder-binding, applicability, and policy evidence
remain in that Decision. This wrapper adds trust references without silently
changing `DecisionEvidence` or recursively signing evidence.

## Trusted Execution Revalidation

The existing `revalidate_for_execution()` remains the low-level structural
revalidator and retains all ADR-0009 semantics.

`revalidate_trusted_for_execution()` is a separate trusted orchestration
wrapper. It requires a `TrustedPolicyBundle`, freshly calls
`authenticate_delegation_chain()` against current state and current trust
inputs, and only after success invokes the unchanged low-level execution
revalidator with the trusted wrapper's bundle. Its typed result distinguishes
delegation-authentication failure from ordinary execution-revalidation
failure. The wrapper binds both the raw policy-bundle digest and the protected
trusted-policy digest, and construction requires the nested execution result to
use the exact structural validation produced during delegation authentication.

The structural validator is invoked through the authentication component and
again inside the existing low-level revalidator. This deliberate composition
does not implement either algorithm twice; it preserves the low-level API and
its independent fail-closed invariants while ensuring the trusted path cannot
reach it without current cryptographic provenance.

## Canonical Encoding

ADR 0001 framing remains unchanged. New schemas are:

- `nest-authz/principal-key-binding@1`
- `nest-authz/principal-key-registry@1`
- `nest-authz/trusted-authority-roots@1`
- `nest-authz/grant-attestation@1`
- `nest-authz/grant-attestation-set@1`
- `nest-authz/delegation-authentication-status@1`
- `nest-authz/grant-authentication-evidence@1`
- `nest-authz/authenticated-delegated-authority@1`
- `nest-authz/delegation-authentication-result@1`
- `nest-authz/trusted-authorization-result@1`
- `nest-authz/trusted-execution-authorization-status@1`
- `nest-authz/trusted-execution-authorization-result@1`

Registry bindings, roots, and grant-attestation entries are non-semantic
collections and are sorted by strict UTF-8 semantic identifier bytes.
Per-grant evidence preserves root-to-leaf chain order because provenance order
is semantic. No existing schema changes fields or meaning, so no existing
schema version advances. Private keys remain unsupported by canonical
encoding.

## Consequences and Limitations

- Logical and cryptographic grant provenance must agree before authenticated
  authority exists.
- Globally trusted authority keys cannot impersonate unrelated grantors.
- Root authority is explicit and separate from key presence or key purpose.
- Policies and delegated authority have distinct protected wrappers at the
  trusted authorization boundary.
- TrustStore, PrincipalKeyRegistry, TrustedAuthorityRoots, logical time, and
  revocation state remain trusted caller-supplied inputs.
- Principal/key bindings are configuration assertions, not externally proven
  identities.
- Version 1 supports one signing key per Principal, exactly one attestation per
  grant, and no key rotation, threshold signatures, or multi-signature grants.
- Grant signatures do not authenticate the caller-supplied revocation set,
  logical time, subject binding, or root-set configuration.
- No network discovery, external PKI, DID/JWT verification, persistence,
  distributed execution, or NandaTown integration is introduced.

## Rejected Alternatives

### Infer key ownership from identifier text

Rejected because naming conventions are not cryptographic or configured proof
of Principal/key association.

### Treat every AUTHORITY_GRANT key as able to sign for every Principal

Rejected because key-purpose authorization is not grantor impersonation
authority.

### Put signatures inside AuthorityGrant

Rejected because it would change established grant identity and create
self-referential signing concerns.

### Let signatures rescue invalid structural provenance

Rejected because cryptographic origin does not repair broken parent links,
cycles, amplification, revocation, or expiry.

### Replace the low-level evaluator

Rejected because policy semantics and artifact trust are separate concerns.
The trusted entrypoint composes rather than embeds cryptography in `evaluate()`.
