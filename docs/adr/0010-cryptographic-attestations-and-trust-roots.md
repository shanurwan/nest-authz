# ADR 0010: Cryptographic Attestations and Trust Roots

- Status: Accepted
- Date: 2026-09-18
- Amended by: ADR 0011 at the delegated-authority integration boundary

## Context

ADR 0001 through ADR 0009 establish deterministic content identity, authority
validation against supplied state, holder binding, approval authorization, and
fresh execution revalidation. Those mechanisms prove internal consistency.
They do not prove which key issued a policy, grant, decision receipt, or
execution permit.

Three questions remain deliberately separate:

1. **Signature validity:** did the private key corresponding to a public key
   sign this exact domain-separated message?
2. **Signer trust:** is that public key explicitly present in the supplied
   trust store under the claimed semantic key identifier?
3. **Signer authorization:** is that trusted key allowed for this exact trust
   purpose?

A valid signature alone answers only the first question. It MUST NOT imply
trust or authorization.

## Cryptographic Algorithm and Dependency

Version 1 supports exactly Ed25519 through the mature `cryptography` package.
The project dependency is pinned to `cryptography==50.0.1`. NEST AuthZ does not
implement any signing primitive manually.

Version 1 has no RSA, ECDSA, HMAC, algorithm negotiation, downgrade mechanism,
or user-defined algorithm. `SignatureScheme` therefore contains only
`ED25519`. `SCHEME_UNSUPPORTED` remains an explicit verification status for a
future trust-boundary decoder or version without making another scheme valid
in the current domain model.

## Key and Signature Types

The immutable public domain contains:

- `SigningKeyId`: one stable, nonblank semantic identifier;
- `Ed25519PublicKey`: exactly 32 raw public-key bytes; and
- `ArtifactSignature`: exactly 64 raw Ed25519 signature bytes.

The byte lengths are construction invariants. Verification passes the exact
stored raw representation to `cryptography`; any representation rejected by
that implementation fails closed and cannot verify an artifact.

Private keys are operational arguments to `sign_artifact()` only. Private-key
material is never stored in an immutable domain record, detached attestation,
canonical representation, receipt, verification result, trust store, or
trusted wrapper. The core does not intentionally render, log, return, or
canonicalize private material. Tests generate ephemeral private keys.

Key identifiers are semantic names, not key fingerprints. The `TrustStore`
provides the explicit association between an identifier and public key.

## Trust Purpose and Artifact Kind

`ArtifactPurpose` is a closed authorization namespace:

- `POLICY_BUNDLE`
- `AUTHORITY_GRANT`
- `DECISION_RECEIPT`
- `EXECUTION_PERMIT`

`ArtifactKind` is a distinct closed type with the same version-1 labels. Kind
states what canonical object is authenticated; purpose states what use a key is
authorized for. Neither is inferred from an arbitrary string.

Version 1 defines a one-to-one required-purpose mapping:

| Artifact type | Artifact kind | Required purpose |
| --- | --- | --- |
| `PolicyBundle` | `POLICY_BUNDLE` | `POLICY_BUNDLE` |
| `AuthorityGrant` | `AUTHORITY_GRANT` | `AUTHORITY_GRANT` |
| `DecisionReceipt` | `DECISION_RECEIPT` | `DECISION_RECEIPT` |
| `ExecutionPermit` | `EXECUTION_PERMIT` | `EXECUTION_PERMIT` |

The types remain separate because the signed message must domain-separate both
dimensions and a future version may authorize more than one operation over an
artifact kind. A key trusted for one purpose gains no authority for another.

## Detached Artifact Attestation

`ArtifactAttestation` contains:

- `SignatureScheme`;
- `SigningKeyId`;
- `ArtifactPurpose`;
- `ArtifactKind`;
- the typed SHA-256 digest of the canonical artifact; and
- an `ArtifactSignature`.

Attestations are detached. `PolicyBundle`, `AuthorityGrant`, `DecisionReceipt`,
and `ExecutionPermit` remain unchanged and do not contain their attestations.
An attestation is not included in the object whose digest it signs, avoiding
self-referential hashing and signing.

## Version-1 Signing Message

The signed message is a purpose-built binary protocol, not canonical encoding
of the attestation. Its exact version-1 form is:

```text
ASCII "NEST-AUTHZ-ATTESTATION" | 00 | 01
S | uint32be(7)  | ASCII "ED25519"
P | uint32be(n)  | strict-UTF-8 purpose value
K | uint32be(n)  | strict-UTF-8 artifact-kind value
D | uint32be(32) | raw SHA-256 digest bytes
```

`S`, `P`, `K`, and `D` are the single ASCII tag bytes `0x53`, `0x50`, `0x4b`,
and `0x44`. Every length is an unsigned four-byte big-endian integer. Fields
occur exactly once in that order. The NUL and version byte belong to the
preamble. There are no textual separators, `repr()`, Python `hash()`, pickle,
or platform-dependent values.

The explicit scheme, purpose, kind, and typed artifact digest provide three
layers of domain separation: the canonical artifact type already affects its
SHA-256 digest, kind names the signed artifact category, and purpose names the
authorized trust use.

The golden vector for scheme `ED25519`, purpose and kind `POLICY_BUNDLE`, and
digest bytes `00 01 ... 1f` is 109 bytes with this hexadecimal representation:

```text
4e4553542d415554485a2d4154544553544154494f4e0001530000000745443235353139500000000d504f4c4943595f42554e444c454b0000000d504f4c4943595f42554e444c454400000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

Changing any field changes the signed message.

## Trust Store

`TrustedKey` contains one `SigningKeyId`, one `Ed25519PublicKey`, and a
nonempty immutable set of allowed `ArtifactPurpose` values. Purpose order is
non-semantic and canonicalized by strict UTF-8 enum value bytes.

`TrustStore` is an immutable, explicitly supplied collection of trusted keys.
It defensively copies and sorts keys by strict UTF-8 key-identifier bytes.
Duplicate key identifiers are rejected. An empty store is a valid explicit
trust-nobody configuration.

Verification performs a linear lookup in this supplied value. It reads no
network, filesystem, environment, global registry, database, clock, or mutable
global state. There is no network discovery, external PKI, certificate chain,
or implicit platform trust store.

## Signing and Verification APIs

`sign_artifact(artifact, private_key, key_id, purpose)` accepts only one of the
four supported exact artifact types. It recomputes `sha256_digest(artifact)`,
infers the closed artifact kind, requires the version-1 purpose for that kind,
builds the exact signing message, and returns a detached attestation. Callers
cannot substitute a digest for the artifact.

`verify_artifact(artifact, attestation, trust_store, expected_purpose)` also
accepts only the four supported exact artifact types. It recomputes the digest
and returns `ArtifactVerificationResult`, never a boolean.

Deterministic verification failure precedence is:

1. attested kind differs from the actual supported artifact kind ->
   `ARTIFACT_KIND_MISMATCH`;
2. attested purpose differs from the expected purpose -> `PURPOSE_MISMATCH`;
3. unsupported scheme -> `SCHEME_UNSUPPORTED`;
4. recomputed and attested digests differ -> `DIGEST_MISMATCH`;
5. key identifier is absent -> `UNKNOWN_KEY`;
6. signature verification fails -> `SIGNATURE_INVALID`;
7. the known key is not trusted for the expected purpose ->
   `KEY_NOT_TRUSTED_FOR_PURPOSE`;
8. otherwise -> `VERIFIED`.

Verifying the signature before the known key's purpose authorization makes the
distinction observable: a cryptographically valid signature can still fail
because its key lacks the required purpose. An unknown key cannot be checked
against a public key that the verifier does not possess and therefore remains
`UNKNOWN_KEY`.

The result preserves the actual recomputed artifact digest, complete detached
attestation, expected purpose, expected artifact kind, and status. Its ordinary
constructor is blocked so callers cannot accidentally manufacture `VERIFIED`
evidence.

## Trusted Policy Integration

`verify_policy_bundle()` is the first narrow trust-boundary integration. It
requires an attestation verified with expected purpose `POLICY_BUNDLE` and
returns a factory-protected `TrustedPolicyBundle` only for `VERIFIED`.

The wrapper binds the exact bundle, detached attestation, and verification
result. It does not alter the evaluator or claim to be the final production
policy-distribution trust model. Generic verification failures remain available
as typed `ArtifactVerificationResult` values; failed verification cannot
produce the trusted wrapper.

## Authority-Grant Semantics

A verified `AuthorityGrant` attestation proves that the configured public key
corresponding to the key ID signed the exact domain-separated grant identity
and that the supplied trust store authorizes the key for `AUTHORITY_GRANT`.

On its own, generic `verify_artifact()` does not prove that the key belongs to
`AuthorityGrant.grantor`, that a Principal controls the key, or that every link
in a delegation chain has been issued by its logical grantor. ADR 0011 adds a
separate composed boundary that requires an explicit configured Principal/key
binding for every verified grant and an explicit trusted root. That configured
association is still not external identity or key-ownership proof.

## Receipt and Execution-Permit Semantics

A verified receipt or execution-permit attestation authenticates issuance by a
key explicitly trusted for that artifact purpose. It does not provide atomic
consumption, distributed single-use enforcement, idempotent protected-operation
execution, persistence, or transaction coordination. Signatures authenticate
content and issuer key; they do not solve state-machine races.

## Canonical Encoding

ADR 0001 framing remains unchanged. New public schemas are:

- `nest-authz/signing-key-id@1`
- `nest-authz/ed25519-public-key@1`
- `nest-authz/artifact-signature@1`
- `nest-authz/signature-scheme@1`
- `nest-authz/artifact-purpose@1`
- `nest-authz/artifact-kind@1`
- `nest-authz/trusted-key@1`
- `nest-authz/trust-store@1`
- `nest-authz/artifact-attestation@1`
- `nest-authz/artifact-verification-status@1`
- `nest-authz/artifact-verification-result@1`
- `nest-authz/trusted-policy-bundle@1`

Public keys and signatures encode their raw bytes as fixed-length lowercase hex
inside their typed records. Trust-store key order and allowed-purpose order are
non-semantic and canonicalized. No existing record changes fields or meaning,
so no existing schema version advances.

Private-key objects are deliberately unsupported by `canonical_bytes()`.

## Consequences and Limitations

- Exact canonical artifacts can be authenticated against explicit local trust
  roots without ambient state.
- Signature validity, key presence, and purpose authorization remain distinct.
- Self-signed attacker artifacts fail unless the attacker's key is explicitly
  configured in the trust store for the exact purpose.
- Detached signatures avoid self-reference and preserve existing artifact
  identities.
- Trust-store configuration, distribution, replacement, and freshness remain
  caller responsibilities.
- Key rotation, key expiry, threshold signatures, multi-signature policy,
  compromise recovery, and signed revocation statements are not modeled.
- No HTTP, persistence, database, network discovery, external PKI, JWT/DID,
  NandaTown integration, or distributed execution is introduced.

## Rejected Alternatives

### Sign only an untyped digest

Rejected because a signature could be replayed across purposes or artifact
kinds when digest material is reused outside its intended domain.

### Put signatures inside signed artifacts

Rejected because it creates self-referential identity and changes established
artifact schemas.

### Infer trust from a valid signature

Rejected because anyone can create an Ed25519 key and a valid self-signature.
Trust requires explicit key configuration and exact-purpose authorization.

### Global or network-backed key registry

Rejected because it introduces ambient, nondeterministic, and operationally
mutable state into verification.

### Implement Ed25519 directly

Rejected because hand-written cryptography is unnecessary and unsafe when a
mature maintained implementation is available.
