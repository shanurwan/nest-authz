# ADR 0005: Delegated Authority and Attenuation

- Status: Accepted
- Date: 2026-09-18
- Amended by: ADR 0006 and ADR 0011

ADR 0006 clarifies the limited trust proven by `VerifiedAuthority`, adds
request applicability, and integrates that separate gate with policy
evaluation without changing delegation validation semantics.

ADR 0011 composes this structural validator with detached grant attestations,
explicit Principal/key bindings, and explicit root trust. It does not change
the attenuation, revocation, or logical-time algorithm defined here.

## Problem

NEST AuthZ needs deterministic validation of explicit delegated authority.
Every delegation must preserve or narrow its parent's authority; it must never
amplify authority. Validation must establish provenance, attenuation,
revocation state, and logical-time validity without relying on policy
evaluation or external state.

This decision introduces no cryptographic signatures, identity verification,
key management, HTTP, persistence, external services, or NandaTown
integration.

## Separation of Responsibilities

The design keeps three concerns separate:

1. **Authority provenance** is represented by an ordered `DelegationChain` of
   grants with explicit parent and principal links.
2. **Authority validity** is determined by `validate_authority(chain, state)`,
   using only the supplied immutable chain and authorization state.
3. **Policy evaluation** remains the existing independent `evaluate()`
   component. It is not changed to consume `VerifiedAuthority` in this step.

A valid delegation does not itself permit an action. It only establishes an
authority value suitable for a later, separately bounded integration.

## Principal

`Principal` contains one stable, nonblank semantic identifier. It identifies a
grantor or grantee but contains no authentication, key, signature, trust, or
identity-verification claim.

`Principal` is distinct from request `Subject` so authority provenance is not
mistaken for authentication or policy authorization.

## AuthorityScope

Version 1 deliberately represents a small closed scope:

- one exact allowed `Action`;
- one exact allowed `Resource`; and
- zero or more direct context integer upper bounds.

Each upper bound is keyed by one nonblank literal context name and has an exact
Python `int` value. `bool` is rejected even though it subclasses `int`.
Bounds are immutable, unique by key, and sorted by strict UTF-8 key bytes.

There are no wildcards, regexes, expression languages, callbacks, plugins,
nested paths, or executable predicates.

## Attenuation Algebra

Let a scope denote the set of requests satisfying its exact Action, exact
Resource, and every upper-bound constraint. `child_scope` is an attenuation of
`parent_scope`, written conceptually as:

```text
child_scope <= parent_scope
```

if and only if all of the following hold:

1. `child.action == parent.action`.
2. `child.resource == parent.resource`.
3. For every `(name, parent_bound)` in the parent, the child contains the same
   name and `child_bound <= parent_bound`.
4. The child may contain additional upper bounds because each additional
   constraint narrows the denoted request set.

Consequences:

- equal scope is valid preservation;
- a lower numeric upper bound is valid attenuation;
- omitting a parent bound is amplification because it removes a constraint;
- increasing a parent bound is amplification;
- changing Action or Resource is not a subset and is amplification.

For example, a child limited to `payments.transfer`, `account:alice`, and
`max_amount <= 1000` is within a parent limited to the same Action and Resource
with `max_amount <= 5000`. A child bound of `10000`, a different Action, or a
different Resource is invalid.

Attenuation is checked by authority validation, not policy evaluation.

## AuthorityGrant

`AuthorityGrant` contains:

- a stable, nonblank semantic grant identifier;
- a typed grantor `Principal`;
- a typed grantee `Principal`;
- an `AuthorityScope`;
- an optional nonblank parent grant identifier;
- exact-integer `valid_from`; and
- exact-integer `valid_until`.

The parent identifier is semantic, not a content digest. Position in a chain
determines whether a grant is root or delegated:

- the first/root grant MUST have no parent identifier;
- every later/delegated grant MUST identify the immediately preceding grant.

Local malformed values fail construction. In particular, booleans are not
logical time and `valid_from` MUST be strictly less than `valid_until`.

## DelegationChain and Provenance

`DelegationChain` is a nonempty immutable sequence ordered root to leaf. Order
is semantic and is therefore preserved in canonical encoding.

Validation requires:

- grant identifiers are unique within the chain;
- the root has no parent reference;
- every child references the exact preceding parent identifier;
- `parent.grantee == child.grantor` for every adjacent pair;
- parent-reference traversal contains no cycle;
- the principal path contains no repeated principal, including direct
  self-delegation; and
- every child scope attenuates its parent scope.

The full chain is valid only if every link is valid. A forged parent reference,
missing parent, skipped parent, broken grantor/grantee link, cycle, or amplified
scope invalidates the complete descendant authority.

Duplicate IDs and structural defects remain representable in a Chain so the
validator can return typed failure evidence. The Chain constructor only
enforces a nonempty immutable sequence of typed Grants.

## Logical Time

`AuthorizationState.logical_time` is an explicitly supplied exact integer. The
validator never reads a wall clock.

Each Grant uses a half-open validity interval:

```text
valid_from <= logical_time < valid_until
```

Thus exactly `valid_from` is valid and exactly `valid_until` is expired.
Every Grant in the Chain is checked. The effective validity interval is the
intersection of all ancestor and descendant intervals, so a child cannot be
used after an ancestor expires or before an ancestor becomes valid. Version 1
does not require declared child intervals to be syntactically nested because
checking the complete Chain provides the same non-amplification property.

## RevocationSet and AuthorizationState

`RevocationSet` is explicit immutable input containing canonicalized grant
identifiers. Ordering is non-semantic; identifiers are sorted by strict UTF-8
bytes and duplicates are invalid.

`AuthorizationState` contains logical time and a `RevocationSet`. It reads no
database or service.

If any Grant in the Chain is revoked, the leaf authority and every descendant
relying on that Grant are invalid. Validation examines root to leaf and reports
the first revoked ancestor as the offending grant, making ancestor revocation
visible even behind otherwise valid descendants.

## Validation Status and Evidence

`AuthorityValidationStatus` has exactly:

- `VALID`
- `REVOKED`
- `NOT_YET_VALID`
- `EXPIRED`
- `BROADENED_AUTHORITY`
- `BROKEN_PROVENANCE`
- `CYCLE`
- `INVALID_CHAIN`

`AuthorityValidationResult` is not a boolean. It contains:

- the typed status;
- `sha256_digest(chain)`;
- `sha256_digest(state)`;
- the offending grant identifier for every failure; and
- a `VerifiedAuthority` only for `VALID`.

Validation order is deterministic:

1. duplicate grant identifiers -> `INVALID_CHAIN`;
2. parent-reference cycle -> `CYCLE`;
3. invalid root, parent reference, or grantor/grantee link ->
   `BROKEN_PROVENANCE`;
4. repeated-principal/self-delegation cycle -> `CYCLE`;
5. non-attenuating scope -> `BROADENED_AUTHORITY`;
6. first revoked Grant from root to leaf -> `REVOKED`;
7. first root-to-leaf Grant before `valid_from` -> `NOT_YET_VALID`;
8. first root-to-leaf Grant at or after `valid_until` -> `EXPIRED`;
9. otherwise -> `VALID`.

Structural invalidity is reported before state-dependent checks because an
untrusted malformed provenance chain cannot establish which descendant
authority is being validated. Revocation precedes logical-time checks once the
Chain is structurally valid.

## VerifiedAuthority

Only successful validation produces `VerifiedAuthority`. It contains:

- the leaf grant identifier;
- the leaf grantee Principal;
- the attenuated leaf Scope;
- the logical time at which validation occurred;
- the exact Chain digest; and
- the exact AuthorizationState digest.

The public constructor is blocked. A private module capability used by
`validate_authority()` is required for construction. Python cannot create an
absolute security boundary against hostile in-process introspection, but this
pattern prevents ordinary callers from accidentally manufacturing verified
authority.

`VerifiedAuthority` contains no authentication or signature claim. It is not
yet accepted by policy evaluation.

## Canonical Representation

ADR 0001 framing remains version 1. These new stable schemas are added:

- `nest-authz/principal@1`
- `nest-authz/authority-scope@1`
- `nest-authz/authority-grant@1`
- `nest-authz/delegation-chain@1`
- `nest-authz/revocation-set@1`
- `nest-authz/authorization-state@1`
- `nest-authz/authority-validation-status@1`
- `nest-authz/verified-authority@1`
- `nest-authz/authority-validation-result@1`

No existing record schema changes. Scope bounds and revocation identifiers are
canonicalized because their order is non-semantic. Delegation-chain order is
preserved because it is provenance.

All records participate in `canonical_bytes()` and `sha256_digest()`. Python
`hash()` is never used as persistent or security identity.

## Failure Boundary

Malformed local domain values fail construction. Complete typed but invalid
Chains return an `AuthorityValidationResult` with deterministic failure status
and evidence. Impossible internal validator states raise a typed
`AuthorityValidationError`; callers MUST treat any exception as invalid
authority and MUST NOT proceed to policy authorization.

No failure can produce `VerifiedAuthority`.

## Consequences and Limitations

- Delegation amplification is mechanically rejected before policy evaluation.
- Revocation and time are deterministic explicit inputs.
- Validation results and successful verified authority are reproducible and
  content-identifiable.
- The validator proves internal chain structure and supplied state only. It
  does not authenticate Principals or Grants.
- No signatures, trusted issuer registry, key management, revocation
  distribution, persistence, HTTP, external service, policy integration, or
  NandaTown integration is introduced.
- Scope version 1 supports one exact Action, one exact Resource, and direct
  integer upper bounds only.
