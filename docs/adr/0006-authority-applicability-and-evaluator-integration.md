# ADR 0006: Authority Applicability and Evaluator Integration

- Status: Accepted
- Date: 2026-09-18
- Amends: ADR 0004 and ADR 0005

## Problem

ADR 0005 validates delegation structure and supplied authorization state, but
does not establish that the resulting effective authority applies to a
particular `AuthorizationRequest`. ADR 0004 allows an opaque `Authority` value
on a request to satisfy the evaluator's authority-presence gate. That is no
longer sufficient: policy must never widen validated delegated authority, and
decision evidence must be bound to the exact request being authorized.

This decision introduces a separate deterministic applicability check and
requires policy evaluation to use it as a mandatory execution-authority gate.
It introduces no cryptographic signatures, key management, HTTP, persistence,
external services, NandaTown integration, or approval execution.

## Meaning and Naming of VerifiedAuthority

The current validator proves only that, for the exact supplied inputs:

- delegation provenance is structurally coherent;
- every child scope preserves or attenuates its parent scope;
- every Grant contains the supplied logical time within its deterministic
  validity interval; and
- no Grant is present in the caller-supplied revocation state.

It does **not** prove:

- cryptographic identity authenticity;
- cryptographic authenticity of any Grant;
- trusted root issuance;
- authenticity or freshness of caller-supplied logical time; or
- authenticity, completeness, or freshness of caller-supplied revocation
  state.

The name `VerifiedAuthority` can therefore be read too broadly. A clearer name
would be `ValidatedDelegatedAuthority`. This ADR records that proposed rename
before any terminology change, but retains `VerifiedAuthority` in the current
public API to avoid an unrelated breaking migration. In this codebase,
"verified" MUST be read only as "successfully validated by the deterministic
ADR-0005 validator against the supplied chain and state." It is not an
authentication or trust-root claim.

## Authority Applicability Model

The pure public operation is:

```text
check_authority_applicability(
    request: AuthorizationRequest,
    authority: VerifiedAuthority,
) -> AuthorityApplicabilityResult
```

Only exact domain types are accepted. The operation reads no wall clock,
randomness, environment, network, filesystem, database, external service, or
mutable global state.

`AuthorityApplicabilityStatus` has exactly:

- `APPLICABLE`
- `ACTION_MISMATCH`
- `RESOURCE_MISMATCH`
- `MISSING_CONTEXT`
- `BOUND_EXCEEDED`
- `TYPE_ERROR`

The result is not a boolean. It contains deterministic evidence for the exact
request and effective authority:

- `sha256_digest(request)`;
- `sha256_digest(authority)`;
- the authority's Chain and AuthorizationState digests;
- the effective leaf Grant identifier;
- expected authority Action, actual request Action, and their exact comparison;
- expected authority Resource, actual request Resource, and their exact
  comparison;
- one `AuthorityBoundEvaluation` for every effective upper bound; and
- the aggregate applicability status.

Bound evaluations are canonically ordered by strict UTF-8 bytes of the direct
context key. Each records the key, authority upper bound, presence, supplied
scalar value, and individual status. Scalar type is part of equality and
canonical identity, so `True` and `1` cannot become equal evidence.

## Action and Resource Semantics

The effective leaf Action must exactly equal `request.action`. The effective
leaf Resource must exactly equal `request.resource`. There are no wildcards,
patterns, normalization, hierarchy, or implicit aliases.

Both comparisons are always recorded. A mismatch cannot be overridden by
policy.

## Integer-Bound Semantics

Every effective integer upper bound is evaluated, even if Action, Resource, or
another bound already fails. For every `(key, upper_bound)`:

1. If the exact direct request-context key is absent, the bound status is
   `MISSING_CONTEXT`.
2. If present but the value's exact type is not `int`, the status is
   `TYPE_ERROR`. Python `bool` is not an integer for this purpose.
3. If the exact integer is greater than the upper bound, the status is
   `BOUND_EXCEEDED`.
4. Otherwise the bound status is `APPLICABLE`.

No default is inferred. Extra request-context fields are ignored by authority
applicability unless named by an authority bound; they remain part of the exact
request digest and may independently be used by policy.

The aggregate status uses this deterministic precedence:

1. `ACTION_MISMATCH`
2. `RESOURCE_MISMATCH`
3. `MISSING_CONTEXT`
4. `TYPE_ERROR`
5. `BOUND_EXCEEDED`
6. `APPLICABLE`

All per-bound results remain available, so aggregate precedence does not hide
simultaneous failures.

## Final Authorization Pipeline

The three trust boundaries remain distinct:

```text
DelegationChain + AuthorizationState
    -> validate_authority()
    -> VerifiedAuthority

AuthorizationRequest + VerifiedAuthority
    -> check_authority_applicability()
    -> AuthorityApplicabilityResult

AuthorizationRequest + PolicyBundle + VerifiedAuthority
    -> evaluate()
    -> Decision
```

`evaluate` now requires an explicit third argument of exact type
`VerifiedAuthority | None`. The two-argument call is intentionally removed so
callers cannot accidentally continue relying on opaque Authority presence.

The evaluator still evaluates every policy Rule for complete deterministic
policy evidence. It separately computes applicability when verified authority
is supplied. Before returning a non-deny outcome it applies this mandatory
gate:

- absent verified authority -> `DENY`;
- any applicability status other than `APPLICABLE` -> `DENY`;
- only `APPLICABLE` authority proceeds to existing fail-closed Rule aggregation
  and `DENY_OVERRIDES` policy combination.

Thus a matching `PERMIT` or `APPROVAL_REQUIRED` Rule cannot widen authority.
A matching policy `DENY` remains `DENY` when authority is applicable.

`AuthorizationRequest.authority` remains an opaque, optional request value for
the closed ADR-0004 `AUTHORITY` policy namespace. It is not evidence of
delegation validity and does not satisfy the execution-authority gate.

## Request Binding and Decision Evidence

Every `DecisionEvidence` contains `sha256_digest(request)`. This binds the
Decision to the complete canonical request, including Subject, Action,
Resource, Context, and opaque request Authority. A Decision for request A is
therefore not content-equivalent evidence for request B.

When a `VerifiedAuthority` is supplied, `DecisionEvidence` also contains the
complete `AuthorityApplicabilityResult`. Deterministic views expose the exact
Chain digest, AuthorizationState digest, and effective leaf Grant identifier.
The nested result binds the request digest and validated-authority digest, and
construction rejects inconsistent evidence.

Non-deny `Decision` construction requires an `APPLICABLE` result. Opaque
request Authority presence alone is never sufficient.

No decision identifier, timestamp, nonce, or Python `hash()` value is used.

## Canonical Schema Versions

ADR 0001 framing remains version 1. New records use:

- `nest-authz/authority-applicability-status@1`
- `nest-authz/authority-bound-evaluation@1`
- `nest-authz/authority-applicability-result@1`

`DecisionEvidence` changes incompatibly by adding the request digest and
replacing opaque request-Authority evidence with applicability evidence. Its
schema advances from `nest-authz/decision-evidence@3` to
`nest-authz/decision-evidence@4`.

`Decision` construction semantics now require applicable validated authority
for non-deny outcomes. Its schema advances from `nest-authz/decision@2` to
`nest-authz/decision@3` rather than silently reusing the former contract.

`AuthorizationRequest`, `VerifiedAuthority`, delegation records, policy
records, and Rule-evaluation records retain their existing schema versions.
Historical schema identifiers remain documented; no existing identifier is
assigned new field or semantic meaning.

## Consequences and Limitations

- Policy cannot authorize an Action, Resource, or numeric context value outside
  the effective delegated scope.
- Decisions are content-addressably bound to the exact request.
- Applicability and policy evidence remain independently inspectable.
- `VerifiedAuthority` still relies on caller-supplied logical time and
  revocation state and proves no cryptographic authenticity or trusted root.
- Version 1 does not bind `Principal` to `Subject`; no authenticated mapping
  between those semantic identifiers has been defined.
- Opaque request-Authority attributes remain policy inputs but are not validated
  delegation claims.
- A caller must revalidate authority against the appropriate current supplied
  state before evaluation; this library does not establish state freshness.
- No approval execution, signature, key management, API, persistence, external
  service, or NandaTown integration is introduced.
