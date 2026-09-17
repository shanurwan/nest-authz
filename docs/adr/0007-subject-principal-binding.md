# ADR 0007: Subject/Principal Binding

- Status: Accepted
- Date: 2026-09-18
- Supersedes: the opaque request-authority terminology and non-deny evidence
  requirements in ADR 0004 and ADR 0006 where noted below

## Context

ADR 0005 validates delegation structure, attenuation, caller-supplied logical
time, and caller-supplied revocation state. ADR 0006 proves that the validated
leaf scope applies to an `AuthorizationRequest`. Neither decision binds the
runtime `Subject` to the `Principal` that owns the leaf authority. Without a
separate holder check, a valid authority object can behave as a bearer
capability: an unrelated subject can present another principal's authority and
reach a policy `PERMIT`.

NEST AuthZ version 1 uses holder-bound delegated authority. A separate future
authentication boundary will assert which `Subject` represents which
`Principal`; the deterministic core validates only the consistency of that
assertion with the request and validated authority.

## Decision

### Binding assertion

`SubjectPrincipalBinding` is an immutable pair of the existing typed `Subject`
and `Principal` values. It is not represented as two strings and performs no
cross-namespace identifier comparison. It is deliberately not named
`AuthenticatedSubjectBinding`: no authentication is implemented here.

The record means only: an external identity boundary asserts that this Subject
represents this Principal. The core accepts this assertion as input; it does
not establish its authenticity.

### Holder check

The pure function

```text
check_subject_authority_binding(request, binding, verified_authority)
    -> SubjectAuthorityBindingResult
```

compares typed values in this order:

1. `request.subject` must equal `binding.subject`.
2. `binding.principal` must equal `verified_authority.principal`, which is the
   effective leaf grantee.

The closed status is:

- `BOUND`: both comparisons match;
- `SUBJECT_MISMATCH`: the binding is not for the request Subject;
- `PRINCIPAL_MISMATCH`: the asserted Principal is not the authority leaf
  grantee.

If both comparisons would fail, `SUBJECT_MISMATCH` has precedence because the
assertion does not apply to the request in the first place. There is no string
coercion, no comparison between `Subject.identifier` and
`Principal.identifier`, and no fallback based on similar-looking identifiers.

`SubjectAuthorityBindingResult` preserves the status, request Subject, complete
binding assertion, effective authority Principal, effective grant identifier,
request digest, and digest of the `VerifiedAuthority`. Its constructor derives
the only valid status from the evidence and rejects inconsistent records.

### Authorization pipeline

The authorization trust boundaries remain separate:

```text
DelegationChain + AuthorizationState
    -> validate_authority()
    -> VerifiedAuthority

AuthorizationRequest + SubjectPrincipalBinding + VerifiedAuthority
    -> check_subject_authority_binding()
    -> SubjectAuthorityBindingResult

AuthorizationRequest + VerifiedAuthority
    -> check_authority_applicability()
    -> AuthorityApplicabilityResult

AuthorizationRequest + PolicyBundle + both successful gate results
    -> policy effect combination
    -> Decision
```

`evaluate(request, bundle, authority, binding)` computes deterministic policy
and gate evidence, but its security gate precedence is:

1. validated authority must exist;
2. the binding assertion must exist and be `BOUND`;
3. authority applicability must be `APPLICABLE`;
4. policy results are combined under the existing deny-overrides rules.

Policy effects cannot override `SUBJECT_MISMATCH` or `PRINCIPAL_MISMATCH`.
`PERMIT` and `APPROVAL_REQUIRED` therefore require all authority gates to
succeed. `Decision` enforces this again at construction, so callers cannot
manufacture a valid non-deny decision from failed binding evidence.

All checks are pure. They read no clock, randomness, network, environment,
filesystem, database, or mutable global state.

### Authority-context terminology

The former `AuthorizationRequest.authority: Authority | None` value contains
only policy-visible contextual attributes. It is not delegation validation
evidence and its name is security-ambiguous beside `VerifiedAuthority`.

It is intentionally renamed to
`AuthorizationRequest.authority_context: AuthorityContext | None`.
`AuthorityContext` remains distinct from `VerifiedAuthority` and cannot satisfy
any execution-authority gate. No `Authority` compatibility alias is retained,
because such an alias would preserve the ambiguity at the public trust
boundary. This is a deliberate breaking source change.

`FieldNamespace.AUTHORITY` is retained as the stable policy-language namespace;
it now explicitly resolves only against `AuthorityContext`. Renaming the enum
member would unnecessarily change policy meaning and content identities.

### Decision evidence

`DecisionEvidence` now includes `subject_authority_binding` alongside the
request digest, policy bundle digest, policy rule evidence, and authority
applicability evidence. Construction requires:

- every supplied gate result to carry the exact decision request digest;
- binding and applicability evidence to carry the same validated-authority
  digest and effective grant identifier;
- every non-deny decision to have `BOUND` binding evidence and `APPLICABLE`
  scope evidence.

This content-addressably binds the holder assertion and delegated authority to
the exact request. No Python `hash()` value, random identifier, or wall-clock
value is used.

## Trust boundary

The deterministic core guarantees only that:

- the request Subject equals the binding Subject; and
- the binding Principal equals the validated authority's leaf grantee.

`SubjectPrincipalBinding` is trusted input from a future authentication or
identity adapter. NEST AuthZ does not yet guarantee that the binding came from a
trusted identity provider, that any party possesses a private key, that a JWT
is authentic, that a DID is controlled by the claimant, or that a NANDA
identity is authentic. These are responsibilities of a future authentication
integration layer.

Likewise, `VerifiedAuthority` retains the limited meaning recorded in ADR 0006:
it proves structural delegation validation against caller-supplied logical time
and revocation state, not cryptographic issuance or trusted roots.

## Canonical encoding and compatibility

New schemas are:

- `nest-authz/authority-context@1`;
- `nest-authz/authorization-request@2`;
- `nest-authz/subject-principal-binding@1`;
- `nest-authz/subject-authority-binding-status@1`;
- `nest-authz/subject-authority-binding-result@1`;
- `nest-authz/decision-evidence@5`;
- `nest-authz/decision@4`.

`authorization-request@2` replaces the `authority` field with
`authority_context` and encodes it using `authority-context@1`. The historical
`authority@1` and `authorization-request@1` schemas are not reinterpreted.
`decision-evidence@5` adds the holder-binding result, and `decision@4` records
the stronger construction semantics. Earlier schema identifiers remain
historical contracts but are not emitted for the renamed current objects.

Every new record and status has explicit type framing under ADR 0001. Digests
remain typed SHA-256 values. Constructor input ordering cannot affect any map
representation, and repeated evaluation produces equal records and bytes.

## Consequences

- Valid delegated authority is no longer usable as an implicit bearer
  capability.
- Callers must supply an explicit typed binding for any non-deny outcome.
- Policy-visible authority context and validated delegated authority are
  unmistakably separate concepts.
- Existing callers using `Authority`, `request.authority`, or the three-argument
  evaluator must migrate explicitly.
- The external binding assertion remains a security-critical trusted input
  until an authentication adapter is introduced.

## Rejected alternatives

### Compare identifier strings implicitly

Rejected because `Subject` and `Principal` are different namespaces. Equal or
similar text is not evidence of identity ownership.

### Treat validated authority as a bearer capability

Rejected because object possession alone would allow credential substitution.

### Put the binding inside `VerifiedAuthority`

Rejected because delegation validation does not receive or authenticate the
runtime request Subject. Combining them would obscure separate trust
boundaries.

### Let policy express or override holder binding

Rejected because policy must not widen authority or repair failed provenance.

### Retain `Authority` as an alias

Rejected because a compatibility name at this security boundary would continue
to invite confusion with delegated execution authority.
