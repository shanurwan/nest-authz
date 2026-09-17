# ADR 0004: Deterministic Evaluator Semantics

- Status: Accepted
- Date: 2026-09-18

## Problem

NEST AuthZ needs its first authorization evaluator. The evaluator must be a
pure, deterministic function of an immutable `AuthorizationRequest` and
`PolicyBundle`, while preserving complete evidence and failing closed when a
potentially applicable rule cannot be evaluated.

Before evaluation can be implemented, the policy model also needs stable
condition identities, support for multiple approval requirements, and a safer
rule against empty policies.

This decision supersedes the affected model details in ADR 0003. It does not
introduce APIs, persistence, external services, signing, key management,
delegation, revocation, approval processing, or NandaTown integration.

## Policy Model Amendments

### Condition identity

Every `Condition` has a stable, nonblank semantic identifier. The identifier is
chosen by the policy author for audit and evidence correlation; it is not a
content hash.

Condition identifiers are unique within a `Rule`. A Rule also rejects repeated
structurally identical predicates under different identifiers because they add
no authorization meaning and most likely indicate an authoring error.

Condition order remains non-semantic. Conditions are stored in identifier order
using strict UTF-8 bytes.

### Approval requirements

`Rule.approval_requirements` and `Decision.approval_requirements` are immutable
collections rather than singular optional values.

- An `APPROVAL_REQUIRED` Rule or Decision has at least one requirement.
- A `PERMIT` or `DENY` Rule or Decision has no requirements.
- Requirement order is non-semantic and is canonicalized by complete typed
  structural value.
- Exact duplicates within one Rule or Decision are invalid. Exact duplicates
  contributed by separate matching rules are deduplicated during aggregation.
- Every distinct requirement from every matching `APPROVAL_REQUIRED` rule is
  retained. The evaluator never chooses one requirement arbitrarily.

This decision represents approval requirements only. It does not process or
satisfy approvals.

### Empty policies and bundles

An empty `PolicyBundle` is valid and evaluates to the explicit safe default
`DENY`.

A `Policy` with zero Rules is invalid. It can never affect a result and is more
likely an authoring or configuration mistake than an intentional security
construct. This distinction keeps an explicit empty deployment state while
rejecting inert named configuration.

## Public Evaluation API

The evaluator exposes one pure operation:

```text
evaluate(
    request: AuthorizationRequest,
    bundle: PolicyBundle,
) -> Decision
```

Only exact domain types are accepted. Evaluation reads no time, randomness,
network, environment variables, filesystem state, database, callback, plugin,
or mutable global state. It generates no random decision identifier.

## Closed Field Resolution

Field resolution is an explicit branch over `FieldNamespace`. It performs no
`eval`, `exec`, reflection, arbitrary `getattr`, callback, plugin invocation, or
nested traversal.

Version 1 resolves only:

| Namespace | Supported direct fields |
| --- | --- |
| `SUBJECT` | `identifier` |
| `ACTION` | `name` |
| `RESOURCE` | `identifier` |
| `CONTEXT` | an exact direct key in `RequestContext.attributes` |
| `AUTHORITY` | `identifier`, or an exact direct key in `Authority.attributes` |

An unsupported fixed-record field is `ERROR`. A missing direct context or
authority attribute is absent, without any attempt to interpret punctuation as
traversal.

If the request has no Authority, every `AUTHORITY` reference produces
`MISSING_INPUT`, including `EXISTS`. This represents absence of the authority
object, not merely absence of one attribute.

## EXISTS Semantics

`EXISTS` tests presence, never truthiness. A direct context or authority key
whose value is `None`, `False`, zero, or an empty string is present and produces
`SATISFIED`. An absent direct key produces `UNSATISFIED`.

For operators other than `EXISTS`, an absent direct key produces
`MISSING_INPUT`.

## Exact Scalar Types

Comparison never coerces values. Python `bool` is not treated as `int`, and
`True` is distinct from `1`.

`EQUALS` and `NOT_EQUALS` require the actual value and policy operand to have
the exact same supported scalar type. A type mismatch produces `ERROR`, rather
than `UNSATISFIED`. A mismatch indicates a policy/input contract defect; making
it an error prevents a `NOT_EQUALS` rule from granting access merely because
Python values have different types.

Integer operators require the resolved actual value to have exact type `int`.
A boolean, string, null, or any other value produces `ERROR`.

## Condition Evaluation

Every condition in every Rule is evaluated exactly once during normal version-1
evaluation. A condition produces one of:

- `SATISFIED`
- `UNSATISFIED`
- `MISSING_INPUT`
- `ERROR`

`NOT_EVALUATED` is not emitted by the version-1 evaluator. It remains reserved
for a future explicitly versioned evaluation strategy.

## Rule Evaluation

`RuleEvaluationStatus` has exactly:

- `MATCHED`
- `NOT_MATCHED`
- `INDETERMINATE`

After every condition in a Rule is evaluated, statuses combine without regard
to condition order:

1. If any condition is `UNSATISFIED`, the Rule is `NOT_MATCHED`.
2. Otherwise, if any condition is `MISSING_INPUT` or `ERROR`, the Rule is
   `INDETERMINATE`.
3. Otherwise, all conditions are `SATISFIED` and the Rule is `MATCHED`.

Thus `UNSATISFIED AND UNKNOWN` is `NOT_MATCHED`, because the conjunction cannot
match regardless of the unavailable value. `SATISFIED AND UNKNOWN` is
`INDETERMINATE`, because the unavailable value could change whether the Rule
matches.

## Final Combining

Every Rule in every Policy is evaluated. If any Rule is `INDETERMINATE`, the
final outcome is `DENY`; a matching `PERMIT` cannot mask the indeterminate Rule.

Otherwise, matching effects use `DENY_OVERRIDES`:

1. Any matching `DENY` produces `DENY`.
2. Otherwise, any matching `APPROVAL_REQUIRED` produces
   `APPROVAL_REQUIRED`.
3. Otherwise, any matching `PERMIT` produces `PERMIT`.
4. Otherwise, the default is `DENY`.

If `request.authority` is absent, the final outcome is `DENY` regardless of
matching effects. Version 1 treats the supplied Authority as explicit input; it
does not validate cryptographic authenticity, expiry, revocation, delegation,
or provenance.

Policy, Rule, Condition, and caller collection order cannot change the semantic
Decision.

## Evidence

`RuleEvaluation` is an immutable evidence record containing:

- policy identifier;
- rule identifier;
- rule effect;
- `RuleEvaluationStatus`; and
- every condition identifier paired with its `ConditionStatus`.

`DecisionEvidence` contains the exact `sha256_digest(bundle)`, every Rule
evaluation, and the request Authority when one was supplied. Deterministic
derived views identify matched policy and Rule identifiers, all condition
results, indeterminate Rule identifiers, and indeterminate conditions.

Rule identifiers remain scoped by policy identifier in evidence. No Python
`hash()`, random identifier, or timestamp is used.

## Obligations

For `PERMIT`, obligations from every matching `PERMIT` Rule are returned.

For `APPROVAL_REQUIRED`, obligations from every matching `PERMIT` and
`APPROVAL_REQUIRED` Rule are returned.

For `DENY`, no execution obligations from otherwise permitting rules are
returned.

Rule-local obligation order remains semantic. Cross-rule aggregation follows
the canonical policy and Rule order. Exact duplicate obligations are removed by
equality without using Python hashes; all distinct obligations remain mandatory.
No generic conflict resolution is defined.

## Approval Requirement Aggregation

For `APPROVAL_REQUIRED`, requirements from every matching
`APPROVAL_REQUIRED` Rule are combined. Exact duplicates are removed and all
distinct requirements are retained. The Decision constructor canonicalizes the
result because requirement ordering is non-semantic.

No requirements are returned for `PERMIT` or `DENY`.

## Failure Boundary

Expected policy outcomes and input problems are represented by condition
statuses and fail-closed Decisions. Impossible internal enum or aggregation
states raise a typed `EvaluationError`.

The evaluator does not broadly catch programming exceptions and turn them into
a Decision, because doing so could fabricate incomplete or misleading evidence.
The caller is the trust boundary and MUST treat `EvaluationError` or any other
unexpected exception as denial/no execution. No exception path can produce
`PERMIT`.

## Canonical Schema Versions

ADR 0001 framing remains version 1. The model changes advance affected record
schemas instead of silently changing existing meanings:

- `nest-authz/condition@2` adds the semantic identifier.
- `nest-authz/rule@2` contains identified conditions and plural approval
  requirements.
- `nest-authz/policy@2` rejects an empty Rules collection and contains Rule
  schema version 2.
- `nest-authz/policy-bundle@2` contains Policy schema version 2.
- `nest-authz/decision-evidence@3` contains typed Rule evaluations and request
  Authority evidence.
- `nest-authz/decision@2` contains plural approval requirements.

New records use:

- `nest-authz/rule-evaluation-status@1`
- `nest-authz/rule-evaluation@1`

The unchanged field-reference, operator, effect, obligation, approval-
requirement, digest, Outcome, and condition-status records retain their existing
schema versions.

## Consequences and Limitations

- Evaluation is deterministic, pure, complete over the closed version-1 model,
  and independently reproducible.
- Complete Rule and condition evidence explains matches, non-matches, and
  indeterminate failures.
- Equality and integer comparisons cannot inherit Python's boolean/integer
  equivalence.
- Authority presence is required for non-deny outcomes, but Authority
  authenticity is outside this evaluator.
- No obligation conflict-resolution language exists; all distinct returned
  obligations are mandatory.
- No approval is processed or recorded as satisfied.
- No decoder, API, persistence, external service, signing, key management,
  delegation, revocation, or NandaTown integration is introduced.
