# ADR 0003: Policy Model and Combining Semantics

- Status: Accepted
- Date: 2026-09-18

## Problem

NEST AuthZ needs an immutable policy representation before policy evaluation can
be implemented. The representation must be deterministic, fail closed, exclude
executable policy content, and have an order-independent content identity where
order does not affect authorization semantics.

This ADR defines the version-1 policy domain and its semantics. It does not
implement condition resolution, rule matching execution, policy evaluation,
approval processing, or obligation execution.

## PolicyBundle

`PolicyBundle` contains an immutable collection of `Policy` records and a fixed
version-1 combining marker, `DENY_OVERRIDES`.

Policy order has no authorization meaning. Construction defensively copies and
sorts policies by the strict UTF-8 bytes of their identifiers. Duplicate policy
identifiers within a bundle are invalid.

An empty bundle is legal. It contains no matching rules and therefore has the
safe semantic result of default deny.

A bundle MUST NOT contain its own digest. Its content identity is derived
externally with `sha256_digest(bundle)`, avoiding self-referential hashing.

## Policy

`Policy` contains:

- a stable, nonblank semantic identifier; and
- an immutable collection of `Rule` records.

The identifier identifies the policy for evidence and configuration purposes;
it is not a content digest.

Rule order has no authorization meaning under `DENY_OVERRIDES`. Construction
defensively copies and sorts rules by the strict UTF-8 bytes of their
identifiers. Duplicate rule identifiers within one policy are invalid. The same
rule identifier may occur in different policies because its identity is scoped
by the policy identifier.

An empty policy is legal and inert. It cannot grant authority and contributes no
matching rule to combination.

## Rule

`Rule` contains:

- a stable, nonblank semantic identifier;
- one `RuleEffect`;
- one or more `Condition` records;
- zero or more immutable `Obligation` records; and
- an optional `ApprovalRequirement`.

Condition order has no matching meaning because conditions form a conjunction.
Construction defensively copies conditions, rejects duplicate structural
conditions, and sorts them by their complete structural value.

Obligation order is preserved. Existing decision-domain semantics allow order
to express enforcement order, so reordering obligations is a meaningful policy
change and changes canonical bytes.

### Zero-condition rules

Version 1 rejects rules with zero conditions. Vacuous truth would make such a
rule unconditional, and an accidentally empty `PERMIT` or
`APPROVAL_REQUIRED` rule would be dangerous. Unconditional deny does not need a
special rule because default deny already provides the safe fallback. Rejecting
all zero-condition rules keeps one uniform construction invariant.

## RuleEffect

`RuleEffect` is distinct from decision `Outcome`, even though version 1 uses the
same three labels:

- `PERMIT`
- `DENY`
- `APPROVAL_REQUIRED`

A rule with `APPROVAL_REQUIRED` MUST carry an `ApprovalRequirement`. A rule
with `PERMIT` or `DENY` MUST NOT carry one. Rules of any effect may carry
obligations; this ADR represents those obligations but does not execute them.

## FieldReference and FieldNamespace

`FieldReference` contains exactly:

- one `FieldNamespace`; and
- one nonblank direct field name.

Version 1 namespaces are:

- `SUBJECT`
- `ACTION`
- `RESOURCE`
- `CONTEXT`
- `AUTHORITY`

The field name is a literal, single reference component. Punctuation in the
name is not parsed. Version 1 defines no dot navigation, indexes, nested object
traversal, method calls, or expression language. Resolution of valid direct
field names is deferred to the future evaluator.

## Condition and ConditionOperator

`Condition` contains one typed `FieldReference`, one `ConditionOperator`, and an
operator-compatible immutable literal value.

Version 1 operators are:

- `EQUALS`
- `NOT_EQUALS`
- `EXISTS`
- `INTEGER_LESS_THAN`
- `INTEGER_LESS_THAN_OR_EQUAL`
- `INTEGER_GREATER_THAN`
- `INTEGER_GREATER_THAN_OR_EQUAL`

Construction enforces these structural combinations:

- `EXISTS` has no operand and therefore requires `value=None`.
- `EQUALS` and `NOT_EQUALS` require `str`, exact `int`, or `bool`.
- Integer comparison operators require an exact `int`. Python booleans are
  rejected even though `bool` subclasses `int`.
- All other values, including callables and mutable objects, are rejected.

Null equality is not part of version 1. `None` is reserved as the absence of an
operand for `EXISTS`. A future null-test operator would require a versioned
schema decision.

Conditions are declarative data. They cannot contain Python functions, lambdas,
callbacks, plugins, regexes, wildcards, CEL, SQL, Python expressions, or
user-defined operators. String values and field names are always treated as
literal data and are never executed.

## Rule Matching Semantics

A rule matches if and only if every condition has status `SATISFIED`.

- Any `UNSATISFIED` condition makes the rule not match.
- A `NOT_EVALUATED` condition means the all-satisfied requirement was not met,
  so the rule does not match.
- `MISSING_INPUT` and `ERROR` are fail-closed evaluation failures under
  security-model invariant INV-010, not ordinary non-matches. If either status
  occurs while considering the bundle, the final decision MUST be `DENY` even
  if another rule would otherwise contribute `PERMIT` or
  `APPROVAL_REQUIRED`.

`EXISTS` is satisfied when the referenced direct field is present and
unsatisfied when it is absent. For operators that require a value, an absent
field yields `MISSING_INPUT`. Integer operators require the resolved field value
to be an exact integer; incompatible types are evaluation errors. `EQUALS` and
`NOT_EQUALS` use type-sensitive scalar comparison.

These semantics constrain a future evaluator but no matching code is introduced
by this decision.

## Policy Combining Semantics

Version 1 uses the explicit, fixed `DENY_OVERRIDES` algorithm. After all rules
have been considered, matching rule effects combine as follows:

1. If any matching rule has `DENY`, the final outcome is `DENY`.
2. Otherwise, if any matching rule has `APPROVAL_REQUIRED`, the final outcome is
   `APPROVAL_REQUIRED`.
3. Otherwise, if any matching rule has `PERMIT`, the final outcome is `PERMIT`.
4. Otherwise, the final outcome is the default `DENY`.

All matching rules across all policies in the bundle participate in this
combination. Policy order, rule order, and condition order MUST NOT change the
authorization result. Numeric priority is not defined or represented.

Condition-evaluation failures are handled by the fail-closed rule above before
matching effects are combined. The combining precedence applies only after a
failure-free evaluation and does not weaken INV-010.

## Ordering and Canonical Identity

The following order is non-semantic and is canonicalized during construction:

- policies within a bundle;
- rules within a policy; and
- conditions within a rule.

Canonicalization sorts policies and rules by UTF-8 identifier bytes and
conditions by complete typed structural value. This makes semantically
equivalent constructor orderings equal and gives them identical canonical bytes
and bundle digests. Duplicate policy IDs, duplicate rule IDs within a policy,
and duplicate structural conditions are rejected rather than silently dropped.

Obligation order remains semantic and is preserved. No other ordering or
priority field exists.

## Canonical Schemas

ADR 0001 remains the framing specification. Version 1 adds these stable wire
schema identifiers:

- `nest-authz/field-namespace@1`
- `nest-authz/field-reference@1`
- `nest-authz/condition-operator@1`
- `nest-authz/condition@1`
- `nest-authz/rule-effect@1`
- `nest-authz/rule@1`
- `nest-authz/policy@1`
- `nest-authz/policy-bundle@1`

The policy-bundle record includes the fixed `DENY_OVERRIDES` combining marker.
It does not include a digest field.

## Consequences and Limitations

- Policy content is immutable, type constrained, and canonically serializable.
- Irrelevant policy, rule, and condition ordering cannot change a bundle digest.
- Semantic identifiers remain distinct from content-derived SHA-256 identity.
- Arbitrary executable policy content cannot be represented.
- Empty policies and bundles are safe inert values; zero-condition rules are
  rejected.
- Obligation aggregation across multiple matching rules is not yet defined.
- Combining multiple approval requirements is not yet defined.
- Direct field resolution and the set of valid field names per namespace remain
  evaluator responsibilities.
- This ADR does not implement evaluation, delegation, revocation, approval
  processing, obligation execution, APIs, persistence, signing, key management,
  or NandaTown integration.
