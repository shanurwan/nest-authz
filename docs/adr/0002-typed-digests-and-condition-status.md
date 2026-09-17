# ADR 0002: Typed SHA-256 Digests and Condition Status

- Status: Accepted
- Date: 2026-09-18

## Problem

`DecisionEvidence` currently accepts a policy-bundle identifier as an arbitrary
string. That permits malformed, unlabeled, or non-content-derived values even
though the security model requires decisions to identify the exact evaluated
policy bundle with a stable digest or equivalent content-derived identifier.

Decision evidence also records each condition result as a boolean. A boolean
can describe an evaluated true or false condition, but it cannot distinguish a
condition that was skipped, could not be evaluated because input was missing,
or failed during evaluation. Collapsing those states loses evidence needed for
audit review and incident diagnosis.

## Decision

### Typed SHA-256 digest

Introduce a frozen, slotted `Sha256Digest` domain record with:

- an explicit, fixed algorithm value of `sha256`;
- exactly 32 immutable digest bytes;
- construction from exactly 64 lowercase hexadecimal characters; and
- canonical text in the form `sha256:<64 lowercase hex>`.

Only SHA-256 is supported. A generic algorithm registry or digest hierarchy is
not introduced. `sha256_digest()` returns `Sha256Digest` rather than an
unlabeled string.

`DecisionEvidence.policy_bundle_id` is replaced by
`DecisionEvidence.policy_bundle_digest: Sha256Digest`. This binds evidence to a
well-formed content digest without inventing a `PolicyBundle` domain type or
claiming that this layer can verify which policy content produced the digest.

### Condition evaluation status

Introduce `ConditionStatus` with exactly these values:

- `SATISFIED`: the condition was evaluated and succeeded;
- `UNSATISFIED`: the condition was evaluated and failed;
- `NOT_EVALUATED`: the condition was intentionally not evaluated or was not
  reached;
- `MISSING_INPUT`: evaluation could not proceed because required input was
  absent; and
- `ERROR`: evaluation was attempted but failed.

`DecisionEvidence.condition_results` maps condition names to these statuses.
The domain model records statuses only; it does not determine them and does not
perform policy evaluation.

## Why Boolean Results Are Insufficient

Treating every non-success state as `False` makes materially different events
indistinguishable. An explicit policy rejection, a short-circuited condition,
missing mandatory context, and an evaluation error have different security and
operational implications.

The explicit status supports:

- determining whether a deny was policy-driven or caused by incomplete input;
- distinguishing expected short-circuiting from evaluator failure;
- investigating fail-closed behavior without reconstructing transient runtime
  state; and
- producing machine-readable evidence without relying on prose messages.

## Canonical Representation

ADR 0001 remains the framing specification. These stable wire schemas are
added:

- `nest-authz/sha256-digest@1`, containing named `algorithm` and `value` string
  fields; and
- `nest-authz/condition-status@1`, containing a named `value` string field.

The digest `value` field contains exactly 64 lowercase hexadecimal characters.
Including the algorithm field makes the algorithm explicit in both the domain
record and canonical bytes.

Decision evidence changes incompatibly from a free-form policy identifier and
boolean condition values. Its wire schema advances from
`nest-authz/decision-evidence@1` to `nest-authz/decision-evidence@2` and contains
`policy_bundle_digest` plus condition-status records.

## Rejected Alternatives

### Keep the policy digest as a string

A string cannot enforce the algorithm, byte length, alphabet, or canonical
case. Prefix conventions alone would remain caller discipline rather than a
construction invariant.

### Introduce a generic multi-algorithm digest abstraction

There is no current requirement for another algorithm. A registry, hierarchy,
or algorithm negotiation mechanism would be speculative and would enlarge the
security surface.

### Retain boolean condition results

Boolean results erase whether a condition was false, skipped, missing input, or
failed. Optional booleans add only one extra state and still cannot represent
the required distinctions clearly.

### Store condition status in reason messages

Free-form text is unsuitable for deterministic machine processing and makes
auditing depend on message wording.

## Consequences and Limitations

- Malformed SHA-256 values fail during construction.
- Digest text and canonical bytes always identify the algorithm explicitly.
- Decision evidence cannot carry an arbitrary policy-bundle identifier.
- Condition evidence preserves operationally distinct non-success states.
- Existing callers must replace strings and booleans with typed values.
- The digest proves content equality only; it does not authenticate origin,
  verify a signature, establish freshness, or perform authorization.
- This decision does not define policy content, policy evaluation, signing,
  cryptographic key management, or how an evaluator assigns condition status.
