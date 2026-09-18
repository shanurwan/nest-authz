# ADR 0008: Decision Receipts and Approval State Machine

- Status: Accepted
- Date: 2026-09-18
- Amended by: ADR 0009 approval authorization and execution revalidation;
  ADR 0012 atomic execution enforcement

> Amendment note: ADR 0009 supersedes the transition signatures that accepted
> an arbitrary `Principal`, the unauthenticated `decided_by` storage model, and
> consumption based on a caller-supplied current receipt. Current transitions
> require exact successful approver-authorization evidence, and consumption
> requires an `ExecutionPermit` produced by fresh revalidation. The sections
> below preserve the original ADR 0008 decision for historical clarity. ADR
> 0012 further establishes durable reservation of that exact permit as the
> authoritative duplicate-execution gate. A pure `CONSUMED` value remains
> useful audit state but does not provide cross-process single-use enforcement.

## Context

ADR 0004 produces deterministic policy decisions. ADR 0005 through ADR 0007
add delegation validation, request applicability, and holder binding. The
resulting `Decision` contains the evidence needed to explain one authorization
evaluation, but there is not yet a small immutable record that binds all of its
security-relevant identities for replay correlation. There is also no state
machine for independently satisfying multiple approval requirements.

Approval must never become a second source of authority. It must remain bound
to the exact request, policy, validated delegation state, holder evidence,
applicability evidence, and decision that originally required approval.

## Decision Receipt

`create_decision_receipt(decision)` creates an immutable `DecisionReceipt`.
Ordinary direct construction is blocked so the receipt cannot accidentally
contain caller-selected digests inconsistent with the supplied Decision.

A receipt contains:

- the request digest;
- the policy-bundle digest;
- the validated-authority digest, when validated authority was present;
- the delegation-chain digest, when delegation evidence was present;
- the authorization-state digest, when applicability evidence was present;
- the digest of the complete `SubjectAuthorityBindingResult`, when present;
- the digest of the complete `AuthorityApplicabilityResult`, when present;
- the digest of the final canonical `Decision`;
- the final `Outcome`; and
- the canonical complete set of approval requirements from the Decision.

Authority-related fields are optional only because fail-closed `DENY` decisions
can be produced before every authority gate exists. Their absence is encoded
explicitly as null. A `PERMIT` or `APPROVAL_REQUIRED` receipt requires the full
successful authority, chain, state, binding-evidence, and applicability-
evidence digest set.

The receipt does not contain its own digest. Its content identity is derived
only as:

```text
sha256_digest(receipt)
```

The receipt provides deterministic content identity and replay correlation. It
is not a cryptographic signature and does not prove issuer authenticity,
freshness, delivery, possession, or non-repudiation.

## Pending Approval

`create_pending_approval(receipt, logical_time)` accepts only a receipt whose
outcome is `APPROVAL_REQUIRED`. Receipts for `PERMIT` or `DENY` are rejected.

`PendingApproval` stores the exact `DecisionReceipt`, its SHA-256 content
digest, one state for every receipt approval requirement, the latest explicit
logical transition time, a derived overall status, and an optional consumption
time. The name represents the approval lifecycle; an instance remains a
`PendingApproval` value after it becomes approved, rejected, expired, or
consumed.

The requirement set is copied from the receipt. Construction and every
transition require the requirement states to contain exactly that complete set,
with no additions, omissions, or duplicates. Requirement ordering is
non-semantic and follows the existing canonical `ApprovalRequirement` order.

## Requirement Approval State

`ApprovalRequirementStatus` has exactly:

- `PENDING`
- `APPROVED`
- `REJECTED`
- `EXPIRED`

Each `ApprovalRequirementState` contains:

- the exact `ApprovalRequirement`;
- its typed status;
- `decided_by: Principal | None`; and
- the explicit logical time at which the current state was established.

`APPROVED` and `REJECTED` require `decided_by`. It identifies the approver or
rejector respectively. `PENDING` and `EXPIRED` prohibit it. This core makes no
authentication claim about that Principal.

## Overall Approval Status

`ApprovalStatus` has exactly:

- `PENDING`
- `APPROVED`
- `REJECTED`
- `EXPIRED`
- `CONSUMED`

Overall status is derived rather than caller-selected. Version 1 uses this
precedence:

1. A valid consumption marker produces `CONSUMED`.
2. Otherwise, any rejected requirement produces `REJECTED`.
3. Otherwise, any expired requirement produces `EXPIRED`.
4. Otherwise, if every requirement is approved, the result is `APPROVED`.
5. Otherwise, the result is `PENDING`.

Rejection therefore wins over expiry when both exist. Expiry wins over a mix
of pending and approved requirements. Consumption is possible only from an
all-approved state.

## Pure Transitions

The public transition operations are:

```text
approve_requirement(approval, requirement, approver, logical_time)
reject_requirement(approval, requirement, rejector, logical_time)
expire_requirement(approval, requirement, logical_time)
consume_approval(approval, current_receipt, logical_time)
```

Every function validates exact domain types, reads no external state, mutates
nothing, and returns a new immutable value. Transition logical time must be an
exact integer and must not precede the approval's latest logical time. Equal
logical times are allowed so independently recorded events may share one
logical instant.

`ApprovalTransitionError` is the deterministic typed failure boundary for
invalid transitions, unknown requirements, receipt mismatch, logical-time
regression, and attempts to change consumed state. Invalid transitions never
silently succeed.

## Transition Table

Requirement transitions are:

| Current | Operation | Next | Actor |
| --- | --- | --- | --- |
| `PENDING` | approve | `APPROVED` | required Principal |
| `PENDING` | reject | `REJECTED` | required Principal |
| `PENDING` | expire | `EXPIRED` | none |

Every transition from an `APPROVED`, `REJECTED`, or `EXPIRED` requirement is
invalid. There is no operation that resets a requirement to `PENDING`.

Overall consumption is:

| Current overall status | Consume |
| --- | --- |
| `APPROVED` | `CONSUMED` |
| `PENDING` | invalid |
| `REJECTED` | invalid |
| `EXPIRED` | invalid |
| `CONSUMED` | invalid |

Individual still-pending requirements may be recorded after another
requirement has rejected or expired; this preserves independent audit state.
The rejection/expiry precedence means doing so cannot recover an approved
overall result.

## Exact Receipt Binding and Stale Approval

`PendingApproval` embeds the exact receipt and its digest. `consume_approval`
requires a current receipt argument and compares it with that embedded receipt
and digest. An approval created for receipt A cannot be consumed for receipt B.

Any change to the request Subject, Action, Resource, constrained Context,
policy bundle, delegation chain, authorization state, holder-binding evidence,
applicability evidence, or final Decision changes one or more receipt fields
and therefore changes `sha256_digest(receipt)`.

An approved `PendingApproval` does not independently authorize execution.
Before protected execution, future orchestration must revalidate or recompute
authorization and supply the corresponding current receipt. Approval cannot:

- revive revoked or expired authority;
- widen delegated scope;
- bypass failed holder binding;
- bypass a `DENY`;
- apply to a changed request;
- apply to a changed policy bundle; or
- replace current authorization-state validation.

Receipt equality proves only that the supplied content is the same. This core
does not establish that the caller actually obtained fresh external state.

## Logical Expiry

Version 1 models expiry as the explicit `expire_requirement` transition at a
caller-supplied logical time. It does not define an automatic deadline or read
the wall clock. Deadline calculation and the authority to assert expiry remain
future orchestration concerns. This avoids silently inventing ambient-time
semantics.

## Canonical Encoding

ADR 0001 framing remains unchanged. New schemas are:

- `nest-authz/decision-receipt@1`
- `nest-authz/approval-requirement-status@1`
- `nest-authz/approval-status@1`
- `nest-authz/approval-requirement-state@1`
- `nest-authz/pending-approval@1`

Receipt and approval-state fields are named, typed, and deterministic.
Requirement-state ordering is non-semantic and canonicalized by complete
`ApprovalRequirement` identity. Existing `Decision`, `DecisionEvidence`, and
all preceding schemas are unchanged because this ADR adds downstream values
without changing their meaning.

## Distributed Consumption Limitation

This pure immutable state machine cannot by itself prevent distributed double
consumption. Two processes can independently read the same approved value and
both derive equal consumed values. Deterministic state transition is not an
atomic coordination mechanism.

Future persistence or orchestration must provide atomic compare-and-swap,
optimistic concurrency with a checked prior digest, or an equivalent
transactional transition from `APPROVED` to `CONSUMED`. Protected operation
execution must be coordinated with that transition. No persistence or
execution mechanism is introduced here.

## Consequences and Limitations

- Security-relevant authorization input and output identities are correlated
  by one deterministic receipt.
- Multiple requirements progress independently without boolean ambiguity.
- Approval replay against changed receipt content is rejected by the pure
  consumption boundary.
- All time is explicit logical input.
- Receipt and approval identity are stable across processes and Python hash
  seeds.
- Receipts and approval actors are not authenticated or signed.
- The state machine does not execute obligations, approvals, or protected
  operations.
- The state machine does not prevent distributed races without future atomic
  persistence.
- No signing, JWT/DID verification, key management, HTTP, database, background
  worker, NandaTown integration, or external service is introduced.

## Rejected Alternatives

### Boolean approval

Rejected because it cannot represent independent pending, rejection, expiry,
or consumption states and loses the actor and logical transition evidence.

### Receipt containing its own digest

Rejected because it creates self-referential content identity. The digest is
always derived externally with `sha256_digest(receipt)`.

### Ambient timestamps

Rejected because wall-clock reads make replay and testing nondeterministic.

### Treat approval as authority

Rejected because approval may satisfy a requirement only for authority that is
still valid, holder-bound, applicable, and policy-compatible.

### Silently accept repeated transitions

Rejected because audit and incident diagnosis must distinguish a valid event
from a stale or replayed state transition.
