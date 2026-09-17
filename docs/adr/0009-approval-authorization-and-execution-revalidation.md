# ADR 0009: Approval Authorization and Execution Revalidation

- Status: Accepted
- Date: 2026-09-18
- Amends: ADR 0008 approval actors and consumption boundary

## Context

ADR 0008 binds approval state to an exact authorization `DecisionReceipt`, but
it leaves two separate security gaps.

### Approval identity is not approval authority

An external identity boundary may assert that an approver Subject represents a
Principal. That assertion establishes identity consistency only. It does not
authorize that Principal to satisfy an `ApprovalRequirement`. Requirement code
names such as `MANAGER_APPROVAL` are human/audit identifiers, not roles,
groups, capabilities, or authorization rules.

### Receipt identity is not execution equivalence

A receipt is an exact content snapshot. Requiring a byte-identical receipt at
execution time would also require an identical `AuthorizationState`. That is
too strict: logical time may advance and unrelated grants may be revoked while
the approved request, policy, delegation chain, and relevant authority remain
valid.

Content identity answers whether every encoded input and output is identical.
Security equivalence answers whether the immutable approved intent still passes
all current authority and policy gates. The original receipt remains unchanged;
fresh revalidation establishes the latter.

## Approver Authorization Model

### ApprovalRequirement

`ApprovalRequirement` version 2 contains:

- a nonblank descriptive code;
- a nonempty immutable set of allowed `Principal` values; and
- immutable scalar parameters.

Allowed-Principal order is non-semantic. Construction defensively copies,
rejects duplicates, and sorts by strict UTF-8 identifier bytes. Version 1 has
no roles, groups, wildcards, regexes, expressions, directory queries, or
inferred authority. Knowing a requirement code never authorizes a Principal.

### Approver binding

`ApproverSubjectPrincipalBinding` is a typed immutable assertion supplied by a
future identity boundary. It relates the runtime approver `Subject` to one
`Principal`. It is deliberately distinct from `SubjectPrincipalBinding`, which
binds the requesting Subject to an authority holder.

The core treats the approver binding as trusted input and checks consistency.
It does not prove authentication, identity-provider provenance, possession of
a private key, or cryptographic authenticity.

### Authorization check and evidence

The pure operation is:

```text
check_approver_authorization(
    actor,
    binding,
    required_requirement,
    attempted_requirement,
) -> ApproverAuthorizationResult
```

The explicit required/attempted pair makes reuse of evidence for another
requirement observable rather than collapsing it into a missing lookup.

`ApproverAuthorizationStatus` is:

- `AUTHORIZED`
- `SUBJECT_MISMATCH`
- `PRINCIPAL_NOT_ALLOWED`
- `REQUIREMENT_MISMATCH`

Status precedence is:

1. unequal required and attempted requirements -> `REQUIREMENT_MISMATCH`;
2. actor Subject unequal to binding Subject -> `SUBJECT_MISMATCH`;
3. bound Principal absent from the required allowed set ->
   `PRINCIPAL_NOT_ALLOWED`;
4. otherwise -> `AUTHORIZED`.

The result preserves all compared typed values. Its constructor derives the
only valid status from those values.

## Approval Transitions

`approve_requirement()` and `reject_requirement()` now require an
`ApproverAuthorizationResult`. The result must be `AUTHORIZED` and must name
the exact requirement being transitioned. An arbitrary Principal is no longer
sufficient.

Rejection uses the same authorization rule as approval in version 1. Allowing
an unauthorized actor to reject would give that actor denial authority over a
request. Separate reject authority would require an explicit future model.

`ApprovalRequirementState` retains the complete authorization result for an
approved or rejected transition. Its `decided_by` view is the authorized bound
Principal. Pending and expired states carry no approver-authorization result.
Expiry remains an explicit logical/system transition and requires no actor.

## Execution Revalidation

The pure operation is:

```text
revalidate_for_execution(
    original_receipt,
    approved_state,
    current_request,
    current_policy_bundle,
    current_delegation_chain,
    current_authorization_state,
    current_subject_binding,
) -> ExecutionAuthorizationResult
```

It recomputes, from current supplied values:

1. delegated-authority validation;
2. request/holder binding when validation succeeds;
3. authority applicability when validation succeeds; and
4. policy evaluation.

The result is typed evidence rather than a boolean. Version 1 statuses are:

- `AUTHORIZED`
- `APPROVAL_NOT_APPROVED`
- `RECEIPT_MISMATCH`
- `REQUEST_MISMATCH`
- `DELEGATION_CHAIN_MISMATCH`
- `AUTHORITY_INVALID`
- `HOLDER_BINDING_FAILED`
- `AUTHORITY_NOT_APPLICABLE`
- `POLICY_DENIED`
- `POLICY_REAUTHORIZATION_REQUIRED`
- `APPROVAL_REQUIREMENTS_CHANGED`
- `POLICY_BUNDLE_MISMATCH`

All current digests and recomputed validation, binding, applicability, and
decision evidence that exist are preserved in the result.

## Receipt Identity and Security Equivalence

The original `DecisionReceipt` remains the immutable audit snapshot that was
approved. It is never weakened, rewritten, or replaced.

Execution requires all of these stable security semantics:

- `approved_state` is `APPROVED`, embeds the exact original receipt, and has
  the corresponding receipt digest;
- current request digest equals the original request digest;
- current policy-bundle digest equals the original policy-bundle digest;
- current delegation-chain digest equals the original chain digest;
- fresh delegation validation is `VALID` against current state;
- fresh holder binding is `BOUND`;
- fresh authority applicability is `APPLICABLE`;
- fresh policy result is `APPROVAL_REQUIRED`; and
- its complete approval-requirement set equals the approved set.

The current `AuthorizationState` digest, `VerifiedAuthority` digest, binding
evidence digest, applicability evidence digest, and Decision digest are allowed
to differ from the historical receipt. They describe fresh evidence. Success
depends on their semantics, not equality with stale evidence.

Failure precedence is deterministic. Lifecycle/receipt mismatch is considered
first, followed by request and chain identity, current authority validity,
holder binding, applicability, fresh policy outcome, changed requirements, and
other policy-content change. A current policy `DENY` is reported as denial even
when the bundle also changed. A current `PERMIT` returns
`POLICY_REAUTHORIZATION_REQUIRED`: version 1 conservatively refuses to turn an
old approval into execution authority after approval semantics disappear.

## Dynamic Logical Time and Revocation

Logical time may advance. Approval at logical time 100 may execute at time 130
when the same request, policy, and chain still validate, holder binding and
scope still apply, and approval requirements remain identical.

Grant validity remains half-open. If a relevant grant has `valid_until=120`,
revalidation at 130 returns current authority `EXPIRED` and cannot create an
execution permit.

Adding an unrelated revoked grant changes the complete `AuthorizationState`
digest but does not invalidate a chain that does not contain that grant. Fresh
validation examines the relevant chain. Revocation of any relevant ancestor or
leaf invalidates the authority and approval cannot resurrect it.

## ExecutionPermit

Only a fully successful revalidation creates `ExecutionPermit`. Ordinary
construction is blocked with the same module-capability pattern used for
`VerifiedAuthority` and receipt-bound approval records.

The permit binds:

- the original approved receipt digest;
- the exact approved `PendingApproval` digest;
- current request and policy-bundle digests;
- current delegation-chain and authorization-state digests;
- current validated-authority digest;
- complete current holder-binding evidence;
- complete current authority-applicability evidence; and
- the fresh `APPROVAL_REQUIRED` Decision.

It contains no self-digest. Its content identity is
`sha256_digest(execution_permit)`.

An execution permit proves deterministic internal consistency only. It is not
a signature and provides no issuer authenticity or non-repudiation.

## Consumption

`consume_approval()` requires the exact successful `ExecutionPermit`. It
checks that the permit names both the original receipt and the exact approved
state being consumed. `ApprovalStatus.APPROVED` alone is insufficient.

The pure transition still cannot prevent two processes from consuming the same
approved value independently. Future persistence must atomically compare and
swap the exact pending-approval identity from `APPROVED` to `CONSUMED` while
binding the transition to the exact execution permit. No persistence or
protected-operation execution is introduced here.

## Canonical Schemas and Versioning

New schemas are:

- `nest-authz/approver-subject-principal-binding@1`
- `nest-authz/approver-authorization-status@1`
- `nest-authz/approver-authorization-result@1`
- `nest-authz/execution-authorization-status@1`
- `nest-authz/execution-authorization-result@1`
- `nest-authz/execution-permit@1`

The explicit allowed-Principal set and approval-evidence semantics advance
affected schemas:

- `approval-requirement@1` -> `approval-requirement@2`
- `rule@2` -> `rule@3`
- `policy@2` -> `policy@3`
- `policy-bundle@2` -> `policy-bundle@3`
- `approval-requirement-state@1` -> `approval-requirement-state@2`
- `decision@4` -> `decision@5`
- `decision-receipt@1` -> `decision-receipt@2`
- `pending-approval@1` -> `pending-approval@2`

`DecisionEvidence` fields and meaning do not change, so
`decision-evidence@5` remains current. Historical identifiers retain their
documented meanings and are not silently reused.

## Consequences and Limitations

- Approver authentication and approval authorization are separate.
- Exact Principal allowlists keep version 1 mechanically closed and
  deterministic.
- Approval cannot create, widen, or resurrect authority.
- Fresh execution checks tolerate safe state evolution without weakening the
  historical receipt.
- Old approval cannot satisfy changed or additional requirements.
- Current policy `PERMIT` requires a new ordinary authorization path; it cannot
  consume an old approval.
- Binding assertions, logical time, revocation state, roots, grants, and
  policies remain trusted caller inputs without cryptographic authenticity.
- No signatures, key management, JWT/DID verification, HTTP, persistence,
  database, NandaTown integration, or protected-operation execution is added.
- Distributed single-use enforcement still requires future transactional or
  compare-and-swap persistence.

## Rejected Alternatives

### Infer authority from requirement codes

Rejected because text such as `MANAGER_APPROVAL` is not a verified role or
authorization grant.

### Treat any bound Principal as an approver

Rejected because identity consistency is not permission to approve.

### Require the current receipt to equal the historical receipt

Rejected because safe logical-time advancement and unrelated revocations alter
state identity without invalidating the relevant authority.

### Ignore policy `PERMIT` after approval

Rejected because silently treating an old approval as execution authority
would obscure a changed policy contract. Version 1 requires explicit
reauthorization.

### Consume by overall status alone

Rejected because `APPROVED` does not prove successful fresh authority and
policy revalidation.
