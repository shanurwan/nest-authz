# NEST AuthZ Security Model

## Purpose

NEST AuthZ is a deterministic authorization control plane for autonomous agents.

The system determines whether an authenticated agent may perform a specific action against a specific resource under a specific execution context.

Authentication, identity, trust, capability possession, and authorization are treated as separate concepts.

A valid identity or credential is not, by itself, sufficient authority to perform an action.

---

## Authorization Question

Every authorization request answers the following question:

> May this subject perform this action on this resource under this context,
> using holder-bound delegated authority validated against this authorization
> state and this policy bundle?

Conceptually:

```text
authorize(
    subject,
    action,
    resource,
    context,
    authority_context,
    subject_principal_binding,
    delegated_authority,
    policy_bundle,
    authorization_state
) -> Decision
```

For identical inputs and identical authorization state, the evaluator MUST produce an identical semantic decision.

---

## Outcomes

An authorization evaluation produces exactly one terminal policy outcome:

* `PERMIT`
* `DENY`
* `APPROVAL_REQUIRED`

A decision MAY additionally contain obligations that an enforcement point must satisfy before or while executing a permitted action.

Examples include:

* audit logging
* data redaction
* provenance attachment
* additional authentication
* rate limiting
* restricted response fields

Failure to satisfy a mandatory obligation MUST prevent execution.

---

## Security Invariants

### INV-001 — Default Deny

Absence of matching authority MUST result in `DENY`.

The system MUST NOT infer permission from:

* successful authentication
* agent registration
* trust score
* possession of unrelated capabilities
* absence of an explicit deny rule

---

### INV-002 — Authentication Is Not Authorization

Proof of identity establishes who or what the caller is.

It does not establish that the caller may perform the requested operation.

Identity verification and authorization evaluation MUST remain logically separate.

---

### INV-003 — Delegation Cannot Amplify Authority

A delegate MUST NOT grant authority exceeding the effective authority held by the delegator.

Delegation may preserve or attenuate authority.

Delegation MUST NOT amplify authority.

---

### INV-004 — Approval Cannot Create Authority

Human approval may satisfy an approval requirement associated with otherwise valid authority.

Approval MUST NOT grant an action that the principal lacked authority to authorize.

---

### INV-005 — Revocation Takes Precedence

Revoked authority MUST NOT be usable for new authorization decisions.

Previously issued credentials, delegation documents, approval artifacts, or cached state MUST NOT override a valid revocation applicable to the authorization request.

---

### INV-006 — Deterministic Evaluation

Authorization evaluation MUST NOT depend directly on nondeterministic environmental inputs.

The evaluator MUST NOT directly read:

* wall-clock time
* operating-system randomness
* external network services
* LLM responses
* mutable global variables
* process-local random UUIDs

Time-sensitive policy MUST use logical or explicitly supplied time contained in the authorization request or authorization state.

Randomness, where a surrounding simulation requires it, MUST be supplied explicitly as deterministic input and MUST NOT alter authorization semantics unpredictably.

---

### INV-007 — Policy Version Binding

Every authorization decision MUST identify the exact policy bundle against which it was evaluated.

The decision MUST include a stable digest or equivalent content-derived identifier for the policy bundle.

A decision MUST NOT be represented as reproducible unless the policy version used to create it can be identified.

---

### INV-008 — Complete Decision Evidence

Every non-error decision MUST provide machine-readable evidence describing why that outcome occurred.

A consumer MUST be able to determine:

* which policy matched
* which relevant conditions succeeded or failed
* which authority was considered
* which obligations were produced
* why approval was required, if applicable

Sensitive internal information MAY be redacted from user-facing explanations while remaining available to appropriately privileged audit systems.

---

### INV-009 — Enforcement Is Mandatory

A policy decision has no security value unless the protected operation is mediated by an enforcement point.

Protected actions MUST NOT provide an alternate execution path that bypasses authorization.

---

### INV-010 — Fail Closed

Malformed policy, unverifiable authority, unknown actions, unsupported policy constructs, incomplete mandatory context, invalid delegation, evaluation errors, and integrity failures MUST NOT produce `PERMIT`.

Unless a narrower deterministic error semantic is explicitly defined, these conditions MUST fail closed.

### INV-011 — Delegated Authority Is Holder-Bound

Validated delegated authority MUST NOT be treated as a bearer capability.

The runtime request `Subject` MUST equal the `Subject` in an explicit
`SubjectPrincipalBinding`, and the binding `Principal` MUST equal the effective
leaf grantee of the validated authority. Policy MUST NOT override either
mismatch.

The deterministic core validates consistency of this supplied binding. It does
not authenticate the binding or infer one from similar Subject and Principal
identifier strings.

---

## Trust Boundary

NEST AuthZ does not assume that an agent is trustworthy merely because it:

* has a valid identity
* has authenticated successfully
* has a high trust score
* originates from a known registry
* possesses a syntactically valid token

All security-relevant claims used in an authorization decision must be validated by the responsible subsystem before or during policy evaluation.

`AuthorityContext` is optional policy-visible request context only. It is not
`VerifiedAuthority`, does not prove delegation, and cannot satisfy an execution-
authority gate. `SubjectPrincipalBinding` is currently trusted input from a
future authentication adapter; the core does not yet prove IdP, JWT, DID,
private-key, or NANDA identity authenticity.

---

## Initial Non-Goals

The initial system does not attempt to:

* determine whether an LLM's intention is morally correct
* use an LLM as the policy decision engine
* infer unspecified permissions
* make probabilistic authorization decisions
* replace agent identity infrastructure
* replace cryptographic authentication
* provide a general-purpose IAM platform for humans

The first target is deterministic runtime authorization for autonomous-agent actions.

---

## Core Principle

> Authority must be explicit, attenuable, revocable, explainable, enforceable, and reproducible.
