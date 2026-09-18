# NEST AuthZ v1 threat model

## Scope and assets

This model covers the deterministic library, detached artifact attestations,
approval and revalidation flow, SQLite execution adapter, and Nanda Town demo.
Protected assets are authorization integrity, delegated scope, policy and
artifact authenticity relative to configured trust, approval integrity,
decision evidence, and single logical execution per permit.

The caller, local process, Python runtime, `cryptography`, configured trust
inputs, and—when used—SQLite/filesystem integrity are trusted. Availability is
secondary to authorization safety: ambiguous or indeterminate security state
fails closed.

“Mitigated” below means mitigated within that trust model. It does not mean the
residual risk is eliminated in a production deployment.

## Threat catalogue

| ID | Threat and asset | Attacker capability / boundary | Mitigation and observed behavior | Residual risk | Evidence |
|---|---|---|---|---|---|
| TM-001 | Authority amplification; delegated scope | Submit a child grant with wider action, resource, or numeric bounds at the delegation boundary | Mechanical attenuation rejects widening before policy evaluation; no `VerifiedAuthority` is produced. **Mitigated.** | Scope language is deliberately limited to exact action/resource and integer upper bounds. | `test_delegation.test_broader_numeric_bound_is_rejected`; ADR-0005 |
| TM-002 | Broken delegation provenance | Forge parent IDs or grantor/grantee continuity | Every adjacent link requires exact parent reference and `parent.grantee == child.grantor`; cycles and duplicate IDs fail. **Mitigated.** | Principal identifiers are configured names, not externally authenticated identities. | `test_delegation.test_forged_parent_reference_is_rejected`; ADR-0005 |
| TM-003 | Malicious or self-signed policy | Sign a permit policy with an attacker-controlled key | Trusted flow accepts only a factory-produced `TrustedPolicyBundle`; unknown keys fail verification. **Mitigated.** | Compromise or misconfiguration of the trusted policy key remains authoritative. | `test_attestation.test_self_signed_attacker_policy_is_rejected`; ADR-0010 |
| TM-004 | Trusted key used for the wrong purpose | Reuse an authority key to sign policy or vice versa | Attestations bind closed purpose and artifact kind; `TrustStore` permissions are purpose-scoped. **Mitigated.** | A key deliberately trusted for multiple purposes retains those powers. | `test_attestation.test_valid_signature_is_insufficient_for_wrong_key_purpose`; ADR-0010 |
| TM-005 | Signer/grantor mismatch | A trusted Mallory key signs a grant claiming Alice as grantor | Exact `PrincipalKeyRegistry` binding must agree with logical grantor. **Mitigated.** | The registry itself is trusted caller-supplied state. | `test_authenticated_delegation.test_31_globally_trusted_mallory_key_cannot_sign_for_alice`; ADR-0011 |
| TM-006 | Credential substitution / bearer use | Subject A presents authority whose leaf grantee is Principal B | Exact typed subject-binding subject and bound principal checks precede non-deny decisions. **Mitigated.** | Binding authenticity is delegated to a future identity adapter. | `test_binding.test_credential_substitution_regression_is_denied`; ADR-0007 |
| TM-007 | Boolean/integer confusion | Supply `True` where integer `1` or an amount is expected | Runtime checks use exact scalar types; bool is not int, mismatches are `ERROR` and fail closed. **Mitigated.** | New scalar/operator types would require new explicit rules. | `test_evaluator.test_equality_distinguishes_true_and_one`; ADR-0004 |
| TM-008 | Malformed policy input | Blank IDs, duplicate IDs, executable conditions, invalid operator operands | Immutable constructors reject malformed structure; condition language is closed and non-executable. **Mitigated.** | Semantic authoring mistakes that are structurally valid remain possible. | `test_policy.PolicyDomainTests`; ADR-0003 |
| TM-009 | Default-allow mistake | No matching rule or empty bundle | Empty bundle is explicit safe default deny; no match is `DENY`; deny overrides. **Mitigated.** | A legitimately matching permit rule can still express an overly broad policy within delegated scope. | `test_evaluator.test_empty_bundle_is_explicit_default_deny`; ADR-0004 |
| TM-010 | Missing context | Omit data used by an otherwise applicable rule or authority bound | Policy condition becomes `MISSING_INPUT`; indeterminate applicable rules deny. Missing authority-bound context is not applicable. **Mitigated.** | An unrelated rule already proven unsatisfied does not poison a valid rule by design. | `test_evaluator.test_missing_context_on_applicable_rule_is_indeterminate_and_denied`; ADR-0004 |
| TM-011 | Stale approval | Change request, policy, delegation, or approval set after approval | Receipt binds the original snapshot; fresh execution revalidation compares security semantics and recomputes current gates. **Mitigated.** | External current state is only as fresh/authentic as the caller supplies. | `test_execution.ExecutionRevalidationTests`; ADR-0009 |
| TM-012 | Approval replay | Reuse a consumed approval or approval for another receipt | Approval state is receipt-bound; consumed is terminal; execution requires the exact successful permit. **Mitigated locally.** | Distributed double consumption needs transactional shared persistence. | `test_approval.test_consumed_approval_replay_fails_deterministically`; ADR-0008/0009 |
| TM-013 | Unauthorized approver | An authenticated but unlisted principal attempts approval | Exact allowed principals are part of each requirement; binding alone or knowing a code grants nothing. **Mitigated.** | Approver binding authenticity is external trusted input. | `test_execution.test_mallory_cannot_satisfy_manager_approval`; ADR-0009 |
| TM-014 | Authority revoked after approval | Revoke an ancestor/leaf before execution | Current chain is revalidated; any relevant revocation blocks an execution permit. **Mitigated.** | No global revocation discovery/distribution is provided. | `test_execution.test_revocation_after_approval_cannot_resurrect_authority`; ADR-0009 |
| TM-015 | Request mutation after approval | Change amount, action, resource, subject, or constrained context | Request digest and receipt binding differ; execution revalidation returns typed mismatch and no permit. **Mitigated.** | Canonical schema evolution must remain versioned. | `test_execution.test_modified_amount_cannot_execute`; ADR-0008/0009 |
| TM-016 | Duplicate execution race | Concurrent callers reserve the same permit | Deterministic execution ID plus database PK/UNIQUE constraints and atomic transaction yield one `NEW_RESERVATION`. **Mitigated for one SQLite database.** | No distributed consensus or multi-database serialization. | `test_atomic_execution.test_23_many_concurrent_reservations_have_one_winner`; ADR-0012 |
| TM-017 | Crash after external side effect | Process completes operation but crashes before `mark_succeeded` | Record remains `RESERVED`; execution ID is available as downstream idempotency key. **Accepted residual risk.** | Exactly-once external execution requires downstream idempotency, outbox/inbox, or reconciliation. | ADR-0012 crash semantics; `docs/failure-modes.md` |
| TM-018 | Compromised `TrustStore` or root set | Replace configured keys, purposes, roots, or principal/key bindings | Inputs are immutable, explicit, and content-addressable; no global registry exists. **Not mitigated against a trusted-input compromise.** | Compromise can authorize malicious artifacts. Operational configuration protection is required. | Constructor/order tests in `test_attestation.py` and `test_authenticated_delegation.py`; ADR-0010/0011 |
| TM-019 | Malicious local process | Modify memory, monkey-patch code, steal operational private keys, or forge caller inputs | Factory-protected values prevent ordinary accidental construction; private keys are not domain records. **Accepted trust assumption.** | Python in-process isolation is not a hostile-process security boundary. | ADR-0010/0011; `docs/security-model.md` |
| TM-020 | SQLite tampering or denial | Modify/delete/lock the local database or bypass filesystem permissions | Adapter checks permit digest on transitions, uses constraints and transactions, and surfaces typed store errors. **Partially mitigated.** | No tamper-evident database, replication, Byzantine protection, or guaranteed availability. | `test_atomic_execution`; ADR-0012 |
| TM-021 | Leaked demo fixture keys | Reuse public deterministic Nanda seed material operationally | Source and docs label fixtures TEST-ONLY; traces exclude private material; fixtures establish repeatability only. **Operational prohibition.** | Anyone can derive the public demo private keys; misuse outside the demo destroys authenticity. | `test_nandatown_integration.test_18_private_material_and_signatures_are_absent_from_trace`; ADR-0013 |
| TM-022 | Cross-artifact signature replay | Pair a signature with a different artifact kind or digest | Versioned signing message binds scheme, purpose, kind, and typed digest. **Mitigated.** | A canonicalization or library compromise is in the TCB. | `test_attestation.test_cross_kind_replay_changes_the_signed_message`; ADR-0010 |
| TM-023 | Ambient-state nondeterminism | Influence hash seed, clock, environment, filesystem, or network | Pure modules accept state explicitly and source-hygiene/adversarial tests scan imports; cross-process tests vary `PYTHONHASHSEED`. **Mitigated in semantic core.** | Infrastructure and Nanda Town itself legitimately use I/O and operational metadata. | Source-hygiene tests across the suite; ADR-0001/0004 |

## Abuse cases that remain in caller scope

- Supplying a forged `SubjectPrincipalBinding` from an untrusted identity
  adapter.
- Supplying stale or incomplete revocations, dishonest logical time, or a
  malicious trusted-root/key registry.
- Writing a structurally valid policy that grants more than intended within an
  already delegated scope.
- Ignoring obligations returned by a decision.
- Calling the protected operation without first requiring
  `NEW_RESERVATION`.
- Treating a content digest, `DecisionReceipt`, or `ExecutionPermit` as an
  issuer-authenticated object without verifying a detached attestation where
  authenticity is required.

## Review cadence

Update this model when a trust input becomes internally authenticated, when a
new persistence adapter changes concurrency guarantees, when canonical schemas
change, or when a new integration crosses a different identity or execution
boundary.
