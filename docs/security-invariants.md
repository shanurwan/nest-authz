# Security invariant catalogue

The IDs in this document are stable review references. “Implementation” names
the enforcing module; it does not imply that module alone establishes the
invariant.

| ID | Invariant | Implementation | ADR | Representative evidence |
|---|---|---|---|---|
| AUTHZ-001 | No match, empty policy bundle, missing required gate, or indeterminate applicable rule produces `DENY`. | `evaluator.py`, `domain.py` | ADR-0004 | `EvaluatorOutcomeTests.test_empty_bundle_is_explicit_default_deny`; `EvaluatorConditionTests.test_permit_cannot_mask_an_indeterminate_rule` |
| AUTHZ-002 | Authentication or an `AuthorityContext` is not authorization. | `evaluator.py`, `binding.py`, `trusted.py` | ADR-0007, ADR-0011 | `AuthorityApplicabilityTests.test_authority_context_alone_cannot_permit`; Nanda adapter test 02 |
| AUTHZ-003 | Delegation preserves or narrows authority; it never broadens action, resource, or numeric upper bounds. | `delegation.py` | ADR-0005 | `test_broader_numeric_bound_is_rejected`; `test_scope_widening_several_hops_down_is_rejected` |
| AUTHZ-004 | Policy cannot widen validated delegated authority. | `applicability.py`, `evaluator.py` | ADR-0006 | `test_permit_policy_cannot_override_bound_exceeded`; Nanda amount-4000 scenario |
| AUTHZ-005 | Approval cannot create, widen, or resurrect authority. | `approval.py`, `execution.py`, `trusted.py` | ADR-0008, ADR-0009 | `test_revocation_after_approval_cannot_resurrect_authority`; `test_current_deny_policy_cannot_be_overridden` |
| AUTHZ-006 | Revocation of any grant invalidates every descendant authority that depends on it. | `delegation.py` | ADR-0005 | `test_revoked_parent_invalidates_descendant`; `test_revoked_root_is_not_hidden_behind_valid_descendants` |
| AUTHZ-007 | A non-deny decision requires exact request-subject and authority-holder binding. | `binding.py`, `evaluator.py` | ADR-0007 | `test_credential_substitution_regression_is_denied`; `test_failed_binding_cannot_construct_non_deny_decision` |
| AUTHZ-008 | Decisions and applicability evidence bind to exact canonical request semantics. | `canonical.py`, `domain.py`, `evaluator.py` | ADR-0006 | request-digest tests in `test_applicability.py`; `test_decision_evidence_rejects_applicability_for_another_request` |
| AUTHZ-009 | Approval state is bound to one exact `DecisionReceipt` and exact requirement set. | `receipt.py`, `approval.py`, `domain.py` | ADR-0008 | `test_approval_for_receipt_a_cannot_satisfy_receipt_b`; receipt mutation tests |
| AUTHZ-010 | Approved work requires fresh validation of current authority, holder, applicability, and policy before an `ExecutionPermit` exists. | `execution.py`, `trusted.py` | ADR-0009, ADR-0011 | `ExecutionRevalidationTests`; authenticated delegation tests 38–39 |
| AUTHZ-011 | Signature validity alone is insufficient: key trust, purpose, artifact kind, and digest must also agree. | `attestation.py` | ADR-0010 | `test_valid_signature_is_insufficient_for_wrong_key_purpose`; cross-kind replay test |
| AUTHZ-012 | Signing-key trust is purpose-scoped. | `domain.py`, `attestation.py` | ADR-0010 | policy-key/authority-key cross-purpose tests in `test_attestation.py` |
| AUTHZ-013 | An authenticated grant's signing key must be exactly bound to its logical grantor. | `authenticated_delegation.py` | ADR-0011 | `test_31_globally_trusted_mallory_key_cannot_sign_for_alice` |
| AUTHZ-014 | Root authority is explicit; owning a valid delegation key does not create root authority. | `authenticated_delegation.py`, `domain.py` | ADR-0011 | `test_13_child_principal_cannot_originate_unrelated_root`; test 32 |
| AUTHZ-015 | One exact `ExecutionPermit` maps to one durable logical execution identity in one SQLite database. | `execution_enforcement.py`, `sqlite_execution_store.py` | ADR-0012 | atomic execution tests 01–04, 23, 27 |
| AUTHZ-016 | Exact scalar types are security semantics: `bool` is not `int`, and equality never coerces types. | `domain.py`, `evaluator.py`, `applicability.py` | ADR-0001, ADR-0004 | bool/int tests in `test_evaluator.py`, `test_applicability.py`, and `test_delegation.py` |
| AUTHZ-017 | Canonical identities do not use `repr()`, Python `hash()`, insertion order, ambient time, or randomness. | `canonical.py` | ADR-0001, ADR-0002 | `test_canonical.py` cross-process and boundary tests |
| AUTHZ-018 | Every policy condition is declarative, directly addressed, and non-executable. | `domain.py`, `evaluator.py` | ADR-0003, ADR-0004 | `test_arbitrary_executable_conditions_cannot_be_represented`; closed-field-resolution tests |
| AUTHZ-019 | Denial carries no execution obligations from otherwise permitting rules. | `evaluator.py` | ADR-0004 | `test_deny_does_not_carry_permit_obligations` |
| AUTHZ-020 | Only `NEW_RESERVATION` is the local durable gate to begin protected execution. | `sqlite_execution_store.py`, `execution_store.py` | ADR-0012 | replay and concurrency tests in `test_atomic_execution.py` |

## Limits of the catalogue

These invariants assume correct execution of the checked-in code and integrity
of explicit trusted inputs. They do not authenticate identity-provider
bindings, establish global revocation freshness, or make external side effects
exactly once. See the [threat model](threat-model.md) and
[failure modes](failure-modes.md).
