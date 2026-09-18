# Failure modes and recovery

NEST AuthZ prefers typed failures and fail-closed authorization outcomes. Some
malformed objects fail at construction; operational adapter failures raise
typed exceptions. Callers should record canonical correlation digests, not
silently convert errors to permit.

| Failure | Observed behavior | Open/closed | Recovery expectation | Operator-visible evidence |
|---|---|---|---|---|
| Malformed policy | Constructor raises `TypeError` or `ValueError` for invalid IDs, duplicate records, empty policy/rule conditions, or invalid operands. | Closed: no evaluable bundle exists. | Correct and reissue the policy; do not catch and substitute permit. | Validation exception plus policy source/version outside the core. |
| Malformed delegation | Construction fails or `validate_authority()` returns `INVALID_CHAIN`, `BROKEN_PROVENANCE`, `CYCLE`, or `BROADENED_AUTHORITY`. | Closed. | Repair the chain and reauthenticate every affected grant. | Typed validation status and offending grant ID. |
| Unknown signing key | `verify_artifact()` returns `UNKNOWN_KEY`; trusted wrapper creation raises `ArtifactVerificationError`. | Closed. | Provision a reviewed key into the explicit store or reject the artifact. | Artifact digest, key ID, purpose, kind, status. |
| Wrong key purpose | Verification returns `KEY_NOT_TRUSTED_FOR_PURPOSE`. | Closed. | Use a key explicitly authorized for that purpose; do not expand trust as an automatic retry. | Key ID, expected purpose, verification evidence. |
| Missing validated/authenticated authority | Low-level evaluator returns `DENY`; trusted entrypoint rejects the wrong wrapper type. | Closed. | Obtain and validate the correct chain; authentication alone is insufficient. | `VALIDATED_AUTHORITY_REQUIRED` or a boundary `TypeError`. |
| Missing policy context | `MISSING_INPUT`; an otherwise applicable rule becomes `INDETERMINATE`, forcing `DENY`. | Closed. | Supply explicit context and evaluate again. | Condition ID/status and indeterminate rule evidence. |
| Missing authority-bound context | Applicability returns `MISSING_CONTEXT`; policy cannot override it. | Closed. | Supply the exact constrained key with an exact scalar type. | Bound-evaluation key, presence flag, limit, and status. |
| Revoked authority | Validation returns `REVOKED`; descendant and execution revalidation fail. | Closed. | Acquire new valid authority; approval does not revive the chain. | Offending grant ID and current state digest. |
| Expired/not-yet-valid authority | Validation returns `EXPIRED` or `NOT_YET_VALID` under the explicit half-open interval. | Closed. | Use caller-approved logical time and a currently valid grant; reissue if needed. | Grant ID, logical-time state digest, status. |
| Failed holder binding | Binding returns `SUBJECT_MISMATCH` or `PRINCIPAL_MISMATCH`; final result is `DENY`. | Closed. | Correct the external binding assertion or use the authority holder. | Request digest, subjects/principals, effective grant, status. |
| Unauthorized approver | Authorization returns `SUBJECT_MISMATCH`, `PRINCIPAL_NOT_ALLOWED`, or `REQUIREMENT_MISMATCH`; transition raises `ApprovalTransitionError`. | Closed. | Ask an explicitly allowed principal to approve the exact requirement. | Approver binding and requirement evidence/status. |
| Stale or changed approval | Execution revalidation returns a typed request, policy, chain, requirement, or receipt mismatch. | Closed. | Start a new authorization/approval flow for the current inputs. | Original receipt digest, current digests, typed status. |
| Current policy becomes permit after approval | Returns `POLICY_REAUTHORIZATION_REQUIRED`; old approval is not silently treated as execution authority. | Closed. | Perform explicit reauthorization under the current policy. | Fresh decision and revalidation status. |
| SQLite unavailable or locked | Adapter raises `ExecutionStoreError` after transaction failure/rollback. | Closed operationally: no `NEW_RESERVATION`, so execution must not begin. | Restore database availability/permissions and retry the exact permit. | Store exception, execution ID/permit digest if already derived. |
| Abandoned `RESERVED` execution | Durable record remains `RESERVED` after a crash before the operation. | Closed to duplicate reservation; availability may require intervention. | Reconcile using application knowledge; do not create a new execution ID. | Execution ID, permit digest, `RESERVED` status. |
| External operation succeeded but local success was not recorded | Database still shows `RESERVED`. NEST AuthZ cannot infer external success. | Safety is application-dependent; exactly-once is not guaranteed. | Use downstream idempotency keyed by `ExecutionId`, outbox/inbox, or reconciliation before retry. | Local record plus downstream operation evidence. |
| Terminal execution transition retried | `ExecutionTransitionError`; replay reservation reports `ALREADY_SUCCEEDED` or `FAILED_EXISTING`. | Closed. | Treat the existing record as authoritative for that local store. | Typed reservation/transition status and record. |

## Exception boundary

Malformed input errors and documented operational store errors are expected
trust-boundary failures. Unexpected internal exceptions indicate a programming
or integrity fault; wrappers must surface them or fail closed, never replace
them with a permit.
