# ADR 0012: Atomic Execution Enforcement

- Status: Accepted
- Date: 2026-09-18
- Amends: ADR 0008 and ADR 0009 at the durable single-use boundary

## Context

An `ExecutionPermit` proves that an approved operation passed fresh authority,
holder, scope, and policy revalidation. It is immutable and content addressed,
but object possession and the pure `PendingApproval` transition cannot prevent
two processes from executing the same operation. Deterministic values are not
an atomic coordination mechanism.

This decision introduces a narrow persistence port, immutable logical execution
records, and a standard-library SQLite reference adapter. Persistence remains
outside the pure authorization, delegation, applicability, binding,
cryptographic, and trusted-orchestration modules.

No HTTP, Kubernetes, Redis, Kafka, external database, network service,
NandaTown integration, distributed lease system, or background worker is
introduced.

## Execution Identity

`ExecutionId` is a factory-protected immutable wrapper around exactly:

```text
sha256_digest(execution_permit)
```

Version 1 deliberately does not hash the permit digest again. The permit's
typed SHA-256 content identity already gives deterministic domain-separated
identity because the canonical `ExecutionPermit` record type participates in
the digest. A second digest would introduce a redundant identity without
adding a security property.

The canonical textual form is:

```text
execution:sha256:<64 lowercase hexadecimal characters>
```

`execution_id_for(permit)` is pure and reads no time or randomness. Ordinary
construction is blocked to prevent callers from accidentally associating an
arbitrary digest with execution identity. Equality of execution IDs means
equality of permit SHA-256 content identity, subject to the normal collision-
resistance assumption of SHA-256.

## Logical Execution Record

`ExecutionStatus` is closed to:

- `RESERVED`
- `SUCCEEDED`
- `FAILED`

`ExecutionRecord` contains:

- the `ExecutionId`;
- the exact typed ExecutionPermit digest;
- the current `ExecutionStatus`;
- an optional nonblank result reference; and
- an optional nonblank failure reference.

Construction requires `execution_id.permit_digest` to equal the stored permit
digest. A `RESERVED` record has neither reference, a `SUCCEEDED` record has
exactly a result reference, and a `FAILED` record has exactly a failure
reference. References are deterministic caller-supplied identifiers; the core
does not interpret, dereference, or generate them.

The version-1 transition table is:

| Current | Operation | Next |
| --- | --- | --- |
| `RESERVED` | `mark_succeeded` | `SUCCEEDED` |
| `RESERVED` | `mark_failed` | `FAILED` |
| `SUCCEEDED` | any transition | invalid |
| `FAILED` | any transition | invalid |

`SUCCEEDED` and `FAILED` are terminal. Invalid transitions raise a typed
`ExecutionTransitionError`; a missing record and permit mismatch have distinct
typed errors. No transition is silently ignored.

## Reservation Result

`ExecutionReservationStatus` is closed to:

- `NEW_RESERVATION`
- `EXISTING_RESERVED`
- `ALREADY_SUCCEEDED`
- `FAILED_EXISTING`

`ExecutionReservationResult` contains the status and complete resulting
`ExecutionRecord`. `NEW_RESERVATION` and `EXISTING_RESERVED` require a
`RESERVED` record. The two terminal reservation statuses require their matching
record status. A repeated exact permit always returns the same execution ID.

## Storage Port

`ExecutionStore` is a narrow framework-free protocol:

```text
reserve(execution_permit) -> ExecutionReservationResult
get(execution_id) -> ExecutionRecord | None
mark_succeeded(
    execution_id,
    execution_permit,
    result_reference,
) -> ExecutionRecord
mark_failed(
    execution_id,
    execution_permit,
    failure_reference,
) -> ExecutionRecord
```

The port imports only logical domain values. Pure authorization modules do not
import the port or SQLite. The SQLite implementation is an adapter behind this
interface, not part of policy evaluation or authority validation.

Every update recomputes the exact permit digest and execution ID. A caller
cannot use permit B to update permit A's execution record even when it knows
the other execution ID.

## SQLite Reference Adapter

`SQLiteExecutionStore` uses only Python's standard-library `sqlite3`. It stores
one table:

```sql
CREATE TABLE execution_records (
    execution_id TEXT PRIMARY KEY,
    execution_permit_digest TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL
        CHECK (status IN ('RESERVED', 'SUCCEEDED', 'FAILED')),
    result_reference TEXT,
    failure_reference TEXT,
    CHECK (
        (status = 'RESERVED'
            AND result_reference IS NULL
            AND failure_reference IS NULL)
        OR
        (status = 'SUCCEEDED'
            AND result_reference IS NOT NULL
            AND failure_reference IS NULL)
        OR
        (status = 'FAILED'
            AND result_reference IS NULL
            AND failure_reference IS NOT NULL)
    )
) WITHOUT ROWID;
```

Execution IDs are stored using their canonical textual form. Permit digests use
the existing `sha256:<hex>` form. SQLite row IDs, paths, connection settings,
transaction IDs, and operational database internals are not domain values and
are never canonicalized.

The adapter enables foreign-key checking, full synchronous durability, and WAL
journaling for a local file database. It rejects the process-local `:memory:`
database because this adapter's contract is durable state across connections.
Local database and filesystem provisioning remain the caller's responsibility.

## Atomic Reservation Algorithm

For one exact permit the adapter:

1. computes `permit_digest = sha256_digest(permit)` and the corresponding
   `ExecutionId`;
2. opens a database transaction with `BEGIN IMMEDIATE`;
3. executes one `INSERT ... ON CONFLICT(execution_id) DO NOTHING`;
4. uses the statement's affected-row count to distinguish the sole creator;
5. reads the authoritative row inside the same transaction;
6. verifies the persisted execution ID/digest relationship; and
7. commits before returning the typed reservation result.

The primary-key and unique-digest constraints are authoritative. The algorithm
does not perform `if not exists` followed by an unguarded insert. Concurrent
writers serialize at SQLite's write boundary; exactly one insert changes a row
and therefore exactly one caller receives `NEW_RESERVATION`. Every other caller
loads the same record and receives a status derived from its durable state.

Database errors roll the transaction back and are exposed as a typed
`ExecutionStoreError`. No partially inserted logical record is returned.

## Idempotency Semantics

The expected flow is:

```text
reserve(P) -> NEW_RESERVATION / execution X
reserve(P) -> EXISTING_RESERVED / execution X
mark_succeeded(X, P, result-reference)
reserve(P) -> ALREADY_SUCCEEDED / execution X
```

A failed execution similarly returns `FAILED_EXISTING` forever in version 1.
Terminal records are never changed back to `RESERVED`, and the same permit
never creates a second logical execution identity.

Different permits produce different IDs when their canonical bytes differ,
subject to SHA-256 collision resistance. No Python `hash()`, UUID, clock, or
randomness participates.

## Approval Consumption and Authoritative Gate

The durable successful reservation is the version-1 authoritative duplicate-
execution gate. A caller MUST reserve the exact `ExecutionPermit` before
invoking a protected operation and MUST execute only after receiving
`NEW_RESERVATION`.

After successful reservation, orchestration may derive the existing pure
`PendingApproval` `CONSUMED` value for audit/state propagation. That immutable
transition is not persisted by this adapter and is not atomic with the SQLite
reservation. `ApprovalStatus.CONSUMED` alone therefore remains insufficient to
prove durable single-use enforcement. Conversely, any non-new reservation
prevents another protected-operation invocation regardless of an in-memory
approval object's status.

This phase intentionally does not claim cross-store atomicity between approval
storage and execution storage.

## Crash Semantics

### Reservation committed, process crashes before the protected operation

The durable record remains `RESERVED`. Retrying reservation returns
`EXISTING_RESERVED`, not permission to blindly execute again. Recovery or
reconciliation must determine whether and how that reservation can proceed.
Version 1 has no lease timeout or automatic reset because either could permit a
duplicate side effect.

### Protected operation succeeds, process crashes before `mark_succeeded`

The local record may remain `RESERVED` even though the external side effect
succeeded. NEST AuthZ alone cannot atomically coordinate a local SQLite commit
with an arbitrary external operation and therefore does not claim exactly-once
external execution.

Future protected-operation integrations must use a downstream idempotency key,
transactional outbox/inbox, application-specific reconciliation, or an
equivalent reliable side-effect protocol.

## Downstream Idempotency Contract

The protected-operation adapter receives the `ExecutionId` from the successful
reservation and should pass its canonical textual form as the downstream
idempotency key. Retries for the same permit therefore use the same key.

NEST AuthZ never executes arbitrary callbacks in its security core. The caller
is responsible for invoking the protected operation and for ensuring the
downstream system actually honors the idempotency key.

## Storage Trust Boundary

The SQLite reference adapter assumes:

- SQLite database integrity;
- local filesystem integrity and permissions;
- trusted process code and database path configuration; and
- SHA-256 collision resistance.

It provides atomic serialization for writers using the same accessible SQLite
database file. It does not provide distributed consensus, Byzantine fault
tolerance, multi-region serialization, fencing-token leases, remote storage,
or atomicity with an external protected operation.

Copying, restoring, replacing, or independently forking the database can fork
the enforcement history. Deployment must ensure all competing local processes
use the same authoritative file and suitable filesystem locking semantics.

## Canonical Encoding

ADR 0001 framing remains unchanged. New logical schemas are:

- `nest-authz/execution-id@1`
- `nest-authz/execution-status@1`
- `nest-authz/execution-record@1`
- `nest-authz/execution-reservation-status@1`
- `nest-authz/execution-reservation-result@1`

No existing schema changes fields or meaning. Database paths, SQL rows,
connections, transaction details, and SQLite configuration have no canonical
schema.

## Consequences and Limitations

- One database file admits at most one durable logical record per exact permit.
- Concurrent exact-permit reservations have one winner and deterministic
  idempotent observations for all other callers.
- Terminal execution state cannot be reopened in version 1.
- Reservation is not proof that the external side effect ran.
- `SUCCEEDED` is not proof that an untrusted process reported truthfully.
- References are opaque identifiers, not persisted operation results.
- No automatic recovery policy exists for abandoned `RESERVED` records.
- SQLite does not solve distributed or cross-system exactly-once execution.
- No external service, network database, ORM, background worker, or protected-
  operation callback is added.

## Rejected Alternatives

### Random or time-based execution identifiers

Rejected because identical permits must have identical identities across
processes and retries without ambient state.

### A second domain-separated hash over the permit digest

Rejected because canonical `ExecutionPermit` content already domain-separates
the digest, and a second identity would add indirection without a new security
property.

### Check then insert

Rejected because concurrent callers can both observe absence before either
unguarded insert, making application-level duplicate checks insufficient.

### Automatically retry a FAILED or abandoned RESERVED execution

Rejected because the protected operation may already have produced an external
side effect. Retry policy requires operation-specific idempotency and recovery
semantics.

### Store SQLite details in canonical domain records

Rejected because paths, connections, row mechanics, and transaction IDs are
operational adapter state rather than authorization semantics.
