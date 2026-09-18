# Operability and observability contract

NEST AuthZ is a library, not a service. A future wrapper should expose metrics
for aggregate health and structured audit records for high-cardinality security
evidence. Telemetry must not change decisions or become an implicit trust
source.

## Metrics

Recommended names and low-cardinality labels:

- `authorization_requests_total`
- `authorization_decisions_total{outcome,reason_code}`
- `authorization_evaluation_duration_seconds`
- `delegation_validation_total{status}`
- `delegation_authentication_total{status}`
- `artifact_verification_total{purpose,artifact_kind,status}`
- `authority_applicability_total{status}`
- `holder_binding_total{status}`
- `approval_transitions_total{transition,status}`
- `execution_revalidation_total{status}`
- `execution_reservations_total{result}`
- `execution_store_operations_total{operation,result}`

Do not use raw subject, principal, grant, policy, request, receipt, or execution
identifiers as Prometheus labels. They are high-cardinality and may be
sensitive. Histograms should use deployment-owned buckets; this repository
does not prescribe latency objectives from microbenchmarks.

## Structured audit records

Where applicable, emit:

- event name and schema/version;
- outcome or typed status and reason codes;
- request, policy bundle, delegation chain, authorization state, decision,
  receipt, pending approval, execution permit, and execution ID digests;
- semantic policy/rule/condition IDs;
- effective grant ID and offending grant ID;
- artifact key ID, purpose, and kind—never private key material;
- logical time supplied to the security operation;
- approval requirement code and authorized approver principal, subject to data
  handling policy;
- execution reservation result and terminal reference; and
- a service-generated trace/correlation ID kept outside canonical security
  objects.

Canonical digests are excellent correlation fields but are not secrets,
signatures, or globally unique random identifiers. A digest can reveal equality
of inputs across events.

## Sensitive information

Potentially sensitive fields include subject/principal IDs, resource IDs,
context values, policy parameters, approval actors, result/failure references,
and request/receipt correlations. Log only what incident response requires,
apply access controls and retention limits, and prefer typed status plus digest
over raw domain objects. Never log:

- Ed25519 private-key bytes or deterministic demo seeds;
- unredacted credentials or authentication tokens;
- raw protected payloads by default; or
- database connection credentials.

## Alerting signals

Useful alerts are sustained increases in indeterminate decisions, unknown keys,
wrong-purpose signatures, signer/grantor mismatches, holder mismatches,
revocations at execution time, unauthorized approvers, store errors, and old
`RESERVED` records. An isolated deny is normally a successful security outcome,
not an availability incident.

## Correlation and replay

Persist enough input identities to reproduce a decision with the exact code and
canonical-schema version. For execution incidents, correlate:

`request digest -> decision receipt digest -> pending approval digest -> execution permit digest -> execution ID`.

Reproduction still needs the original domain inputs; hashes alone are not
reversible evidence.
