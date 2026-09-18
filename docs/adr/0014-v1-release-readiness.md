# ADR-0014: Version 1 release readiness

## Status

Accepted for the proposed `0.1.0` alpha release.

## Context

ADRs 0001 through 0013 define a deterministic authorization core, explicit
trust boundaries, a local execution-enforcement adapter, and a Nanda Town
demonstration. The implementation has extensive adversarial tests, but the
repository needs a concise reviewer path, reproducible quality gates, package
verification, and precise release claims.

This ADR records release engineering decisions. It does not add authorization
semantics.

## Demonstrated guarantees

The repository and its tests demonstrate the following properties within the
documented input and trust model:

- public domain records are immutable, slotted, defensively copied, and reject
  malformed values where their local invariants are knowable;
- canonical bytes and typed SHA-256 identities are deterministic across
  repeated calls, collection insertion order where order is non-semantic, and
  different `PYTHONHASHSEED` values;
- policy evaluation is closed, deterministic, deny-overrides, and default
  deny; missing or erroneous security-relevant inputs cannot yield permit;
- a delegation chain is checked for exact provenance, cycles, logical-time
  validity, caller-supplied revocation, and mechanical scope attenuation;
- request holder binding and authority applicability are mandatory before a
  non-deny semantic decision can escape;
- approval requirements identify exact allowed principals, approvals bind to
  exact receipts, and execution requires fresh authorization revalidation;
- Ed25519 attestations authenticate exact canonical artifacts relative to an
  explicit, purpose-scoped `TrustStore`;
- authenticated delegation requires signer/grantor key binding and an
  explicitly trusted root principal;
- one exact `ExecutionPermit` maps to one durable logical execution in the
  SQLite reference adapter, including concurrent reservation attempts; and
- the Nanda Town scenario demonstrates the trusted flow, adversarial scope and
  approver failures, revocation after approval, and duplicate reservation.

These are scoped software guarantees. Caller-supplied identity, trust,
logical-time, and revocation inputs are trusted inputs unless a documented
verification step says otherwise.

## Properties not guaranteed

Version 1 does not claim:

- exactly-once external execution;
- production PKI, DID, JWT, or identity-provider integration;
- distributed consensus, Byzantine security, or multi-region serialization;
- globally authentic or globally distributed revocation state;
- production-grade key rotation, recovery, or compromise response;
- resistance to a compromised local process, `TrustStore`, or SQLite file;
- automatic obligation or protected-operation execution; or
- replacement of a complete IAM system.

The repository must not use “production-ready” to describe version 1.

## Decisions

### Version and compatibility

The initial release candidate is `0.1.0`, classified as Alpha. Existing
canonical schemas and security semantics are unchanged by this release phase.
The package continues to require Python 3.11 or newer; CI exercises Python 3.11
and 3.12 rather than asserting support for versions not tested here.

### Reproducible environment

Development and release checks use a dedicated virtual environment. A shared
Anaconda environment is not a supported release environment because unrelated
packages previously introduced an incompatible `pyOpenSSL`/`cryptography`
combination. `cryptography==50.0.1` remains the single runtime dependency and
the Nanda Town dependency remains optional.

### Static quality baseline

Ruff is the lint and formatting authority. Mypy checks all NEST AuthZ source.
The only dependency-specific mypy exception is module-scoped missing-import
handling for Nanda Town because that external package does not publish a
`py.typed` marker. No blanket source exclusions or broad inline ignores are
used.

Coverage is measured with line and branch coverage. The observed release
baseline is 78.4%, and CI uses a conservative 75% floor as a regression
tripwire, not a security proof. Adversarial tests are not weakened to increase
the number, and the dynamically loaded Nanda plugin remains in the denominator.

### CI and package evidence

CI performs installation, tests, Ruff lint and format checks, mypy, coverage,
package build, Twine metadata validation, artifact-content inspection, and a
dependency audit without secrets. Nanda Town is an optional integration job.
The source distribution contains reviewer documentation and tests; the wheel
contains the integration scenario YAML but not local databases, caches, or
private-key files.

### Public API

`nest_authz.__init__` is the intentional convenience API for v1. It exposes:

- immutable domain and evidence values;
- canonicalization and typed content-digest functions;
- low-level pure validation/evaluation functions;
- trusted policy/delegation orchestration;
- approval and execution-revalidation transitions; and
- the execution-store protocol and SQLite reference adapter.

Token objects, canonical encoder internals, SQL helpers, and Nanda Town plugin
implementation details remain unexported. The low-level `evaluate()` function
is intentionally public for semantic evaluation and testing; it is not the
trusted artifact entrypoint. Production-oriented callers should enter through
`verify_policy_bundle()`, `authenticate_delegation_chain()`, and
`authorize_trusted()`.

### Security and dependency scanning

`pip-audit` checks published dependency advisories for the resolved
environment. A clean result does not prove application security, correct trust
configuration, or absence of undisclosed vulnerabilities. The source scan
checks prohibited ambient-state and dynamic-execution patterns; manual review
still owns semantic fail-open analysis.

### Performance evidence

The repository includes an informational microbenchmark for canonicalization,
policy evaluation, multi-hop validation, authenticated delegation, trusted
authorization, and execution revalidation. It has no CI latency threshold and
must not be represented as production throughput.

## Release criteria

A `0.1.0` release candidate requires:

1. the complete NEST AuthZ suite to pass from the installed package;
2. Ruff lint and formatting, mypy, coverage, dependency audit, build, Twine,
   and artifact inspection to complete with recorded results;
3. a wheel installed into a fresh environment to import outside the checkout;
4. the documented Nanda Town scenario and validators to pass with deterministic
   authorization semantics; and
5. remaining failures or environmental limitations to be reported rather than
   reclassified as passes.

Publication, tagging, and a GitHub release are separate human-approved steps.

## Consequences

The repository gains a repeatable evidence trail and a much smaller gap between
what the code demonstrates and what its documentation claims. CI and scanners
increase maintenance work and dependency exposure in the development
environment, but do not add runtime dependencies. The largest remaining
release-policy decision is the project license: no license is inferred or
invented by this ADR.
