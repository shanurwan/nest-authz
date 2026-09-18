# Changelog

All notable changes are recorded here. This project follows semantic versioning
for package releases; canonical wire schemas have their own explicit versions.

## [Unreleased]

- Release-readiness documentation, CI, static quality gates, package checks,
  dependency audit, source scan, and informational benchmarks.

## [0.1.0] - proposed

### Added

- Immutable, typed authorization requests, policies, decisions, evidence, and
  deterministic canonical SHA-256 content identity.
- Closed default-deny policy evaluation with deny-overrides semantics and exact
  scalar typing.
- Non-amplifying delegated authority with explicit logical time and revocation.
- Request applicability, holder binding, decision receipts, explicit approver
  authorization, and fresh execution revalidation.
- Detached Ed25519 artifact attestations, purpose-scoped trust stores, explicit
  root trust, and authenticated signer/grantor provenance.
- Atomic local SQLite reservation mapping one execution permit to one durable
  logical execution.
- Optional deterministic Nanda Town delegated-authority scenario and
  validators.

### Known limitations

- No production PKI, DID/JWT verification, key rotation, global revocation
  distribution, or identity-provider authentication.
- No distributed consensus, Byzantine guarantees, or exactly-once external
  execution.
- Caller-supplied trust, binding, logical-time, and revocation inputs remain
  trusted state.
- SQLite assumes local process and filesystem integrity.
- Demo key fixtures are public and test-only.
- Project licensing remains an explicit maintainer decision before public
  release.
