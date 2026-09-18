# Security policy

## Project status

NEST AuthZ `0.1.x` is an experimental/research authorization library. It is not
described as production-ready and is not a complete IAM, PKI, identity,
revocation-distribution, or exactly-once execution system. Supported release
scope is the code and documented semantics in the latest `0.1.x` source.

Review [the threat model](docs/threat-model.md),
[security invariants](docs/security-invariants.md), and
[failure modes](docs/failure-modes.md) before evaluating deployment use.

## Reporting a vulnerability

For a personal OSS repository without a dedicated private security contact,
use the hosting platform's private security-advisory feature if enabled. If it
is unavailable, open a minimal public issue asking the maintainer to enable a
private reporting channel; do not include exploit details, private keys,
credentials, or sensitive deployment data in that issue.

Include affected version/commit, the violated invariant or trust boundary,
reproduction prerequisites, impact, and a minimal proof of concept. Allow the
maintainer time to reproduce and coordinate a fix before public disclosure.

## Demo key warning

The Nanda Town integration contains deterministic TEST-ONLY / PUBLIC DEMO key
seed material. It is intentionally reproducible, publicly known, and must never
be used to protect operational artifacts or identities. Treat any operational
use of those keys as compromised.
