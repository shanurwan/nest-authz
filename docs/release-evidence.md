# NEST AuthZ v0.1.0 release evidence

This is the reviewer-oriented proof index for the proposed `0.1.0` Alpha
release. Results below were observed on 2026-09-18, not inferred from intended
CI behavior.

## Claim-to-evidence index

| Claim | Evidence | Test or scenario | ADR |
|---|---|---|---|
| Canonical identity is process-stable and type-explicit | Golden bytes/digest, integer boundary cases, mapping reorder, and multiple `PYTHONHASHSEED` processes | `tests/test_canonical.py` | ADR-0001, ADR-0002 |
| Domain records are immutable and slotted | Export completeness plus frozen/slotted checks for every public dataclass | `test_domain.DomainInvariantTests` | ADR-0002 onward |
| Default deny and deny-overrides are deterministic | Empty/no-match cases and reordered policy/rule adversarial combinations | `tests/test_evaluator.py` | ADR-0004 |
| Delegation cannot amplify authority | Wider bounds, changed action/resource, omitted parent bounds, and multi-hop widening all fail without a verified value | `tests/test_delegation.py`; Nanda amount-4000 case | ADR-0005 |
| Policy cannot widen delegated authority | Matching permit/approval rules cannot override `BOUND_EXCEEDED` | `tests/test_applicability.py` | ADR-0006 |
| Alice authority cannot become a bearer capability | Mallory subject/principal substitution is denied with typed evidence | `tests/test_binding.py` | ADR-0007 |
| Approval is exact-receipt-bound | Request, policy, authority, state, binding, applicability, and decision mutations change receipt identity | `tests/test_approval.py` | ADR-0008 |
| Approval cannot resurrect revoked authority | Current revocation prevents an execution permit after approval | `test_execution.test_revocation_after_approval_cannot_resurrect_authority`; Nanda `ev-42` | ADR-0009, ADR-0013 |
| Unauthorized approver cannot satisfy a code by name | Mallory is bound but not allowed; transition fails | `test_execution.test_mallory_cannot_satisfy_manager_approval`; Nanda `ev-31` | ADR-0009 |
| Signature validity is insufficient without trust and purpose | Unknown self-signed policy and cross-purpose trusted keys fail | `tests/test_attestation.py` | ADR-0010 |
| Mallory cannot sign for Alice | A mathematically valid, globally trusted authority key fails principal/grantor binding | authenticated delegation test 31 | ADR-0011 |
| A delegated child cannot create a root merely by owning a key | Agent B root fails unless Agent B is explicitly trusted as root | authenticated delegation tests 13 and 32 | ADR-0011 |
| Trusted authorization requires both trusted policy and authenticated delegation | Raw policy and structurally-only authority are rejected at the entrypoint | authenticated delegation tests 25–30 | ADR-0011 |
| One execution permit creates one local durable logical execution | Independent connections and 12 concurrent attempts yield one row and one `NEW_RESERVATION` | atomic execution tests 04, 23, 27 | ADR-0012 |
| Nanda scenario is non-vacuous | Trace contains each malicious attempt; intentionally unsafe trace makes validator fail | Nanda integration tests 15–17 | ADR-0013 |
| Nanda authorization semantics replay deterministically | Repeated seed 42 and seeds 42/7/1337 compare equal after excluding only run ID | Nanda integration tests 19–20 | ADR-0013 |

## Local release-gate results

Environment: Python 3.12.7, Windows 11 `10.0.26200`, dedicated `.venv` created
from the local Python 3.12 interpreter. Nanda Town was installed from the
adjacent checkout at commit
`17fbc7902be49683aee5f7610a0a1dcf8c803b3e`.

| Gate | Command | Observed result |
|---|---|---|
| Complete suite | `python -m unittest discover -s tests -v` | **392 passed**, 0 failed, 0 skipped |
| Ruff lint | `python -m ruff check .` | Passed |
| Ruff formatting | `python -m ruff format --check .` | Passed |
| Static typing | `python -m mypy` | Passed: 21 source files, no issues |
| Line/branch coverage | `python -m coverage run -m unittest discover -s tests` then `coverage report -m` | **78.4%** combined coverage; 3,091 statements, 1,532 branches; 75% floor passes |
| Source hygiene | `python scripts/security_source_scan.py` | Passed; only accepted `sqlite3` adapter import reported |
| Dependency advisory scan | `python -m pip_audit --local` | No known vulnerabilities; local unpublished `nest-authz` and editable `nandatown` themselves were skipped |
| Build | `python -m build` | Built wheel and source distribution |
| Metadata | `python -m twine check dist/*` | Both artifacts passed |
| Artifact contents | `python scripts/check_release_artifacts.py dist` | Scenario YAML present; no cache, SQLite, private-key file, or PEM private key packaged |
| Wheel isolation | install wheel into separate temp venv, import from `%TEMP%` | Imported from `site-packages`; packaged scenario exists |
| Diff whitespace | `git diff --check` | Recorded in final verification below |

The 75% coverage floor is deliberately below the measured 78.4% baseline. It
is a regression tripwire, not a claim that unexecuted paths are safe. Meaningful
gaps include defensive constructor/typed-error branches and the dynamically
loaded Nanda plugin reporting 0% under package-source coverage even though its
22 focused end-to-end tests execute. The plugin remains in the denominator.

## Nanda Town evidence

Focused command:

```text
python -m unittest discover -s tests -p "test_nandatown_integration.py" -v
```

Observed: **22 passed**. The documented CLI scenario reported `PASSED`, 65
events, 11 intents, and all six NEST security stages passed:

- `in_scope_delegated_action`
- `out_of_scope_denied`
- `approval_flow`
- `unauthorized_approver_rejected`
- `revoked_authority_blocked`
- `single_logical_execution`

Representative trace semantics:

```text
ev-17 operation:subagent-700    outcome=PERMIT applicability=APPLICABLE
ev-21 operation:subagent-4000   outcome=DENY applicability=BOUND_EXCEEDED
ev-31 operation:finance-primary approver=mallory status=PRINCIPAL_NOT_ALLOWED
ev-42 operation:finance-primary authority=REVOKED revalidation=DELEGATION_AUTHENTICATION_FAILED
ev-59 operation:finance-replay  reservation=NEW_RESERVATION execution=<X>
ev-63 operation:finance-replay  reservation=EXISTING_RESERVED execution=<same X>
```

Nanda Town includes a random run ID and a wall-clock evaluation timestamp
outside authorization semantics. Determinism tests compare `nest_*` events
after removing only `run_id`; semantic traces are equal for repeat seed 42 and
for seeds 42, 7, and 1337.

## Upstream Nanda checkout baseline

The previously observed complete upstream checkout baseline is recorded
unchanged, as required:

```text
1691 passed, 26 skipped, 39 failed, 9 warnings
```

The failures were observed in upstream/environment-sensitive areas including
Windows symlink/POSIX-permission behavior, historical fixture/receipt hashes,
and schema synchronization. NEST AuthZ did not modify the Nanda checkout or
reclassify those failures as passes. Targeted Nanda layer/simulator tests had
28 passes, and the documented Lab and Track smoke controls passed in the prior
integration verification.

Current upstream `CONTRIBUTING.md` defines pytest, scenario smoke, schema-sync,
and distribution checks; it explicitly states that there is no separate Python
linter/formatter gate and does not define a mypy gate. No nonexistent upstream
quality command is reported as passing.

## Security-sensitive source review

The reproducible scan and manual review found:

- no `eval`, `exec`, `pickle`, arbitrary `getattr` traversal, Python `hash()`,
  `repr()`, clock, randomness, environment, filesystem, network, or broad
  exception handler in the pure security core;
- no `isinstance(value, int)` path that could silently accept bool as int;
- no exception handler that converts an internal failure into `PERMIT`;
- no mutable global trust store, root registry, principal/key registry, or
  revocation state; those values are explicit immutable inputs;
- `sqlite3` only in `sqlite_execution_store.py`, the intended infrastructure
  adapter;
- the SQLite adapter's broad `BaseException` handler exists only to roll back
  an active transaction and immediately re-raises; it cannot return success;
- attestation catches only `InvalidSignature`/`ValueError` and maps them to
  `SIGNATURE_INVALID`; UTF-8/type decoding catches are validation failures;
- the two core `Outcome.PERMIT` matches are explicit post-gate semantic paths,
  and the Nanda plugin returns true only for the resulting exact permit;
- `canonical.py` uses `type(value) is int`, intentionally excluding bool;
- `perf_counter_ns` only in the informational benchmark;
- filesystem/tar/zip access only in release tooling;
- subprocess/environment use only in tests that prove cross-process
  `PYTHONHASHSEED` stability;
- deterministic Ed25519 seeds only in the Nanda adapter, prominently marked
  TEST-ONLY / PUBLIC DEMO MATERIAL and excluded from trace evidence; and
- cryptographic mathematics delegated to `cryptography`; no custom Ed25519
  implementation.

## Informational performance baseline

Python 3.12.7 on Windows 11 `10.0.26200`, median of 5 × 500 iterations, one
policy containing two rules/six conditions, and a two-grant chain:

| Operation | Median |
|---|---:|
| Canonical policy bundle | 225.7 µs/op |
| Policy evaluation | 530.6 µs/op |
| Two-hop delegation validation | 125.4 µs/op |
| Two-hop authenticated delegation | 846.1 µs/op |
| Trusted authorization | 1,574.0 µs/op |
| Trusted execution revalidation | 2,620.7 µs/op |

These are local microbenchmarks, not production capacity or latency targets.

## Remaining release blockers and limitations

Before a public `0.1.0` release:

1. the maintainer must choose and add an explicit project license; none was
   inferred;
2. the new GitHub Actions workflow should pass on hosted Python 3.11 and 3.12;
   local verification covered Python 3.12.7 only; and
3. the complete diff and public TEST-ONLY demo-key warning should receive human
   review.

There is no claim of production PKI, DID/JWT identity, global revocation,
distributed consensus, Byzantine security, key rotation, exactly-once external
execution, or complete IAM replacement.
