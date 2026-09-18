# Nanda Town Delegated-Authority Demo

This Tier-1 offline scenario shows NEST AuthZ acting as a real Nanda Town Auth
layer gate. It covers attenuation, authenticated delegation, holder binding,
policy approval, unauthorized approval, revocation at execution time, and
single-use execution reservation.

No model API, network service, production HTTP API, cloud resource, or external
database is used.

## Architecture

```text
Nanda Town scenario, logical clock, agents, and trace
    -> nest-authz.v1 Auth plugin
        -> Nanda input translation
            -> authenticated delegation + trusted policy NEST core path
```

Nanda Town authenticates the simulated message sender with its deterministic
HMAC reference implementation. That proves only the current simulated sender.
NEST AuthZ separately authenticates the exact signed authority grants, checks
the explicit Subject/Principal binding and authority scope, and evaluates the
trusted policy.

The plugin is loaded by the scenario's `plugin_files: [plugin.py]` declaration,
which is Nanda Town 0.2.0's current external-plugin mechanism.

## Delegation Graph

```text
principal:alice
  G1 amount <= 5000 -> principal:finance-agent
      G2 amount <= 1000 -> principal:payment-subagent
```

Alice is the exact trusted root and signs G1. The Finance Agent signs G2 with a
key explicitly bound to that Principal. Both grants authorize only:

```text
action   = payments.transfer
resource = account:alice
```

The policy permits amounts through 1000 and requires exact manager approval for
larger amounts. It defaults to deny.

After the primary revocation test, a separately signed G3 from Alice to the
Finance Agent supports a fresh replay test. G1 remains revoked.

## Expected Events

| Operation | Expected result |
| --- | --- |
| Payment Subagent, amount 700 | `PERMIT` |
| Payment Subagent, amount 4000 | `DENY`, `BOUND_EXCEEDED` |
| Finance Agent, amount 4000 | `APPROVAL_REQUIRED` |
| Mallory approval attempt | `PRINCIPAL_NOT_ALLOWED` |
| Authorized manager approval | `APPROVED` |
| G1 revoked before execution | revalidation denied, `REVOKED` |
| Fresh G3 permit reservation | `NEW_RESERVATION` |
| Exact permit replay | `EXISTING_RESERVED`, same execution ID |

The scenario does not execute a protected business operation.

## TEST-ONLY keys — never reuse operationally

The demo's Ed25519 seeds are intentionally public and deterministic. They are
marked `TEST-ONLY / PUBLIC DEMO MATERIAL` in source. They must never be reused
for production signing or trust. Private material is not emitted into the trace
or placed in canonical NEST records.

## Fresh-environment reviewer path

Clone or place the current Nanda Town checkout next to NEST AuthZ, then run the
following from the NEST AuthZ repository root. A dedicated virtual environment
is required; do not use a shared Anaconda environment.

```bash
python -m venv .venv
# POSIX: source .venv/bin/activate
# PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install --editable ../nandatown
python -m pip install --editable ".[dev]"
python -m unittest discover -s tests -v
```

Installing only NEST AuthZ remains sufficient for `import nest_authz`; the core
does not import Nanda Town. The declared `nandatown` extra accepts compatible
published `0.2.x` releases, but the adjacent editable checkout is the exact
development path used to verify this integration.

## Run the Scenario

From the NEST AuthZ repository root:

```bash
nandatown run src/nest_authz/integrations/nandatown/delegated_authority.yaml --out .demo-runs --seed 42
```

Nanda Town automatically runs the registered
`nest_authz_delegated_authority` validator and writes its standard evidence
bundle. A passing run reports the scenario verdict as `passed`; the six NEST
stages listed below must each be `passed` rather than merely absent. To run the
focused integration suite:

```bash
python -m unittest discover -s tests -p "test_nandatown_integration.py" -v
```

The integration end-to-end test invokes the real `run_lab()` path, loads the
standard bundle, and checks every NEST validator stage.

## Inspect the Trace

Open the generated `events.jsonl` and filter event kinds beginning with
`nest_`. Important events are:

- `nest_authorization_decided`
- `nest_approval_authorization`
- `nest_approval_state`
- `nest_execution_revalidation`
- `nest_execution_reservation`
- `nest_request_admitted`

For example, PowerShell can locate the newest evidence bundle and select the
integration events with:

```powershell
$run = Get-ChildItem .demo-runs -Directory |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
Get-Content (Join-Path $run.FullName events.jsonl) |
  Select-String '"kind":"nest_'
Get-Content (Join-Path $run.FullName result.json)
```

On POSIX shells:

```bash
run="$(ls -dt .demo-runs/*/ | head -1)"
grep '"kind":"nest_' "${run}/events.jsonl"
cat "${run}/result.json"
```

The validator stages in `result.json` are:

- `in_scope_delegated_action`
- `out_of_scope_denied`
- `approval_flow`
- `unauthorized_approver_rejected`
- `revoked_authority_blocked`
- `single_logical_execution`

Each adversarial stage requires evidence that the attempt occurred. Removing an
attempt produces insufficient evidence; changing a denial into unsafe success
produces a failed stage.

## Concise expected evidence

Field order in JSON is not significant. The trace should contain facts
equivalent to:

```text
operation:subagent-700   nest_authorization_decided outcome=PERMIT
operation:subagent-4000  nest_authorization_decided outcome=DENY applicability_status=BOUND_EXCEEDED
operation:finance-primary nest_approval_authorization requesting_agent=mallory status=PRINCIPAL_NOT_ALLOWED
operation:finance-primary nest_execution_revalidation authority_status=REVOKED status=DELEGATION_AUTHENTICATION_FAILED
operation:finance-replay nest_execution_reservation status=NEW_RESERVATION execution_id=<X>
operation:finance-replay nest_execution_reservation status=EXISTING_RESERVED execution_id=<same X>
```

The approval path also includes `APPROVAL_REQUIRED` followed by an
`nest_approval_state` event with `status=APPROVED` for
`principal:authorized-manager`.

The focused suite above exercises the validators through Nanda Town's real
`run_lab()` path; the CLI run also executes them and writes their evidence to
`result.json`.

## Deterministic Replay

The same configuration produces identical authorization-relevant `nest_*`
event semantics. Full bundle bytes differ because current Nanda Town generates
a run ID and records evaluation wall-clock metadata outside logical simulation
semantics. Tests compare events after removing only `run_id`.

Seeds 42, 7, and 1337 produce the same authorization trace because no
authorization decision branches on simulator RNG. The seeded HMAC key bytes may
differ, but neither keys nor signatures enter the authorization evidence.

## What the Evidence Proves

The scenario proves deterministic internal consistency against its configured
trust inputs: exact signed policy, signed grants, root/key registry, holder
bindings, logical revocation state, approval authority, and execution-permit
identity.

It does not prove external identity authenticity, production key custody,
distributed persistence, exactly-once side effects, or correctness of an actual
payment system. The scenario's in-run reservation store is not durable;
`SQLiteExecutionStore` remains the reference local durable adapter.
