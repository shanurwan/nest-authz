# ADR 0013: Nanda Town Integration

- Status: Accepted
- Date: 2026-09-18

## Context

NEST AuthZ now has deterministic policy, delegation, trust, approval,
execution-revalidation, and single-use enforcement components. It needs a real
offline integration that demonstrates those components through Nanda Town's
current Lab architecture without changing the NEST semantic core or creating a
parallel simulator.

The current checked-out Nanda Town version is 0.2.0. Repository archaeology was
performed against that checkout before selecting an integration design.

## Current Nanda Town Interfaces

### Auth layer

`nandatown.layers.auth` contains the current Auth implementations. There is no
formal Python `Protocol`; plugins are duck typed. The live interface used by
the simulator and registry is exactly:

```text
__init__(engine)
sign_as(name: str, payload: Any) -> str
verify(
    claimed_name: str,
    payload: Any,
    signature: str,
    subject: str = "",
) -> bool
```

The reference plugin is `HmacAuth`, registered as `hmac.v1`. It signs canonical
JSON with the simulated identity's HMAC key. `PlainAuth`, registered as
`plain.v1`, is an intentionally unsafe comparison plugin. Contrary to the
initial integration brief, this checkout contains no JWT Auth plugin.

The boolean `verify()` result gives Nanda Town no typed channel to distinguish
authentication failure from authorization denial. NEST-specific trace events
therefore retain the precise authorization reason before a denial returns
`False`. Nanda Town's later generic `delivery_failed` / `bad signature` event is
transport-gate behavior, not the authoritative NEST denial explanation.

### Plugin registry and loading

`nandatown.layers` defines:

- `register(layer, plugin_id)`, a class decorator;
- `resolve(layer, plugin_id)`, used by the engine;
- `plugins()`, used for discovery output;
- `LAYER_NAMES` and `DEFAULT_PLUGINS`; and
- a process-local registry populated by imports.

`nandatown.sim.runner.load_plugin_files()` loads scenario plugin files with
`importlib.util.spec_from_file_location()`. `ScenarioSpec.plugin_files` names
those files and `load_scenario_file()` resolves relative paths against the YAML
file.

This checkout has no Python distribution entry-point group for layer plugins.
Its only package entry point is the `nandatown` console script. Registering an
unused packaging entry point would not make the simulator discover the plugin,
so this integration uses the supported `plugin_files` mechanism.

### Scenario model

`nandatown.sim.scenario.ScenarioSpec` is the Pydantic model behind the YAML
schema. Its current fields are:

- `name`, `description`, and `seed`;
- `layers`;
- `agents`, each containing `name`, `role`, and `config`;
- `faults`;
- `redact_fields`;
- `max_time`;
- `validator`;
- `plugin_files`; and
- `adaptations`.

Bundled scenarios live in `nandatown.sim.scenarios`. A third-party scenario is
run by filesystem path and is not silently installed into Nanda Town's built-in
catalog.

### Simulator and logical state

`nandatown.sim.engine.Engine` owns:

- `rng = random.Random(spec.seed)`;
- logical `now`, beginning at `0.0`;
- an event queue ordered by `(logical_time, insertion_sequence)`;
- `schedule()`, `deliver()`, and `emit()`; and
- the selected layer instances.

`nandatown.sim.api.TownAPI` is the agent-facing context. It exposes logical time,
the seeded RNG, scheduling, observation, messaging, and the other layer APIs.
NEST maps the simulator's logical seconds to exact integer logical
milliseconds. It does not read a system clock.

### Trace and validation

`nandatown.records.TownEvent` contains `event_id`, `run_id`, logical `at`,
`observer`, `kind`, `subject`, and `detail`. Events are emitted only through the
engine/TownAPI mechanisms.

`nandatown.sim.validators.validator(name)` registers a validator.
`evaluate_scenario()` supplies a `Trace` with `find()`, `ids()`, and `index()`;
validators return `StageResult` values. Lab evaluation also appends ledger and
privacy stages.

Current tests use `run_lab()`, load the evidence bundle, and compare normalized
logical traces. Nanda Town deliberately excludes generated run IDs and
evaluation wall-clock metadata from Tier-1 semantic determinism; complete
bundles are not promised byte-identical.

## Decision

The integration lives at:

```text
src/nest_authz/integrations/nandatown/
```

The dependency direction is:

```text
Nanda Town Lab
    -> NEST AuthZ Nanda Town adapter/plugin
        -> NEST AuthZ core
```

No core module imports Nanda Town. `import nest_authz` remains independent of
the simulator. The Nanda Town dependency is declared only in the optional
`nandatown` extra. The scenario YAML is package data for the integration
subpackage.

`adapter.py` contains translation and deterministic demo material but no Nanda
Town imports. `plugin.py` is the Nanda-specific registration boundary and is
loaded explicitly from `delegated_authority.yaml`.

## Auth Plugin Semantics

`NestAuthzAuth` is registered as `auth = nest-authz.v1` and implements the
actual current `sign_as`/`verify` methods.

It first delegates sender authentication to Nanda Town's `HmacAuth`. Successful
HMAC verification is never treated as authorization. Untagged simulator
messages and agent cards receive only the reference authentication behavior.

For a body containing a `nest_authz` marker, the plugin translates the exact
claimed agent, action, resource, amount, explicitly configured authority
profile, and simulator logical state into:

- `AuthorizationRequest`;
- `SubjectPrincipalBinding`;
- a verified `TrustedPolicyBundle`;
- an `AuthenticatedDelegatedAuthority`; and
- `AuthorizationState`.

It invokes `authenticate_delegation_chain()` and `authorize_trusted()`. It does
not duplicate policy evaluation, attenuation, attestation verification, holder
binding, or authority applicability.

Only `PERMIT` passes a protected-action message through Nanda Town's boolean
delivery gate. `APPROVAL_REQUIRED` and `DENY` retain typed trace evidence and do
not admit the protected request.

## Scenario Authority and Policy

The primary graph is:

```text
principal:alice [trusted root, key:demo-alice]
    |
    | G1 grant:alice-finance
    | payments.transfer / account:alice / amount <= 5000
    v
principal:finance-agent [key:demo-finance-agent]
    |
    | G2 grant:finance-payment-subagent
    | payments.transfer / account:alice / amount <= 1000
    v
principal:payment-subagent
```

G1 is signed by Alice's configured authority key. G2 is signed by the Finance
Agent key. Both attestations are verified for `AUTHORITY_GRANT`; logical grantor
and signing-key ownership must agree.

The policy is signed by a separate key trusted only for `POLICY_BUNDLE`:

- exact transfer/resource and `amount <= 1000`: `PERMIT`;
- exact transfer/resource and `amount > 1000`: `APPROVAL_REQUIRED`; and
- otherwise: default `DENY`.

The approval requirement allows only
`principal:authorized-manager`. Its code `MANAGER_APPROVAL` has no role or
authorization meaning by itself.

After G1 is revoked, the replay demonstration uses G3
`grant:alice-finance-refresh`, a separately signed root grant from Alice to the
same Finance Agent. G3 is not a reset or mutation of G1. The revocation set
continues to contain G1, while G3 proves the unrelated-revocation semantics and
provides a currently valid operation for single-use reservation.

## Test-Only Cryptographic Material

The scenario uses fixed Ed25519 private-key seeds so repeated offline runs
produce identical artifact identities and signatures. They are labeled
`TEST-ONLY / PUBLIC DEMO MATERIAL` in source, are intentionally public, and are
created only as short-lived signing inputs while constructing the scenario.

Private keys are not placed in NEST domain objects, canonical receipts, trace
events, scenario YAML, or verification evidence. These public demo seeds MUST
NEVER be reused for operational trust.

## Scenario Flow

The scenario deterministically performs:

1. Payment Subagent requests amount 700 through G1/G2: `PERMIT`.
2. Payment Subagent requests amount 4000: `DENY`, `BOUND_EXCEEDED`.
3. Finance Agent requests amount 4000 through G1: `APPROVAL_REQUIRED`.
4. Mallory attempts `MANAGER_APPROVAL`: `PRINCIPAL_NOT_ALLOWED`.
5. The configured manager approves: overall state becomes `APPROVED`.
6. G1 is revoked and execution is freshly revalidated: delegation
   authentication fails because current authority validation is `REVOKED`.
7. Finance Agent obtains separate, valid G3 approval; fresh revalidation creates
   an `ExecutionPermit`; reservation returns `NEW_RESERVATION`; replay of the
   exact permit returns `EXISTING_RESERVED` with the same `ExecutionId`.

No protected business operation is executed.

## Trace Evidence

The plugin emits through `Engine.emit()` only:

- `nest_authorization_decided`;
- `nest_approval_authorization`;
- `nest_approval_state`;
- `nest_execution_revalidation`;
- `nest_execution_reservation`;
- `nest_adapter_rejected`; and
- `nest_request_admitted` through the normal `TownAPI.observe()` path.

Evidence includes stable operation, agent, action/resource, outcome/status,
effective grant, relevant typed digests, approval status, revalidation failure,
and execution reservation status. It excludes HMAC keys, private Ed25519
material, signatures, and other secrets.

## Validators and Non-Vacuity

The `nest_authz_delegated_authority` validator proves:

1. the amount-700 attempt exists, is permitted, and reaches the gate;
2. the amount-4000 subagent attempt exists and is denied by
   `BOUND_EXCEEDED`;
3. the Finance Agent approval path exists and becomes approved only by the
   configured manager;
4. Mallory's actual attempt exists and is rejected;
5. the revoked-chain execution attempt exists and produces no permit; and
6. the fresh permit has one `NEW_RESERVATION`, then one
   `EXISTING_RESERVED`, one execution ID, and one logical record.

Every adversarial stage requires its triggering event as evidence. Missing
attacks yield `not_enough_evidence`; an event with unsafe behavior yields
`failed`. Tests mutate a real hardened trace into an unsafe scope result and
prove the validator fails rather than passing vacuously.

## Determinism

The integration imports no wall-clock, UUID, global-randomness, network, LLM,
or cloud APIs. It consumes Nanda Town's logical clock and deterministic seeded
identity/HMAC layer.

Nanda Town itself generates a run ID and evaluation timestamp outside logical
trace semantics. Tests therefore compare all authorization-relevant `nest_*`
events after removing only `run_id`. Same-seed runs are equal, and seeds 42, 7,
and 1337 also yield equal authorization semantics because the scenario has no
RNG-dependent authorization branch.

## Execution Reservation Boundary

The Tier-1 scenario uses a private deterministic in-run reservation ledger.
It derives IDs with `execution_id_for()` and constructs the core typed
reservation records, but it does not claim to implement the complete
`ExecutionStore` persistence port. This avoids an environment-selected
database path in a deterministic Lab run.

It is not durable persistence and makes no cross-process claim. Real local
enforcement uses `SQLiteExecutionStore` from ADR 0012. The scenario demonstrates
the same identity and replay status semantics, not database crash recovery.

## Installation

For adjacent editable checkouts:

```text
python -m pip install --editable ../nandatown
python -m pip install --editable ".[nandatown]"
```

Core-only users continue to install NEST AuthZ without the extra and can use
`import nest_authz` without importing Nanda Town.

## Consequences and Limitations

- The integration exercises the real Nanda Lab loader, engine, trace, and
  validator pipeline.
- NEST core semantics and dependency direction remain unchanged.
- Nanda's current Auth boolean conflates delivery-gate failure categories; NEST
  trace evidence preserves the exact reason.
- The simulator HMAC identity and supplied Subject/Principal mappings remain
  trusted test inputs, not JWT, DID, IdP, or human-identity proof.
- Demo private seeds are public fixtures, not operational keys.
- The integration scenario store is deterministic but not durable.
- No HTTP API, external database, network call, LLM, cloud service, Kubernetes,
  Nanda production integration, or protected-operation execution is added.
- Nanda Town has no current Python lint, formatter, or typecheck command; its
  Python quality gate is pytest plus packaging/smoke checks described in
  `CONTRIBUTING.md` and CI.

## Rejected Alternatives

### Add a Python entry point

Rejected because the current Nanda Town loader never queries distribution entry
points. Scenario `plugin_files` is the implemented extension mechanism.

### Modify Nanda Town's Auth interface

Rejected for this phase. The adapter targets the current interface exactly and
records typed denial evidence before returning its boolean gate result.

### Add authorization to the NEST core for Nanda-specific types

Rejected because it would reverse the dependency direction and contaminate the
framework-independent semantic core.

### Reuse revoked G1 for the replay example

Rejected because approval cannot resurrect authority. The replay flow uses a
separate signed grant while retaining G1 in the current revocation set.
