# ADR 0001: Canonical Encoding for Domain Objects

- Status: Accepted
- Date: 2026-09-18

## Problem

Authorization requests, decisions, and their component values need a stable byte
representation before they can have stable content-derived identifiers. Python
object equality alone does not define a wire format. Common implementation
details such as dictionary insertion order, `repr()`, and `hash()` are not
suitable security boundaries and can vary without changing the semantic domain
value.

The representation must distinguish values that Python may otherwise compare
loosely, such as `True` and `1`, and it must remain stable across interpreter
processes and supported platforms.

## Security Requirements

The canonical encoding MUST:

- be a pure function of the supplied immutable domain value;
- include explicit primitive and domain-object type information;
- be independent of mapping insertion order;
- preserve ordering where ordering is part of domain semantics;
- use fixed byte-order and length rules;
- reject unsupported values instead of guessing an encoding;
- never use `repr()`, `hash()`, memory addresses, time, randomness, network,
  environment variables, filesystem state, databases, or mutable global state;
- produce identical bytes for identical semantic values; and
- provide a SHA-256 digest over the complete versioned representation.

A digest identifies content. It does not authenticate the content and is not a
signature.

## Decision

All public domain values that can contribute to an authorization request or
decision have a canonical representation:

- `Subject`
- `Action`
- `Resource`
- `Sha256Digest`
- `RequestContext`
- `AuthorityContext` (current; the historical `Authority` record used
  `nest-authz/authority@1`)
- `AuthorizationRequest`
- `SubjectPrincipalBinding`
- `SubjectAuthorityBindingStatus`
- `SubjectAuthorityBindingResult`
- `Outcome`
- `ConditionStatus`
- `FieldNamespace`
- `FieldReference`
- `ConditionOperator`
- `Condition`
- `RuleEffect`
- `RuleEvaluationStatus`
- `Rule`
- `Policy`
- `PolicyBundle`
- `RuleEvaluation`
- `Reason`
- `Obligation`
- `ApprovalRequirement`
- `DecisionEvidence`
- `Decision`
- `Principal`
- `AuthorityScope`
- `AuthorityGrant`
- `DelegationChain`
- `RevocationSet`
- `AuthorizationState`
- `AuthorityValidationStatus`
- `VerifiedAuthority`
- `AuthorityValidationResult`
- `AuthorityApplicabilityStatus`
- `AuthorityBoundEvaluation`
- `AuthorityApplicabilityResult`

The public operations are:

- `canonical_bytes(value)`, returning the versioned canonical bytes; and
- `sha256_digest(value)`, returning a typed `Sha256Digest` over those exact
  bytes. Its canonical text is `sha256:<64 lowercase hex>`.

Only exact supported domain types are accepted. Subclasses are rejected so that
additional subclass state cannot be omitted and collide with a base value.

## Chosen Canonical Encoding

The top-level representation starts with this preamble:

```text
ASCII "NEST-AUTHZ-CANONICAL" | 00 | 01
```

The final byte is canonical-format version 1. It is followed by one encoded
domain value.

Every encoded value is a type-length-value frame:

```text
TAG (1 byte) | PAYLOAD_LENGTH (8-byte unsigned big-endian) | PAYLOAD
```

Version 1 defines these tags:

| Tag | Meaning | Payload |
| --- | --- | --- |
| `N` | null | empty |
| `B` | boolean | exactly `00` for false or `01` for true |
| `I` | integer | sign byte followed by minimal unsigned big-endian magnitude |
| `S` | string | strict UTF-8 bytes |
| `L` | ordered sequence | concatenated framed elements |
| `M` | string-keyed map | concatenated framed key/value pairs in canonical key order |
| `R` | domain record | framed wire-type string followed by a framed field map |

Each domain record uses a stable wire type such as `nest-authz/subject@1`.
Python module paths and class representations are not part of the wire format.
Record fields are named and encoded as a map.

Typed SHA-256 digests use `nest-authz/sha256-digest@1`. Condition statuses use
`nest-authz/condition-status@1`. The condition-status model and the version-2
decision-evidence schema are specified by ADR 0002.

Initial policy-domain records use the schemas defined by ADR 0003. ADR 0004
adds evaluator evidence and explicitly advances the affected Condition, Rule,
Policy, PolicyBundle, DecisionEvidence, and Decision record schemas.

ADR 0005 adds delegated-authority records without changing any existing record
schema.

ADR 0006 adds authority-applicability records and advances DecisionEvidence and
Decision for exact-request and validated-authority binding.

Map keys are strings. Entries are sorted lexicographically by the strict UTF-8
bytes of their keys. The serialized map key is still a complete `S` frame, so
the ordering rule and the encoded data are both explicit. Duplicate map keys
are invalid.

Nested values do not repeat the top-level preamble. Their frames remain fully
typed and length-delimited.

## Ordering Semantics

The following collections are mappings. Their input or storage order has no
semantic meaning and their keys are sorted only for canonical serialization:

- request-context attributes;
- authority attributes;
- obligation parameters;
- approval-requirement parameters;
- decision-evidence condition results; and
- policies within a policy bundle;
- rules within a policy;
- conditions within a rule; and
- approval requirements within a rule or decision;
- rule evaluations within decision evidence; and
- authority-scope context upper bounds;
- grant identifiers within a revocation set; and
- authority-bound evaluations within an applicability result; and
- record fields.

`Decision.reasons` and `Decision.obligations` are ordered sequences. Their order
is preserved because it already participates in domain equality and may express
explanation priority or enforcement order. Reordering either sequence therefore
changes the canonical representation and digest.

Rule obligations are ordered for the same reason. Policy, rule, and condition
collections are canonicalized because ADR 0003 declares their ordering
non-semantic.

Delegation-chain order is semantic root-to-leaf provenance and is preserved.
Scope upper bounds and revocation identifiers are set-like and are sorted by
strict UTF-8 key bytes before storage and encoding.

ADR 0004 declares approval-requirement ordering non-semantic. Rule evaluations
are ordered by policy and rule identifier, and their condition results are
ordered by condition identifier.

## String and Unicode Handling

Strings are encoded using strict UTF-8, and frame lengths count bytes rather
than Unicode code points. Lone surrogate code points are invalid because they
cannot be represented by strict UTF-8.

Version 1 performs no Unicode normalization. The exact code-point sequence is
part of the domain value, so precomposed and decomposed spellings are distinct
unless an upstream identifier profile normalizes them before construction.
Silently normalizing identifiers inside the encoder could merge identifiers
that the domain currently treats as unequal.

Map ordering uses the resulting UTF-8 bytes, not locale-sensitive collation.

## Boolean, Integer, and Null Handling

Booleans are encoded before considering integers and have their own `B` tag.
This is necessary because Python's `bool` is a subclass of `int` and
`True == 1`.

Integers have an `I` tag. The first payload byte is `00` for zero or a positive
integer and `01` for a negative integer. The remaining bytes are the absolute
value as a minimal unsigned big-endian magnitude with no leading zero byte.
Zero has no magnitude bytes. This supports arbitrary-size Python integers and
avoids decimal formatting limits or leading-zero ambiguity.

Null is encoded as an `N` frame with an empty payload. It cannot collide with an
empty string, zero, false, an empty sequence, or an empty map because each has a
different tag.

Floating-point values are not supported by the current domain scalar model.
This avoids NaN equality, signed-zero, and cross-platform formatting questions.

## Why Python `hash()` Is Unsuitable

Python hashing exists to distribute objects among in-process hash-table buckets.
It is not a serialization and it is not collision resistant. Hashes of strings
and bytes are randomized between ordinary interpreter processes, the result size
and details are implementation-dependent, and hash algorithms may change across
Python versions.

Equal objects must have equal hashes within a process, but that contract does
not make the numeric hash value persistent or reproducible. Domain equality is
deterministic; Python object hashing is process-local implementation behavior.
`hash()` MUST NOT be used for persisted identifiers, audit references, cache
keys shared across processes, or any security identifier.

## Rejected Alternatives

### `repr()` or `str()`

These are human-oriented Python representations, not stable protocols. They may
change during refactoring, may include implementation details, and custom object
representations can include memory addresses.

### Python `hash()`

It is process-local, collision-prone, implementation-dependent, and not
cryptographic, as described above.

### `pickle`

Pickle is Python-specific, version-sensitive, unsafe to load from untrusted
sources, and not designed to produce canonical bytes.

### Ordinary JSON

Ordinary JSON does not prescribe object-key order, Unicode normalization,
whitespace, or a distinction between all required domain types. JSON numbers
also introduce interoperability questions for arbitrary-size integers. A fully
specified canonical JSON profile plus domain type envelopes would be larger than
the small binary format required here.

### CBOR, MessagePack, or another external serialization library

Canonical profiles exist for some formats, but adding a dependency and choosing
a broader data model is not justified by the current small set of domain types.
This decision can be revisited if interoperability requirements outweigh the
benefit of a dependency-free encoding.

## Versioning Considerations

The preamble versions the canonical framing rules. Any incompatible change to
primitive encoding, key ordering, framing, or Unicode treatment requires a new
canonical-format version.

Each record wire type also carries a schema version, for example `@1`. Adding,
removing, renaming, or changing the meaning of a record field requires a new
record schema version. Refactoring Python module or class names does not require
a version change when the wire schema remains unchanged.

Consumers that persist digests should store or communicate the digest algorithm
alongside the hexadecimal value. Version 1's `sha256_digest()` operation returns
a `Sha256Digest` containing the explicit `sha256` algorithm and the digest of
the complete preamble and top-level frame.

## Consequences and Limitations

- Canonical bytes and SHA-256 identifiers are reproducible across processes for
  the same supported domain value.
- Mapping construction order cannot affect bytes or digests.
- Type tags prevent primitive and domain-type ambiguity.
- Sequence reordering intentionally changes bytes and digests.
- Version or schema changes intentionally change bytes and digests.
- No decoder is introduced yet; this ADR defines deterministic encoding and
  identification only.
- The custom format requires independent implementations to follow this ADR
  exactly if cross-language interoperability is later needed.
- Unicode confusable characters remain distinct and must be addressed by a
  future identifier profile if necessary.
- SHA-256 digests provide content integrity references, not origin authenticity,
  authorization, signatures, freshness, or replay protection.
- This encoding does not implement policy evaluation or validate that decision
  evidence is truthful or complete.
