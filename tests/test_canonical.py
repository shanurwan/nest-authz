from hashlib import sha256
import os
import subprocess
import sys
import unittest

from nest_authz import (
    Action,
    ApprovalRequirement,
    Authority,
    AuthorizationRequest,
    Condition,
    ConditionOperator,
    ConditionStatus,
    Decision,
    DecisionEvidence,
    Obligation,
    Outcome,
    FieldNamespace,
    FieldReference,
    Policy,
    PolicyBundle,
    Reason,
    RequestContext,
    Resource,
    Rule,
    RuleEffect,
    Sha256Digest,
    Subject,
    canonical_bytes,
    sha256_digest,
)


_SUBJECT_CANONICAL_HEX = (
    "4e4553542d415554485a2d43414e4f4e4943414c0001520000000000000049"
    "5300000000000000146e6573742d617574687a2f7375626a65637440314d00"
    "0000000000002353000000000000000a6964656e7469666965725300000000"
    "000000076167656e743a37"
)
_SUBJECT_DIGEST_HEX = (
    "5a804e74f9c21b92ff085deb96b1a338ab56c67c019b7c14e5bd1fd6fe330495"
)


def _policy_bundle_digest():
    return Sha256Digest.from_hex("ab" * 32)


class CanonicalEncodingTests(unittest.TestCase):
    def test_mapping_insertion_order_does_not_change_canonical_bytes(self):
        left = RequestContext({"zone": "north", "attempt": 2})
        right = RequestContext({"attempt": 2, "zone": "north"})

        self.assertEqual(canonical_bytes(left), canonical_bytes(right))

    def test_mapping_insertion_order_does_not_change_digest(self):
        left = Authority("grant:1", {"scope": "read", "active": True})
        right = Authority("grant:1", {"active": True, "scope": "read"})

        self.assertEqual(sha256_digest(left), sha256_digest(right))

    def test_distinct_primitive_and_domain_types_have_distinct_bytes(self):
        scalar_values = (True, 1, "1", None)
        encodings = [
            canonical_bytes(RequestContext((("value", value),)))
            for value in scalar_values
        ]

        for index, left in enumerate(encodings):
            for right in encodings[index + 1 :]:
                self.assertNotEqual(left, right)

        self.assertNotEqual(
            RequestContext((("value", True),)),
            RequestContext((("value", 1),)),
        )

        self.assertNotEqual(
            canonical_bytes(Subject("same")),
            canonical_bytes(Resource("same")),
        )

    def test_repeated_serialization_is_identical(self):
        request = AuthorizationRequest(
            subject=Subject("agent:7"),
            action=Action("message.send"),
            resource=Resource("room:general"),
            context=RequestContext({"attempt": 2}),
            authority=Authority("grant:1", {"active": True}),
        )

        first = canonical_bytes(request)
        self.assertEqual(first, canonical_bytes(request))
        self.assertEqual(first, canonical_bytes(request))

    def test_canonicalization_is_stable_across_python_hash_seeds(self):
        script = "\n".join(
            (
                "from nest_authz import Subject, canonical_bytes, sha256_digest",
                "value = Subject('agent:7')",
                "print(canonical_bytes(value).hex())",
                "print(str(sha256_digest(value)))",
            )
        )
        outputs = []

        for seed in ("1", "987654"):
            environment = os.environ.copy()
            environment["PYTHONHASHSEED"] = seed
            completed = subprocess.run(
                [sys.executable, "-c", script],
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            )
            outputs.append(completed.stdout.strip().splitlines())

        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(
            outputs[0],
            [_SUBJECT_CANONICAL_HEX, f"sha256:{_SUBJECT_DIGEST_HEX}"],
        )

    def test_canonical_integer_boundaries_are_stable_and_distinct(self):
        very_large_positive = (1 << 4096) + 123456789
        very_large_negative = -((1 << 4096) + 987654321)
        values = (
            0,
            1,
            -1,
            127,
            128,
            255,
            256,
            -127,
            -128,
            very_large_positive,
            very_large_negative,
        )
        encodings = []

        for value in values:
            with self.subTest(value=value):
                domain_value = RequestContext((("value", value),))
                encoded = canonical_bytes(domain_value)
                self.assertEqual(encoded, canonical_bytes(domain_value))
                encodings.append(encoded)

        for index, left in enumerate(encodings):
            for right in encodings[index + 1 :]:
                self.assertNotEqual(left, right)

    def test_mutating_constructor_input_cannot_change_digest(self):
        context_input = [["attempt", 2]]
        authority_input = [["active", True]]
        request = AuthorizationRequest(
            subject=Subject("agent:7"),
            action=Action("message.send"),
            resource=Resource("room:general"),
            context=RequestContext(context_input),
            authority=Authority("grant:1", authority_input),
        )
        before = sha256_digest(request)

        context_input[0][1] = 99
        context_input.append(["zone", "south"])
        authority_input[0][1] = False

        self.assertEqual(before, sha256_digest(request))

    def test_semantically_different_values_have_different_bytes(self):
        self.assertNotEqual(
            canonical_bytes(Action("message.read")),
            canonical_bytes(Action("message.write")),
        )

    def test_digest_is_stable_sha256_of_canonical_bytes(self):
        value = Subject("agent:7")
        encoded = canonical_bytes(value)
        digest = sha256_digest(value)

        self.assertEqual(digest.value, sha256(encoded).digest())
        self.assertEqual(digest.hex_value, sha256(encoded).hexdigest())
        self.assertEqual(digest.hex_value, _SUBJECT_DIGEST_HEX)
        self.assertEqual(str(digest), f"sha256:{_SUBJECT_DIGEST_HEX}")

    def test_ordered_decision_sequences_preserve_order(self):
        evidence = DecisionEvidence(
            _policy_bundle_digest(),
            matched_policy_id="policy:1",
            matched_authority=Authority("grant:1"),
        )
        first = Decision(
            Outcome.PERMIT,
            (Reason("PRIMARY"), Reason("SECONDARY")),
            evidence,
            (Obligation("AUDIT"), Obligation("REDACT")),
        )
        second = Decision(
            Outcome.PERMIT,
            (Reason("SECONDARY"), Reason("PRIMARY")),
            evidence,
            (Obligation("REDACT"), Obligation("AUDIT")),
        )

        self.assertNotEqual(canonical_bytes(first), canonical_bytes(second))

    def test_unicode_is_not_implicitly_normalized(self):
        precomposed = Subject("caf\u00e9")
        decomposed = Subject("cafe\u0301")

        self.assertNotEqual(canonical_bytes(precomposed), canonical_bytes(decomposed))

    def test_new_domain_types_have_stable_wire_schema_names(self):
        digest_bytes = canonical_bytes(_policy_bundle_digest())
        status_bytes = canonical_bytes(ConditionStatus.MISSING_INPUT)
        evidence_bytes = canonical_bytes(
            DecisionEvidence(
                _policy_bundle_digest(),
                condition_results={
                    "has_context": ConditionStatus.MISSING_INPUT,
                },
            )
        )

        self.assertIn(b"nest-authz/sha256-digest@1", digest_bytes)
        self.assertIn(b"nest-authz/condition-status@1", status_bytes)
        self.assertIn(b"nest-authz/decision-evidence@2", evidence_bytes)
        self.assertIn(b"policy_bundle_digest", evidence_bytes)

    def test_every_public_domain_type_is_supported(self):
        authority = Authority("grant:1", {"active": True})
        field_reference = FieldReference(FieldNamespace.CONTEXT, "risk_level")
        policy_condition = Condition(
            field_reference,
            ConditionOperator.EQUALS,
            "low",
        )
        policy_rule = Rule(
            "rule:1",
            RuleEffect.PERMIT,
            (policy_condition,),
        )
        policy = Policy("policy:1", (policy_rule,))
        policy_bundle = PolicyBundle((policy,))
        evidence = DecisionEvidence(
            _policy_bundle_digest(),
            matched_policy_id="policy:1",
            matched_authority=authority,
            condition_results={
                "scope_matches": ConditionStatus.SATISFIED,
            },
        )
        values = (
            Subject("agent:7"),
            Action("message.send"),
            Resource("room:general"),
            _policy_bundle_digest(),
            RequestContext({"attempt": 2}),
            authority,
            AuthorizationRequest(
                Subject("agent:7"),
                Action("message.send"),
                Resource("room:general"),
                RequestContext(),
                authority,
            ),
            Outcome.PERMIT,
            ConditionStatus.SATISFIED,
            FieldNamespace.CONTEXT,
            field_reference,
            ConditionOperator.EQUALS,
            policy_condition,
            RuleEffect.PERMIT,
            policy_rule,
            policy,
            policy_bundle,
            Reason("ALLOWED"),
            Obligation("AUDIT"),
            ApprovalRequirement("OWNER_APPROVAL"),
            evidence,
            Decision(
                Outcome.PERMIT,
                (Reason("ALLOWED"),),
                evidence,
                (Obligation("AUDIT"),),
            ),
        )

        for value in values:
            with self.subTest(domain_type=type(value).__name__):
                self.assertIsInstance(canonical_bytes(value), bytes)
                self.assertEqual(len(sha256_digest(value).value), 32)

    def test_unsupported_values_are_rejected(self):
        for value in ({"not": "a domain object"}, 1, object()):
            with self.subTest(domain_type=type(value).__name__):
                with self.assertRaises(TypeError):
                    canonical_bytes(value)


if __name__ == "__main__":
    unittest.main()
