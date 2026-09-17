from hashlib import sha256
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nest_authz import (  # noqa: E402
    Action,
    ApprovalRequirement,
    Authority,
    AuthorizationRequest,
    Decision,
    DecisionEvidence,
    Obligation,
    Outcome,
    Reason,
    RequestContext,
    Resource,
    Subject,
    canonical_bytes,
    sha256_digest,
)


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

        self.assertEqual(digest, sha256(encoded).hexdigest())
        self.assertEqual(len(digest), 64)
        self.assertEqual(
            digest,
            "5a804e74f9c21b92ff085deb96b1a338ab56c67c019b7c14e5bd1fd6fe330495",
        )

    def test_ordered_decision_sequences_preserve_order(self):
        evidence = DecisionEvidence(
            "sha256:bundle",
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

    def test_every_public_domain_type_is_supported(self):
        authority = Authority("grant:1", {"active": True})
        evidence = DecisionEvidence(
            "sha256:bundle",
            matched_policy_id="policy:1",
            matched_authority=authority,
            condition_results={"scope_matches": True},
        )
        values = (
            Subject("agent:7"),
            Action("message.send"),
            Resource("room:general"),
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
                self.assertEqual(len(sha256_digest(value)), 64)

    def test_unsupported_values_are_rejected(self):
        for value in ({"not": "a domain object"}, 1, object()):
            with self.subTest(domain_type=type(value).__name__):
                with self.assertRaises(TypeError):
                    canonical_bytes(value)


if __name__ == "__main__":
    unittest.main()
