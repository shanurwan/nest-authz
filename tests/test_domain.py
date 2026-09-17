from dataclasses import fields, is_dataclass
import unittest

import nest_authz
from nest_authz import (
    Action,
    ApprovalRequirement,
    Authority,
    AuthorizationRequest,
    Condition,
    ConditionStatus,
    Decision,
    DecisionEvidence,
    Obligation,
    Outcome,
    FieldReference,
    Policy,
    PolicyBundle,
    Reason,
    RequestContext,
    Resource,
    Rule,
    Sha256Digest,
    Subject,
)


_PUBLIC_DATACLASS_DOMAIN_RECORDS = (
    Subject,
    Action,
    Resource,
    Sha256Digest,
    FieldReference,
    Condition,
    RequestContext,
    Authority,
    AuthorizationRequest,
    Reason,
    Obligation,
    ApprovalRequirement,
    Rule,
    Policy,
    PolicyBundle,
    DecisionEvidence,
    Decision,
)


def _policy_bundle_digest():
    return Sha256Digest.from_hex("ab" * 32)


class DomainInvariantTests(unittest.TestCase):
    def test_identifiers_must_not_be_blank(self):
        for factory in (Subject, Resource, Authority):
            for value in ("", " ", "\t\n"):
                with self.subTest(factory=factory.__name__, value=value):
                    with self.assertRaisesRegex(ValueError, "must not be blank"):
                        factory(value)

    def test_action_name_must_not_be_blank(self):
        for value in ("", " ", "\t\n"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "must not be blank"):
                    Action(value)

    def test_request_can_represent_absent_authority_without_authentication(self):
        request = AuthorizationRequest(
            subject=Subject("agent:7"),
            action=Action("message.send"),
            resource=Resource("room:general"),
            context=RequestContext(),
            authority=None,
        )

        self.assertIsNone(request.authority)
        self.assertEqual(
            {field.name for field in fields(Subject)},
            {"identifier"},
        )
        self.assertFalse(hasattr(request.subject, "authenticated"))

    def test_request_rejects_untyped_components(self):
        invalid_values = (
            ("subject", "agent:7"),
            ("action", "message.send"),
            ("resource", "room:general"),
            ("context", {}),
            ("authority", "grant:1"),
        )
        for field_name, bad_value in invalid_values:
            values = {
                "subject": Subject("agent:7"),
                "action": Action("message.send"),
                "resource": Resource("room:general"),
                "context": RequestContext(),
                "authority": Authority("grant:1"),
            }
            values[field_name] = bad_value
            with self.subTest(field=field_name):
                with self.assertRaises(TypeError):
                    AuthorizationRequest(**values)

    def test_key_value_fields_have_deterministic_equality(self):
        left = RequestContext((("zone", "north"), ("attempt", 2)))
        right = RequestContext({"attempt": 2, "zone": "north"})

        self.assertEqual(left.attributes, (("attempt", 2), ("zone", "north")))
        self.assertEqual(left, right)

    def test_mutable_constructor_inputs_are_copied(self):
        source = [["zone", "north"]]
        context = RequestContext(source)
        source[0][1] = "south"
        source.append(["attempt", 2])

        self.assertEqual(context.attributes, (("zone", "north"),))

    def test_mutable_or_nondeterministic_attribute_values_are_rejected(self):
        for value in ([], {}, 1.5, object()):
            with self.subTest(value=value):
                with self.assertRaisesRegex(TypeError, "values must be"):
                    RequestContext((("key", value),))

    def test_attribute_names_are_non_blank_and_unique(self):
        with self.assertRaisesRegex(ValueError, "must not be blank"):
            RequestContext(((" ", "value"),))
        with self.assertRaisesRegex(ValueError, "duplicate key"):
            RequestContext((("zone", "north"), ("zone", "south")))

    def test_strings_must_be_encodable_as_strict_utf8(self):
        with self.assertRaisesRegex(ValueError, "strict UTF-8"):
            Subject("\ud800")
        with self.assertRaisesRegex(ValueError, "strict UTF-8"):
            RequestContext((("key", "\ud800"),))

    def test_public_dataclass_domain_record_set_is_complete(self):
        exported_dataclasses = {
            value
            for name in nest_authz.__all__
            if isinstance((value := getattr(nest_authz, name)), type)
            and is_dataclass(value)
        }

        self.assertEqual(
            exported_dataclasses,
            set(_PUBLIC_DATACLASS_DOMAIN_RECORDS),
        )

    def test_every_public_dataclass_domain_record_is_frozen(self):
        for record_type in _PUBLIC_DATACLASS_DOMAIN_RECORDS:
            with self.subTest(record_type=record_type.__name__):
                self.assertTrue(is_dataclass(record_type))
                self.assertTrue(record_type.__dataclass_params__.frozen)

    def test_every_public_dataclass_domain_record_is_slotted(self):
        for record_type in _PUBLIC_DATACLASS_DOMAIN_RECORDS:
            with self.subTest(record_type=record_type.__name__):
                slots = record_type.__dict__.get("__slots__")
                self.assertIsNotNone(slots)
                self.assertNotIn("__dict__", slots)

    def test_sha256_digest_is_typed_and_has_canonical_text(self):
        digest_bytes = bytes(range(32))
        digest = Sha256Digest(digest_bytes)

        self.assertEqual(digest.algorithm, "sha256")
        self.assertEqual(digest.value, digest_bytes)
        self.assertEqual(digest.hex_value, digest_bytes.hex())
        self.assertEqual(str(digest), f"sha256:{digest_bytes.hex()}")
        self.assertEqual(Sha256Digest.from_hex(digest_bytes.hex()), digest)

    def test_invalid_sha256_digest_values_fail_construction(self):
        for value in (b"", b"x" * 31, b"x" * 33):
            with self.subTest(length=len(value)):
                with self.assertRaisesRegex(ValueError, "exactly 32 bytes"):
                    Sha256Digest(value)

        with self.assertRaises(TypeError):
            Sha256Digest(bytearray(32))

        for value in ("a" * 63, "a" * 65, "A" * 64, "g" * 64):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "64 lowercase"):
                    Sha256Digest.from_hex(value)

        with self.assertRaises(TypeError):
            Sha256Digest.from_hex(1)

    def test_outcome_is_exhaustive(self):
        self.assertEqual(
            tuple(Outcome),
            (Outcome.PERMIT, Outcome.DENY, Outcome.APPROVAL_REQUIRED),
        )

    def test_condition_status_is_exhaustive(self):
        self.assertEqual(
            tuple(ConditionStatus),
            (
                ConditionStatus.SATISFIED,
                ConditionStatus.UNSATISFIED,
                ConditionStatus.NOT_EVALUATED,
                ConditionStatus.MISSING_INPUT,
                ConditionStatus.ERROR,
            ),
        )

    def test_reason_and_instruction_codes_must_not_be_blank(self):
        for factory in (Reason, Obligation, ApprovalRequirement):
            with self.subTest(factory=factory.__name__):
                with self.assertRaisesRegex(ValueError, "must not be blank"):
                    factory(" ")

    def test_evidence_requires_a_typed_policy_bundle_digest(self):
        with self.assertRaisesRegex(TypeError, "Sha256Digest"):
            DecisionEvidence("sha256:" + "ab" * 32)

    def test_condition_results_are_typed_unique_and_canonical(self):
        evidence = DecisionEvidence(
            _policy_bundle_digest(),
            condition_results=(
                ("scope", ConditionStatus.SATISFIED),
                ("active", ConditionStatus.NOT_EVALUATED),
            ),
        )
        self.assertEqual(
            evidence.condition_results,
            (
                ("active", ConditionStatus.NOT_EVALUATED),
                ("scope", ConditionStatus.SATISFIED),
            ),
        )

        with self.assertRaisesRegex(TypeError, "ConditionStatus"):
            DecisionEvidence(
                _policy_bundle_digest(),
                condition_results=(("scope", True),),
            )
        with self.assertRaisesRegex(ValueError, "duplicate name"):
            DecisionEvidence(
                _policy_bundle_digest(),
                condition_results=(
                    ("scope", ConditionStatus.SATISFIED),
                    ("scope", ConditionStatus.UNSATISFIED),
                ),
            )

    def test_default_deny_can_record_that_nothing_matched(self):
        decision = Decision(
            outcome=Outcome.DENY,
            reasons=(Reason("NO_MATCHING_AUTHORITY"),),
            evidence=DecisionEvidence(_policy_bundle_digest()),
        )

        self.assertIsNone(decision.evidence.matched_policy_id)
        self.assertIsNone(decision.evidence.matched_authority)

    def test_non_deny_requires_matched_policy_and_authority(self):
        for outcome in (Outcome.PERMIT, Outcome.APPROVAL_REQUIRED):
            approval = (
                ApprovalRequirement("OWNER_APPROVAL")
                if outcome is Outcome.APPROVAL_REQUIRED
                else None
            )

            with self.subTest(outcome=outcome, missing="policy"):
                with self.assertRaisesRegex(ValueError, "matched policy"):
                    Decision(
                        outcome=outcome,
                        reasons=(Reason("RULE_MATCHED"),),
                        evidence=DecisionEvidence(_policy_bundle_digest()),
                        approval_requirement=approval,
                    )

            with self.subTest(outcome=outcome, missing="authority"):
                with self.assertRaisesRegex(ValueError, "matched authority"):
                    Decision(
                        outcome=outcome,
                        reasons=(Reason("RULE_MATCHED"),),
                        evidence=DecisionEvidence(
                            _policy_bundle_digest(),
                            matched_policy_id="policy:1",
                        ),
                        approval_requirement=approval,
                    )

    def test_approval_requirement_matches_outcome_exactly(self):
        evidence = DecisionEvidence(
            _policy_bundle_digest(),
            matched_policy_id="policy:1",
            matched_authority=Authority("grant:1"),
        )

        with self.assertRaisesRegex(ValueError, "exactly when"):
            Decision(
                outcome=Outcome.APPROVAL_REQUIRED,
                reasons=(Reason("OWNER_APPROVAL_NEEDED"),),
                evidence=evidence,
            )

        with self.assertRaisesRegex(ValueError, "exactly when"):
            Decision(
                outcome=Outcome.PERMIT,
                reasons=(Reason("ALLOWED"),),
                evidence=evidence,
                approval_requirement=ApprovalRequirement("OWNER_APPROVAL"),
            )

    def test_decision_requires_reason_and_typed_outcome(self):
        evidence = DecisionEvidence(_policy_bundle_digest())

        with self.assertRaisesRegex(ValueError, "at least one reason"):
            Decision(Outcome.DENY, (), evidence)
        with self.assertRaisesRegex(TypeError, "Outcome"):
            Decision("DENY", (Reason("NO_MATCH"),), evidence)

    def test_decision_copies_reason_and_obligation_iterables(self):
        reasons = [Reason("ALLOWED")]
        obligations = [Obligation("AUDIT")]
        evidence = DecisionEvidence(
            _policy_bundle_digest(),
            matched_policy_id="policy:1",
            matched_authority=Authority("grant:1"),
        )
        decision = Decision(Outcome.PERMIT, reasons, evidence, obligations)
        reasons.append(Reason("LATER_MUTATION"))
        obligations.append(Obligation("LATER_MUTATION"))

        self.assertEqual(decision.reasons, (Reason("ALLOWED"),))
        self.assertEqual(decision.obligations, (Obligation("AUDIT"),))


if __name__ == "__main__":
    unittest.main()
