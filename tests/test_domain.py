from dataclasses import FrozenInstanceError, fields
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
)


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

    def test_all_domain_objects_are_frozen(self):
        subject = Subject("agent:7")

        with self.assertRaises(FrozenInstanceError):
            subject.identifier = "agent:8"

    def test_outcome_is_exhaustive(self):
        self.assertEqual(
            tuple(Outcome),
            (Outcome.PERMIT, Outcome.DENY, Outcome.APPROVAL_REQUIRED),
        )

    def test_reason_and_instruction_codes_must_not_be_blank(self):
        for factory in (Reason, Obligation, ApprovalRequirement):
            with self.subTest(factory=factory.__name__):
                with self.assertRaisesRegex(ValueError, "must not be blank"):
                    factory(" ")

    def test_evidence_requires_a_policy_bundle_identifier(self):
        with self.assertRaisesRegex(ValueError, "policy bundle identifier"):
            DecisionEvidence(" ")

    def test_condition_results_are_boolean_unique_and_canonical(self):
        evidence = DecisionEvidence(
            "sha256:bundle",
            condition_results=(("scope", True), ("active", False)),
        )
        self.assertEqual(
            evidence.condition_results,
            (("active", False), ("scope", True)),
        )

        with self.assertRaisesRegex(TypeError, "bool"):
            DecisionEvidence("sha256:bundle", condition_results=(("scope", 1),))
        with self.assertRaisesRegex(ValueError, "duplicate name"):
            DecisionEvidence(
                "sha256:bundle",
                condition_results=(("scope", True), ("scope", False)),
            )

    def test_default_deny_can_record_that_nothing_matched(self):
        decision = Decision(
            outcome=Outcome.DENY,
            reasons=(Reason("NO_MATCHING_AUTHORITY"),),
            evidence=DecisionEvidence("sha256:bundle"),
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
                        evidence=DecisionEvidence("sha256:bundle"),
                        approval_requirement=approval,
                    )

            with self.subTest(outcome=outcome, missing="authority"):
                with self.assertRaisesRegex(ValueError, "matched authority"):
                    Decision(
                        outcome=outcome,
                        reasons=(Reason("RULE_MATCHED"),),
                        evidence=DecisionEvidence(
                            "sha256:bundle",
                            matched_policy_id="policy:1",
                        ),
                        approval_requirement=approval,
                    )

    def test_approval_requirement_matches_outcome_exactly(self):
        evidence = DecisionEvidence(
            "sha256:bundle",
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
        evidence = DecisionEvidence("sha256:bundle")

        with self.assertRaisesRegex(ValueError, "at least one reason"):
            Decision(Outcome.DENY, (), evidence)
        with self.assertRaisesRegex(TypeError, "Outcome"):
            Decision("DENY", (Reason("NO_MATCH"),), evidence)

    def test_decision_copies_reason_and_obligation_iterables(self):
        reasons = [Reason("ALLOWED")]
        obligations = [Obligation("AUDIT")]
        evidence = DecisionEvidence(
            "sha256:bundle",
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
