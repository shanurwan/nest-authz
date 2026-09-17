from dataclasses import fields
import unittest

from nest_authz import (
    ApprovalRequirement,
    Condition,
    ConditionOperator,
    FieldNamespace,
    FieldReference,
    Obligation,
    Outcome,
    Policy,
    PolicyBundle,
    Rule,
    RuleEffect,
    Sha256Digest,
    canonical_bytes,
    sha256_digest,
)


def _condition(
    name="risk_level",
    operator=ConditionOperator.EQUALS,
    value="low",
):
    return Condition(
        FieldReference(FieldNamespace.CONTEXT, name),
        operator,
        value,
    )


def _rule(identifier, effect=RuleEffect.PERMIT, conditions=None):
    approval_requirement = (
        ApprovalRequirement("OWNER_APPROVAL")
        if effect is RuleEffect.APPROVAL_REQUIRED
        else None
    )
    return Rule(
        identifier,
        effect,
        tuple(conditions) if conditions is not None else (_condition(),),
        approval_requirement=approval_requirement,
    )


class PolicyDomainTests(unittest.TestCase):
    def test_policy_and_rule_identifiers_must_not_be_blank(self):
        for value in ("", " ", "\t\n"):
            with self.subTest(domain_type="Policy", value=value):
                with self.assertRaisesRegex(ValueError, "must not be blank"):
                    Policy(value)
            with self.subTest(domain_type="Rule", value=value):
                with self.assertRaisesRegex(ValueError, "must not be blank"):
                    Rule(value, RuleEffect.PERMIT, (_condition(),))

    def test_duplicate_policy_identifiers_are_rejected_within_bundle(self):
        with self.assertRaisesRegex(ValueError, "duplicate identifiers"):
            PolicyBundle((Policy("policy:1"), Policy("policy:1")))

    def test_duplicate_rule_identifiers_are_rejected_within_policy(self):
        with self.assertRaisesRegex(ValueError, "duplicate identifiers"):
            Policy(
                "policy:1",
                (
                    _rule("rule:1"),
                    _rule("rule:1", RuleEffect.DENY),
                ),
            )

    def test_same_rule_identifier_is_legal_in_different_policies(self):
        bundle = PolicyBundle(
            (
                Policy("policy:1", (_rule("rule:1"),)),
                Policy("policy:2", (_rule("rule:1"),)),
            )
        )

        self.assertEqual(len(bundle.policies), 2)

    def test_zero_condition_rules_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least one condition"):
            Rule("rule:1", RuleEffect.PERMIT, ())

    def test_duplicate_structural_conditions_are_rejected(self):
        condition = _condition()

        with self.assertRaisesRegex(ValueError, "duplicates"):
            Rule("rule:1", RuleEffect.PERMIT, (condition, condition))

    def test_operator_value_combinations_are_validated(self):
        reference = FieldReference(FieldNamespace.CONTEXT, "attempt")

        with self.assertRaisesRegex(ValueError, "must not have a value"):
            Condition(reference, ConditionOperator.EXISTS, 1)

        for operator in (ConditionOperator.EQUALS, ConditionOperator.NOT_EQUALS):
            with self.subTest(operator=operator, value=None):
                with self.assertRaisesRegex(ValueError, "requires a value"):
                    Condition(reference, operator)

        integer_operators = (
            ConditionOperator.INTEGER_LESS_THAN,
            ConditionOperator.INTEGER_LESS_THAN_OR_EQUAL,
            ConditionOperator.INTEGER_GREATER_THAN,
            ConditionOperator.INTEGER_GREATER_THAN_OR_EQUAL,
        )
        for operator in integer_operators:
            for invalid_value in (True, "1"):
                with self.subTest(operator=operator, value=invalid_value):
                    with self.assertRaisesRegex(TypeError, "require an int"):
                        Condition(reference, operator, invalid_value)

        with self.assertRaisesRegex(TypeError, "ConditionOperator"):
            Condition(reference, "EQUALS", "low")

    def test_all_operator_shapes_can_be_constructed(self):
        reference = FieldReference(FieldNamespace.CONTEXT, "attempt")
        conditions = (
            Condition(reference, ConditionOperator.EQUALS, 1),
            Condition(reference, ConditionOperator.NOT_EQUALS, False),
            Condition(reference, ConditionOperator.EXISTS),
            Condition(reference, ConditionOperator.INTEGER_LESS_THAN, 1),
            Condition(
                reference,
                ConditionOperator.INTEGER_LESS_THAN_OR_EQUAL,
                1,
            ),
            Condition(reference, ConditionOperator.INTEGER_GREATER_THAN, 1),
            Condition(
                reference,
                ConditionOperator.INTEGER_GREATER_THAN_OR_EQUAL,
                1,
            ),
        )

        self.assertEqual(len(conditions), len(ConditionOperator))

    def test_field_reference_requires_typed_namespace_and_nonblank_name(self):
        with self.assertRaisesRegex(TypeError, "FieldNamespace"):
            FieldReference("CONTEXT", "attempt")
        with self.assertRaisesRegex(ValueError, "must not be blank"):
            FieldReference(FieldNamespace.CONTEXT, " ")

    def test_approval_effect_requires_approval_requirement(self):
        with self.assertRaisesRegex(ValueError, "exactly"):
            Rule(
                "rule:1",
                RuleEffect.APPROVAL_REQUIRED,
                (_condition(),),
            )

        rule = Rule(
            "rule:1",
            RuleEffect.APPROVAL_REQUIRED,
            (_condition(),),
            approval_requirement=ApprovalRequirement("OWNER_APPROVAL"),
        )
        self.assertEqual(rule.approval_requirement.code, "OWNER_APPROVAL")

    def test_non_approval_effects_reject_approval_requirement(self):
        for effect in (RuleEffect.PERMIT, RuleEffect.DENY):
            with self.subTest(effect=effect):
                with self.assertRaisesRegex(ValueError, "exactly"):
                    Rule(
                        "rule:1",
                        effect,
                        (_condition(),),
                        approval_requirement=ApprovalRequirement("OWNER_APPROVAL"),
                    )

    def test_collection_inputs_are_defensively_copied(self):
        conditions = [_condition()]
        obligations = [Obligation("AUDIT")]
        rule = Rule(
            "rule:1",
            RuleEffect.PERMIT,
            conditions,
            obligations,
        )
        conditions.append(_condition("region", value="north"))
        obligations.append(Obligation("REDACT"))

        rules = [rule]
        policy = Policy("policy:1", rules)
        rules.append(_rule("rule:2"))

        policies = [policy]
        bundle = PolicyBundle(policies)
        policies.append(Policy("policy:2"))

        self.assertEqual(rule.conditions, (_condition(),))
        self.assertEqual(rule.obligations, (Obligation("AUDIT"),))
        self.assertEqual(policy.rules, (rule,))
        self.assertEqual(bundle.policies, (policy,))

    def test_empty_policies_and_bundles_are_legal_and_inert(self):
        self.assertEqual(Policy("policy:empty").rules, ())
        self.assertEqual(PolicyBundle().policies, ())
        self.assertEqual(PolicyBundle().combining_algorithm, "DENY_OVERRIDES")

    def test_rule_effect_is_distinct_from_decision_outcome(self):
        self.assertIsNot(type(RuleEffect.PERMIT), type(Outcome.PERMIT))
        self.assertNotEqual(RuleEffect.PERMIT, Outcome.PERMIT)

    def test_arbitrary_executable_conditions_cannot_be_represented(self):
        reference = FieldReference(FieldNamespace.CONTEXT, "risk_level")

        with self.assertRaises(TypeError):
            Condition(reference, ConditionOperator.EQUALS, lambda: True)
        with self.assertRaises(TypeError):
            Condition(lambda: True, ConditionOperator.EXISTS)
        with self.assertRaises(TypeError):
            Condition(reference, lambda value: value, "low")

    def test_policy_bundle_has_no_self_digest(self):
        bundle = PolicyBundle((Policy("policy:1", (_rule("rule:1"),)),))

        self.assertNotIn("digest", {item.name for item in fields(PolicyBundle)})
        self.assertIsInstance(sha256_digest(bundle), Sha256Digest)


class PolicyCanonicalEncodingTests(unittest.TestCase):
    def test_policy_bundle_has_stable_canonical_schema_names(self):
        reference = FieldReference(FieldNamespace.CONTEXT, "risk_level")
        condition = Condition(reference, ConditionOperator.EQUALS, "low")
        rule = Rule("rule:1", RuleEffect.PERMIT, (condition,))
        policy = Policy("policy:1", (rule,))
        bundle = PolicyBundle((policy,))
        encoded = canonical_bytes(bundle)

        for schema_name in (
            b"nest-authz/field-namespace@1",
            b"nest-authz/field-reference@1",
            b"nest-authz/condition-operator@1",
            b"nest-authz/condition@1",
            b"nest-authz/rule-effect@1",
            b"nest-authz/rule@1",
            b"nest-authz/policy@1",
            b"nest-authz/policy-bundle@1",
        ):
            with self.subTest(schema_name=schema_name):
                self.assertIn(schema_name, encoded)

    def test_semantically_equivalent_orderings_have_same_bundle_digest(self):
        first_condition = _condition("risk_level", value="low")
        second_condition = _condition("region", value="north")
        first_rule = _rule(
            "rule:a",
            conditions=(first_condition, second_condition),
        )
        reordered_first_rule = _rule(
            "rule:a",
            conditions=(second_condition, first_condition),
        )
        second_rule = _rule("rule:b", RuleEffect.DENY)

        first = PolicyBundle(
            (
                Policy("policy:b", (second_rule,)),
                Policy("policy:a", (first_rule, second_rule)),
            )
        )
        reordered = PolicyBundle(
            (
                Policy("policy:a", (second_rule, reordered_first_rule)),
                Policy("policy:b", (second_rule,)),
            )
        )

        self.assertEqual(first, reordered)
        self.assertEqual(canonical_bytes(first), canonical_bytes(reordered))
        self.assertEqual(sha256_digest(first), sha256_digest(reordered))
        self.assertEqual(sha256_digest(first), sha256_digest(first))

    def test_semantically_different_policies_have_different_digests(self):
        permit = PolicyBundle(
            (Policy("policy:1", (_rule("rule:1", RuleEffect.PERMIT),)),)
        )
        deny = PolicyBundle(
            (Policy("policy:1", (_rule("rule:1", RuleEffect.DENY),)),)
        )

        self.assertNotEqual(canonical_bytes(permit), canonical_bytes(deny))
        self.assertNotEqual(sha256_digest(permit), sha256_digest(deny))

    def test_obligation_order_remains_semantic(self):
        condition = (_condition(),)
        first = PolicyBundle(
            (
                Policy(
                    "policy:1",
                    (
                        Rule(
                            "rule:1",
                            RuleEffect.PERMIT,
                            condition,
                            (Obligation("AUDIT"), Obligation("REDACT")),
                        ),
                    ),
                ),
            )
        )
        second = PolicyBundle(
            (
                Policy(
                    "policy:1",
                    (
                        Rule(
                            "rule:1",
                            RuleEffect.PERMIT,
                            condition,
                            (Obligation("REDACT"), Obligation("AUDIT")),
                        ),
                    ),
                ),
            )
        )

        self.assertNotEqual(first, second)
        self.assertNotEqual(sha256_digest(first), sha256_digest(second))


if __name__ == "__main__":
    unittest.main()
