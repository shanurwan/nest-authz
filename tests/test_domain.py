from dataclasses import fields, is_dataclass
import unittest

import nest_authz
from nest_authz import (
    Action,
    ApprovalRequirement,
    ApprovalRequirementState,
    ApproverAuthorizationResult,
    ApproverSubjectPrincipalBinding,
    AuthorityContext,
    AuthorityApplicabilityResult,
    AuthorityBoundEvaluation,
    AuthorityGrant,
    AuthorityScope,
    AuthorityValidationResult,
    AuthorizationRequest,
    AuthorizationState,
    Condition,
    ConditionOperator,
    ConditionStatus,
    Decision,
    DecisionEvidence,
    DecisionReceipt,
    DelegationChain,
    ExecutionAuthorizationResult,
    ExecutionPermit,
    Obligation,
    Outcome,
    FieldNamespace,
    FieldReference,
    Policy,
    PolicyBundle,
    PendingApproval,
    Principal,
    Reason,
    RequestContext,
    Resource,
    Rule,
    RuleEffect,
    RuleEvaluation,
    RuleEvaluationStatus,
    RevocationSet,
    Sha256Digest,
    Subject,
    SubjectAuthorityBindingResult,
    SubjectAuthorityBindingStatus,
    SubjectPrincipalBinding,
    VerifiedAuthority,
    check_authority_applicability,
    check_subject_authority_binding,
    sha256_digest,
    validate_authority,
)


_PUBLIC_DATACLASS_DOMAIN_RECORDS = (
    Subject,
    Action,
    Resource,
    Sha256Digest,
    FieldReference,
    Condition,
    RequestContext,
    AuthorityContext,
    AuthorizationRequest,
    SubjectPrincipalBinding,
    SubjectAuthorityBindingResult,
    Reason,
    Obligation,
    ApprovalRequirement,
    ApprovalRequirementState,
    ApproverSubjectPrincipalBinding,
    ApproverAuthorizationResult,
    Rule,
    Policy,
    PolicyBundle,
    RuleEvaluation,
    DecisionEvidence,
    Decision,
    DecisionReceipt,
    PendingApproval,
    ExecutionPermit,
    ExecutionAuthorizationResult,
    Principal,
    AuthorityScope,
    AuthorityGrant,
    DelegationChain,
    RevocationSet,
    AuthorizationState,
    VerifiedAuthority,
    AuthorityValidationResult,
    AuthorityBoundEvaluation,
    AuthorityApplicabilityResult,
)


def _policy_bundle_digest():
    return Sha256Digest.from_hex("ab" * 32)


def _domain_request():
    return AuthorizationRequest(
        Subject("agent:7"),
        Action("message.send"),
        Resource("room:general"),
        RequestContext(),
        AuthorityContext("grant:1"),
    )


def _request_digest():
    return sha256_digest(_domain_request())


def _verified_authority():
    grant = AuthorityGrant(
        "grant:1",
        Principal("issuer:root"),
        Principal("agent:7"),
        AuthorityScope(Action("message.send"), Resource("room:general")),
        None,
        0,
        100,
    )
    return validate_authority(
        DelegationChain((grant,)),
        AuthorizationState(50, RevocationSet()),
    ).verified_authority


def _applicability():
    return check_authority_applicability(
        _domain_request(),
        _verified_authority(),
    )


def _holder_binding():
    return check_subject_authority_binding(
        _domain_request(),
        SubjectPrincipalBinding(Subject("agent:7"), Principal("agent:7")),
        _verified_authority(),
    )


def _matched_rule_evaluation(effect=RuleEffect.PERMIT):
    return RuleEvaluation(
        "policy:1",
        "rule:1",
        effect,
        RuleEvaluationStatus.MATCHED,
        (("subject_matches", ConditionStatus.SATISFIED),),
    )


class DomainInvariantTests(unittest.TestCase):
    def test_identifiers_must_not_be_blank(self):
        for factory in (Subject, Resource, AuthorityContext):
            for value in ("", " ", "\t\n"):
                with self.subTest(factory=factory.__name__, value=value):
                    with self.assertRaisesRegex(ValueError, "must not be blank"):
                        factory(value)

    def test_action_name_must_not_be_blank(self):
        for value in ("", " ", "\t\n"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "must not be blank"):
                    Action(value)

    def test_request_can_represent_absent_authority_context_without_authentication(self):
        request = AuthorizationRequest(
            subject=Subject("agent:7"),
            action=Action("message.send"),
            resource=Resource("room:general"),
            context=RequestContext(),
            authority_context=None,
        )

        self.assertIsNone(request.authority_context)
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
            ("authority_context", "grant:1"),
        )
        for field_name, bad_value in invalid_values:
            values = {
                "subject": Subject("agent:7"),
                "action": Action("message.send"),
                "resource": Resource("room:general"),
                "context": RequestContext(),
                "authority_context": AuthorityContext("grant:1"),
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

    def test_rule_evaluation_status_is_exhaustive(self):
        self.assertEqual(
            tuple(RuleEvaluationStatus),
            (
                RuleEvaluationStatus.MATCHED,
                RuleEvaluationStatus.NOT_MATCHED,
                RuleEvaluationStatus.INDETERMINATE,
            ),
        )

    def test_reason_and_instruction_codes_must_not_be_blank(self):
        for factory in (Reason, Obligation):
            with self.subTest(factory=factory.__name__):
                with self.assertRaisesRegex(ValueError, "must not be blank"):
                    factory(" ")
        with self.assertRaisesRegex(ValueError, "must not be blank"):
            ApprovalRequirement(
                " ",
                (Principal("principal:approver"),),
            )

    def test_evidence_requires_a_typed_policy_bundle_digest(self):
        with self.assertRaisesRegex(TypeError, "Sha256Digest"):
            DecisionEvidence("sha256:" + "ab" * 32, _request_digest())

    def test_rule_evaluation_results_are_typed_unique_and_canonical(self):
        evaluation = RuleEvaluation(
            "policy:1",
            "rule:1",
            RuleEffect.PERMIT,
            RuleEvaluationStatus.MATCHED,
            (
                ("scope", ConditionStatus.SATISFIED),
                ("active", ConditionStatus.SATISFIED),
            ),
        )
        self.assertEqual(
            evaluation.condition_results,
            (
                ("active", ConditionStatus.SATISFIED),
                ("scope", ConditionStatus.SATISFIED),
            ),
        )

        with self.assertRaisesRegex(TypeError, "ConditionStatus"):
            RuleEvaluation(
                "policy:1",
                "rule:1",
                RuleEffect.PERMIT,
                RuleEvaluationStatus.MATCHED,
                (("scope", True),),
            )
        with self.assertRaisesRegex(ValueError, "duplicate name"):
            RuleEvaluation(
                "policy:1",
                "rule:1",
                RuleEffect.PERMIT,
                RuleEvaluationStatus.NOT_MATCHED,
                (
                    ("scope", ConditionStatus.SATISFIED),
                    ("scope", ConditionStatus.UNSATISFIED),
                ),
            )

        with self.assertRaisesRegex(ValueError, "does not match"):
            RuleEvaluation(
                "policy:1",
                "rule:1",
                RuleEffect.PERMIT,
                RuleEvaluationStatus.MATCHED,
                (("scope", ConditionStatus.UNSATISFIED),),
            )
        with self.assertRaisesRegex(ValueError, "NOT_EVALUATED"):
            RuleEvaluation(
                "policy:1",
                "rule:1",
                RuleEffect.PERMIT,
                RuleEvaluationStatus.NOT_MATCHED,
                (("scope", ConditionStatus.NOT_EVALUATED),),
            )

    def test_default_deny_can_record_that_nothing_matched(self):
        decision = Decision(
            outcome=Outcome.DENY,
            reasons=(Reason("NO_MATCHING_AUTHORITY"),),
            evidence=DecisionEvidence(
                _policy_bundle_digest(),
                _request_digest(),
            ),
        )

        self.assertEqual(decision.evidence.matched_policy_ids, ())
        self.assertEqual(decision.evidence.matched_rule_ids, ())
        self.assertIsNone(decision.evidence.authority_applicability)

    def test_non_deny_requires_matched_policy_and_authority(self):
        for outcome in (Outcome.PERMIT, Outcome.APPROVAL_REQUIRED):
            approvals = (
                (
                    ApprovalRequirement(
                        "OWNER_APPROVAL",
                        (Principal("principal:owner-approver"),),
                    ),
                )
                if outcome is Outcome.APPROVAL_REQUIRED
                else ()
            )

            with self.subTest(outcome=outcome, missing="rule"):
                with self.assertRaisesRegex(ValueError, "matched rule"):
                    Decision(
                        outcome=outcome,
                        reasons=(Reason("RULE_MATCHED"),),
                        evidence=DecisionEvidence(
                            _policy_bundle_digest(),
                            _request_digest(),
                            authority_applicability=_applicability(),
                            subject_authority_binding=_holder_binding(),
                        ),
                        approval_requirements=approvals,
                    )

            with self.subTest(outcome=outcome, missing="authority"):
                with self.assertRaisesRegex(
                    ValueError,
                    "applicable validated authority",
                ):
                    Decision(
                        outcome=outcome,
                        reasons=(Reason("RULE_MATCHED"),),
                        evidence=DecisionEvidence(
                            _policy_bundle_digest(),
                            _request_digest(),
                            (_matched_rule_evaluation(),),
                            subject_authority_binding=_holder_binding(),
                        ),
                        approval_requirements=approvals,
                    )

    def test_approval_requirement_matches_outcome_exactly(self):
        evidence = DecisionEvidence(
            _policy_bundle_digest(),
            _request_digest(),
            (_matched_rule_evaluation(),),
            _applicability(),
            _holder_binding(),
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
                approval_requirements=(
                    ApprovalRequirement(
                        "OWNER_APPROVAL",
                        (Principal("principal:owner-approver"),),
                    ),
                ),
            )

    def test_decision_approval_requirements_are_nonempty_canonical_and_copied(self):
        owner = ApprovalRequirement(
            "OWNER_APPROVAL",
            (Principal("principal:owner-approver"),),
        )
        security = ApprovalRequirement(
            "SECURITY_APPROVAL",
            (Principal("principal:security-approver"),),
        )
        requirements = [security, owner]
        evidence = DecisionEvidence(
            _policy_bundle_digest(),
            _request_digest(),
            (_matched_rule_evaluation(RuleEffect.APPROVAL_REQUIRED),),
            _applicability(),
            _holder_binding(),
        )

        decision = Decision(
            Outcome.APPROVAL_REQUIRED,
            (Reason("APPROVAL_REQUIRED"),),
            evidence,
            approval_requirements=requirements,
        )
        requirements.append(
            ApprovalRequirement(
                "LATER_MUTATION",
                (Principal("principal:later-approver"),),
            )
        )

        self.assertEqual(decision.approval_requirements, (owner, security))

        with self.assertRaisesRegex(ValueError, "duplicates"):
            Decision(
                Outcome.APPROVAL_REQUIRED,
                (Reason("APPROVAL_REQUIRED"),),
                evidence,
                approval_requirements=(owner, owner),
            )

    def test_decision_requires_reason_and_typed_outcome(self):
        evidence = DecisionEvidence(_policy_bundle_digest(), _request_digest())

        with self.assertRaisesRegex(ValueError, "at least one reason"):
            Decision(Outcome.DENY, (), evidence)
        with self.assertRaisesRegex(TypeError, "Outcome"):
            Decision("DENY", (Reason("NO_MATCH"),), evidence)

    def test_decision_copies_reason_and_obligation_iterables(self):
        reasons = [Reason("ALLOWED")]
        obligations = [Obligation("AUDIT")]
        evidence = DecisionEvidence(
            _policy_bundle_digest(),
            _request_digest(),
            (_matched_rule_evaluation(),),
            _applicability(),
            _holder_binding(),
        )
        decision = Decision(Outcome.PERMIT, reasons, evidence, obligations)
        reasons.append(Reason("LATER_MUTATION"))
        obligations.append(Obligation("LATER_MUTATION"))

        self.assertEqual(decision.reasons, (Reason("ALLOWED"),))
        self.assertEqual(decision.obligations, (Obligation("AUDIT"),))


if __name__ == "__main__":
    unittest.main()
