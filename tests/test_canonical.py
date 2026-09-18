import os
import subprocess
import sys
import unittest
from hashlib import sha256

from nest_authz import (
    Action,
    ApprovalRequirement,
    ApprovalRequirementStatus,
    ApprovalStatus,
    ApproverAuthorizationStatus,
    ApproverSubjectPrincipalBinding,
    AuthorityApplicabilityStatus,
    AuthorityBoundEvaluation,
    AuthorityContext,
    AuthorityGrant,
    AuthorityScope,
    AuthorityValidationStatus,
    AuthorizationRequest,
    AuthorizationState,
    Condition,
    ConditionOperator,
    ConditionStatus,
    Decision,
    DecisionEvidence,
    DelegationChain,
    ExecutionAuthorizationStatus,
    FieldNamespace,
    FieldReference,
    Obligation,
    Outcome,
    Policy,
    PolicyBundle,
    Principal,
    Reason,
    RequestContext,
    Resource,
    RevocationSet,
    Rule,
    RuleEffect,
    RuleEvaluation,
    RuleEvaluationStatus,
    Sha256Digest,
    Subject,
    SubjectAuthorityBindingStatus,
    SubjectPrincipalBinding,
    approve_requirement,
    canonical_bytes,
    check_approver_authorization,
    check_authority_applicability,
    check_subject_authority_binding,
    create_decision_receipt,
    create_pending_approval,
    evaluate,
    revalidate_for_execution,
    sha256_digest,
    validate_authority,
)

_SUBJECT_CANONICAL_HEX = (
    "4e4553542d415554485a2d43414e4f4e4943414c0001520000000000000049"
    "5300000000000000146e6573742d617574687a2f7375626a65637440314d00"
    "0000000000002353000000000000000a6964656e7469666965725300000000"
    "000000076167656e743a37"
)
_SUBJECT_DIGEST_HEX = "5a804e74f9c21b92ff085deb96b1a338ab56c67c019b7c14e5bd1fd6fe330495"


def _policy_bundle_digest():
    return Sha256Digest.from_hex("ab" * 32)


def _sample_request(authority=None):
    return AuthorizationRequest(
        Subject("agent:7"),
        Action("message.send"),
        Resource("room:general"),
        RequestContext(),
        authority,
    )


def _validated_authority(request):
    grant = AuthorityGrant(
        "grant:validated",
        Principal("issuer:root"),
        Principal("agent:7"),
        AuthorityScope(request.action, request.resource),
        None,
        0,
        100,
    )
    validated = validate_authority(
        DelegationChain((grant,)),
        AuthorizationState(50),
    ).verified_authority
    return validated


def _applicability(request):
    return check_authority_applicability(
        request,
        _validated_authority(request),
    )


def _holder_binding(request):
    return check_subject_authority_binding(
        request,
        SubjectPrincipalBinding(request.subject, Principal("agent:7")),
        _validated_authority(request),
    )


def _execution_result():
    request = AuthorizationRequest(
        Subject("agent:7"),
        Action("message.send"),
        Resource("room:general"),
        RequestContext(),
        None,
    )
    approver = Principal("principal:owner-approver")
    requirement = ApprovalRequirement("OWNER_APPROVAL", (approver,))
    bundle = PolicyBundle(
        (
            Policy(
                "policy:approval",
                (
                    Rule(
                        "rule:approval",
                        RuleEffect.APPROVAL_REQUIRED,
                        (
                            Condition(
                                "action_matches",
                                FieldReference(FieldNamespace.ACTION, "name"),
                                ConditionOperator.EQUALS,
                                "message.send",
                            ),
                        ),
                        approval_requirements=(requirement,),
                    ),
                ),
            ),
        )
    )
    chain = DelegationChain(
        (
            AuthorityGrant(
                "grant:approval",
                Principal("issuer:root"),
                Principal("agent:7"),
                AuthorityScope(request.action, request.resource),
                None,
                0,
                100,
            ),
        )
    )
    state = AuthorizationState(50)
    authority = validate_authority(chain, state).verified_authority
    holder = SubjectPrincipalBinding(request.subject, Principal("agent:7"))
    receipt = create_decision_receipt(evaluate(request, bundle, authority, holder))
    pending = create_pending_approval(receipt, 50)
    actor = Subject("approver:owner")
    approver_binding = ApproverSubjectPrincipalBinding(actor, approver)
    authorization = check_approver_authorization(
        actor,
        approver_binding,
        requirement,
        requirement,
    )
    approved = approve_requirement(
        pending,
        requirement,
        authorization,
        51,
    )
    return (
        revalidate_for_execution(
            receipt,
            approved,
            request,
            bundle,
            chain,
            state,
            holder,
        ),
        approver_binding,
        authorization,
    )


class CanonicalEncodingTests(unittest.TestCase):
    def test_mapping_insertion_order_does_not_change_canonical_bytes(self):
        left = RequestContext({"zone": "north", "attempt": 2})
        right = RequestContext({"attempt": 2, "zone": "north"})

        self.assertEqual(canonical_bytes(left), canonical_bytes(right))

    def test_mapping_insertion_order_does_not_change_digest(self):
        left = AuthorityContext("grant:1", {"scope": "read", "active": True})
        right = AuthorityContext("grant:1", {"active": True, "scope": "read"})

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
            authority_context=AuthorityContext("grant:1", {"active": True}),
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
            authority_context=AuthorityContext("grant:1", authority_input),
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
        rule_evaluation = RuleEvaluation(
            "policy:1",
            "rule:1",
            RuleEffect.PERMIT,
            RuleEvaluationStatus.MATCHED,
            (("condition:1", ConditionStatus.SATISFIED),),
        )
        evidence = DecisionEvidence(
            _policy_bundle_digest(),
            sha256_digest(_sample_request(AuthorityContext("grant:1"))),
            (rule_evaluation,),
            _applicability(_sample_request(AuthorityContext("grant:1"))),
            _holder_binding(_sample_request(AuthorityContext("grant:1"))),
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
                sha256_digest(_sample_request()),
                (
                    RuleEvaluation(
                        "policy:1",
                        "rule:1",
                        RuleEffect.PERMIT,
                        RuleEvaluationStatus.INDETERMINATE,
                        (("has_context", ConditionStatus.MISSING_INPUT),),
                    ),
                ),
            )
        )

        self.assertIn(b"nest-authz/sha256-digest@1", digest_bytes)
        self.assertIn(b"nest-authz/condition-status@1", status_bytes)
        self.assertIn(b"nest-authz/decision-evidence@5", evidence_bytes)
        self.assertIn(b"nest-authz/rule-evaluation-status@1", evidence_bytes)
        self.assertIn(b"nest-authz/rule-evaluation@1", evidence_bytes)
        self.assertIn(b"policy_bundle_digest", evidence_bytes)
        self.assertIn(b"request_digest", evidence_bytes)
        self.assertIn(b"authority_applicability", evidence_bytes)

        decision_bytes = canonical_bytes(
            Decision(
                Outcome.DENY,
                (Reason("INDETERMINATE_RULE"),),
                DecisionEvidence(
                    _policy_bundle_digest(),
                    sha256_digest(_sample_request()),
                    (
                        RuleEvaluation(
                            "policy:1",
                            "rule:1",
                            RuleEffect.PERMIT,
                            RuleEvaluationStatus.INDETERMINATE,
                            (("has_context", ConditionStatus.MISSING_INPUT),),
                        ),
                    ),
                ),
            )
        )
        self.assertIn(b"nest-authz/decision@5", decision_bytes)
        self.assertIn(b"approval_requirements", decision_bytes)

        grant = AuthorityGrant(
            "grant:root",
            Principal("issuer:root"),
            Principal("agent:7"),
            AuthorityScope(
                Action("message.send"),
                Resource("room:general"),
                (("max_messages", 10),),
            ),
            None,
            0,
            100,
        )
        chain = DelegationChain((grant,))
        state = AuthorizationState(50, RevocationSet())
        validation = validate_authority(chain, state)
        validation_bytes = canonical_bytes(validation)

        self.assertIn(b"nest-authz/authority-validation-result@1", validation_bytes)
        self.assertIn(b"nest-authz/authority-validation-status@1", validation_bytes)
        self.assertIn(b"nest-authz/verified-authority@1", validation_bytes)

    def test_every_public_domain_type_is_supported(self):
        authority = AuthorityContext("grant:1", {"active": True})
        field_reference = FieldReference(FieldNamespace.CONTEXT, "risk_level")
        policy_condition = Condition(
            "risk_is_low",
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
        rule_evaluation = RuleEvaluation(
            "policy:1",
            "rule:1",
            RuleEffect.PERMIT,
            RuleEvaluationStatus.MATCHED,
            (("risk_is_low", ConditionStatus.SATISFIED),),
        )
        evidence = DecisionEvidence(
            _policy_bundle_digest(),
            sha256_digest(_sample_request(authority)),
            (rule_evaluation,),
            _applicability(_sample_request(authority)),
            _holder_binding(_sample_request(authority)),
        )
        grant = AuthorityGrant(
            "grant:root",
            Principal("issuer:root"),
            Principal("agent:7"),
            AuthorityScope(
                Action("message.send"),
                Resource("room:general"),
                (("max_messages", 10),),
            ),
            None,
            0,
            100,
        )
        chain = DelegationChain((grant,))
        revocations = RevocationSet()
        state = AuthorizationState(50, revocations)
        validation = validate_authority(chain, state)
        self.assertIs(validation.status, AuthorityValidationStatus.VALID)
        applicability = _applicability(_sample_request(authority))
        bound_evaluation = AuthorityBoundEvaluation(
            "max_messages",
            10,
            True,
            5,
            AuthorityApplicabilityStatus.APPLICABLE,
        )
        approval_requirement = ApprovalRequirement(
            "OWNER_APPROVAL",
            (Principal("principal:owner-approver"),),
        )
        approval_rule_evaluation = RuleEvaluation(
            "policy:1",
            "rule:1",
            RuleEffect.APPROVAL_REQUIRED,
            RuleEvaluationStatus.MATCHED,
            (("risk_is_low", ConditionStatus.SATISFIED),),
        )
        approval_evidence = DecisionEvidence(
            _policy_bundle_digest(),
            sha256_digest(_sample_request(authority)),
            (approval_rule_evaluation,),
            applicability,
            _holder_binding(_sample_request(authority)),
        )
        approval_decision = Decision(
            Outcome.APPROVAL_REQUIRED,
            (Reason("APPROVAL_NEEDED"),),
            approval_evidence,
            approval_requirements=(approval_requirement,),
        )
        receipt = create_decision_receipt(approval_decision)
        pending_approval = create_pending_approval(receipt, 50)
        execution_result, approver_binding, approver_authorization = _execution_result()
        self.assertIs(
            execution_result.status,
            ExecutionAuthorizationStatus.AUTHORIZED,
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
            RuleEvaluationStatus.MATCHED,
            policy_rule,
            policy,
            policy_bundle,
            rule_evaluation,
            Reason("ALLOWED"),
            Obligation("AUDIT"),
            ApprovalRequirement(
                "OWNER_APPROVAL",
                (Principal("principal:owner-approver"),),
            ),
            ApprovalRequirementStatus.PENDING,
            ApprovalStatus.PENDING,
            approver_binding,
            ApproverAuthorizationStatus.AUTHORIZED,
            approver_authorization,
            pending_approval.requirement_states[0],
            evidence,
            Decision(
                Outcome.PERMIT,
                (Reason("ALLOWED"),),
                evidence,
                (Obligation("AUDIT"),),
            ),
            receipt,
            pending_approval,
            grant.grantor,
            grant.scope,
            grant,
            chain,
            revocations,
            state,
            AuthorityValidationStatus.VALID,
            validation.verified_authority,
            validation,
            AuthorityApplicabilityStatus.APPLICABLE,
            bound_evaluation,
            applicability,
            SubjectPrincipalBinding(Subject("agent:7"), Principal("agent:7")),
            SubjectAuthorityBindingStatus.BOUND,
            _holder_binding(_sample_request(authority)),
            ExecutionAuthorizationStatus.AUTHORIZED,
            execution_result.execution_permit,
            execution_result,
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
