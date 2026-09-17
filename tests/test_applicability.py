import ast
import importlib
import inspect
import os
import subprocess
import sys
import unittest

from nest_authz import (
    Action,
    ApprovalRequirement,
    AuthorityContext,
    AuthorityApplicabilityStatus,
    AuthorityGrant,
    AuthorityScope,
    AuthorizationRequest,
    AuthorizationState,
    Condition,
    ConditionOperator,
    DecisionEvidence,
    DelegationChain,
    FieldNamespace,
    FieldReference,
    Outcome,
    Policy,
    PolicyBundle,
    Principal,
    RequestContext,
    Resource,
    Rule,
    RuleEffect,
    Subject,
    SubjectPrincipalBinding,
    canonical_bytes,
    check_authority_applicability,
    evaluate as _evaluate_with_binding,
    sha256_digest,
    validate_authority,
)


def _validated_authority(
    *,
    action="payments.transfer",
    resource="account:alice",
    bounds=(("amount", 1000),),
):
    root = AuthorityGrant(
        "grant:root",
        Principal("issuer:root"),
        Principal("principal:alice"),
        AuthorityScope(Action(action), Resource(resource), bounds),
        None,
        0,
        100,
    )
    leaf = AuthorityGrant(
        "grant:leaf",
        Principal("principal:alice"),
        Principal("agent:7"),
        AuthorityScope(Action(action), Resource(resource), bounds),
        root.identifier,
        10,
        90,
    )
    result = validate_authority(
        DelegationChain((root, leaf)),
        AuthorizationState(50),
    )
    return result.verified_authority


def _request(
    *,
    action="payments.transfer",
    resource="account:alice",
    context=(("amount", 1000),),
):
    return AuthorizationRequest(
        Subject("agent:7"),
        Action(action),
        Resource(resource),
        RequestContext(context),
        AuthorityContext("opaque:request-authority"),
    )


def _binding():
    return SubjectPrincipalBinding(
        Subject("agent:7"),
        Principal("agent:7"),
    )


def evaluate(request, bundle, authority):
    return _evaluate_with_binding(request, bundle, authority, _binding())


def _bundle(effect=RuleEffect.PERMIT):
    condition = Condition(
        "subject_is_agent_7",
        FieldReference(FieldNamespace.SUBJECT, "identifier"),
        ConditionOperator.EQUALS,
        "agent:7",
    )
    approvals = (
        (ApprovalRequirement("OWNER_APPROVAL"),)
        if effect is RuleEffect.APPROVAL_REQUIRED
        else ()
    )
    rule = Rule(
        "rule:matching",
        effect,
        (condition,),
        approval_requirements=approvals,
    )
    return PolicyBundle((Policy("policy:authority-integration", (rule,)),))


class AuthorityApplicabilityTests(unittest.TestCase):
    def test_applicability_status_is_closed_and_explicit(self):
        self.assertEqual(
            tuple(AuthorityApplicabilityStatus),
            (
                AuthorityApplicabilityStatus.APPLICABLE,
                AuthorityApplicabilityStatus.ACTION_MISMATCH,
                AuthorityApplicabilityStatus.RESOURCE_MISMATCH,
                AuthorityApplicabilityStatus.MISSING_CONTEXT,
                AuthorityApplicabilityStatus.BOUND_EXCEEDED,
                AuthorityApplicabilityStatus.TYPE_ERROR,
            ),
        )

    def test_valid_authority_and_in_scope_request_can_permit(self):
        request = _request()
        authority = _validated_authority()

        decision = evaluate(request, _bundle(), authority)

        self.assertIs(decision.outcome, Outcome.PERMIT)
        self.assertIs(
            decision.evidence.authority_applicability.status,
            AuthorityApplicabilityStatus.APPLICABLE,
        )

    def test_action_mismatch_is_denied_despite_permit_policy(self):
        request = _request(action="payments.refund")
        authority = _validated_authority()

        decision = evaluate(request, _bundle(), authority)

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertIs(
            decision.evidence.authority_applicability.status,
            AuthorityApplicabilityStatus.ACTION_MISMATCH,
        )
        self.assertEqual(decision.reasons[0].code, "AUTHORITY_ACTION_MISMATCH")

    def test_resource_mismatch_is_denied_despite_permit_policy(self):
        request = _request(resource="account:bob")
        decision = evaluate(request, _bundle(), _validated_authority())

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertIs(
            decision.evidence.authority_applicability.status,
            AuthorityApplicabilityStatus.RESOURCE_MISMATCH,
        )

    def test_value_equal_to_upper_bound_is_applicable(self):
        result = check_authority_applicability(
            _request(context=(("amount", 1000),)),
            _validated_authority(),
        )

        self.assertIs(result.status, AuthorityApplicabilityStatus.APPLICABLE)
        self.assertEqual(result.bound_evaluations[0].supplied_value, 1000)
        self.assertIs(
            result.bound_evaluations[0].status,
            AuthorityApplicabilityStatus.APPLICABLE,
        )

    def test_value_above_upper_bound_is_bound_exceeded(self):
        result = check_authority_applicability(
            _request(context=(("amount", 1001),)),
            _validated_authority(),
        )

        self.assertIs(
            result.status,
            AuthorityApplicabilityStatus.BOUND_EXCEEDED,
        )
        self.assertEqual(result.bound_evaluations[0].upper_bound, 1000)
        self.assertEqual(result.bound_evaluations[0].supplied_value, 1001)

    def test_missing_bounded_context_is_explicit(self):
        result = check_authority_applicability(
            _request(context=()),
            _validated_authority(),
        )

        self.assertIs(result.status, AuthorityApplicabilityStatus.MISSING_CONTEXT)
        self.assertFalse(result.bound_evaluations[0].present)
        self.assertIsNone(result.bound_evaluations[0].supplied_value)

    def test_bool_is_not_an_integer_bound_value(self):
        result = check_authority_applicability(
            _request(context=(("amount", True),)),
            _validated_authority(),
        )

        self.assertIs(result.status, AuthorityApplicabilityStatus.TYPE_ERROR)
        self.assertIs(result.bound_evaluations[0].supplied_value, True)

    def test_string_is_not_an_integer_bound_value(self):
        result = check_authority_applicability(
            _request(context=(("amount", "1000"),)),
            _validated_authority(),
        )

        self.assertIs(result.status, AuthorityApplicabilityStatus.TYPE_ERROR)

    def test_permit_policy_cannot_override_bound_exceeded(self):
        request = _request(context=(("amount", 5000),))

        decision = evaluate(request, _bundle(), _validated_authority())

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(decision.reasons[0].code, "AUTHORITY_BOUND_EXCEEDED")
        self.assertEqual(
            decision.evidence.matched_rule_ids,
            (("policy:authority-integration", "rule:matching"),),
        )

    def test_approval_policy_cannot_override_out_of_scope_authority(self):
        request = _request(context=(("amount", 5000),))

        decision = evaluate(
            request,
            _bundle(RuleEffect.APPROVAL_REQUIRED),
            _validated_authority(),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(decision.approval_requirements, ())
        self.assertIs(
            decision.evidence.authority_applicability.status,
            AuthorityApplicabilityStatus.BOUND_EXCEEDED,
        )

    def test_deny_policy_remains_deny_with_applicable_authority(self):
        decision = evaluate(
            _request(),
            _bundle(RuleEffect.DENY),
            _validated_authority(),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(decision.reasons[0].code, "DENY_RULE_MATCHED")

    def test_unconstrained_context_fields_do_not_change_applicability(self):
        authority = _validated_authority()
        minimal = check_authority_applicability(_request(), authority)
        additional = check_authority_applicability(
            _request(context=(("amount", 1000), ("memo", "invoice:7"))),
            authority,
        )

        self.assertIs(minimal.status, AuthorityApplicabilityStatus.APPLICABLE)
        self.assertIs(additional.status, AuthorityApplicabilityStatus.APPLICABLE)
        self.assertEqual(minimal.bound_evaluations, additional.bound_evaluations)
        self.assertNotEqual(minimal.request_digest, additional.request_digest)

    def test_repeated_applicability_evaluation_is_equal(self):
        request = _request()
        authority = _validated_authority()

        first = check_authority_applicability(request, authority)
        second = check_authority_applicability(request, authority)

        self.assertEqual(first, second)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(sha256_digest(first), sha256_digest(second))

    def test_different_python_hash_seeds_do_not_change_result(self):
        script = "\n".join(
            (
                "from nest_authz import *",
                "scope = AuthorityScope(Action('payments.transfer'), Resource('account:alice'), {'z_limit': 9, 'amount': 1000})",
                "grant = AuthorityGrant('grant:leaf', Principal('issuer:root'), Principal('agent:7'), scope, None, 0, 100)",
                "authority = validate_authority(DelegationChain((grant,)), AuthorizationState(50)).verified_authority",
                "request = AuthorizationRequest(Subject('agent:7'), Action('payments.transfer'), Resource('account:alice'), RequestContext({'amount': 1000, 'z_limit': 9}), AuthorityContext('opaque'))",
                "result = check_authority_applicability(request, authority)",
                "print(result.status.value)",
                "print(canonical_bytes(result).hex())",
                "print(str(sha256_digest(result)))",
            )
        )
        outputs = []
        for seed in ("3", "271828"):
            environment = os.environ.copy()
            environment["PYTHONHASHSEED"] = seed
            completed = subprocess.run(
                [sys.executable, "-c", script],
                check=True,
                capture_output=True,
                text=True,
                env=environment,
            )
            outputs.append(completed.stdout)

        self.assertEqual(outputs[0], outputs[1])
        self.assertTrue(outputs[0].startswith("APPLICABLE\n"))

    def test_applicability_evidence_identifies_effective_leaf_grant(self):
        authority = _validated_authority()
        result = check_authority_applicability(_request(), authority)

        self.assertEqual(result.effective_grant_id, "grant:leaf")
        self.assertEqual(result.chain_digest, authority.chain_digest)
        self.assertEqual(result.state_digest, authority.state_digest)
        self.assertEqual(result.authority_digest, sha256_digest(authority))

    def test_request_digest_changes_with_action(self):
        self.assertNotEqual(
            sha256_digest(_request(action="payments.transfer")),
            sha256_digest(_request(action="payments.refund")),
        )

    def test_request_digest_changes_with_resource(self):
        self.assertNotEqual(
            sha256_digest(_request(resource="account:alice")),
            sha256_digest(_request(resource="account:bob")),
        )

    def test_request_digest_changes_with_constrained_context(self):
        self.assertNotEqual(
            sha256_digest(_request(context=(("amount", 1000),))),
            sha256_digest(_request(context=(("amount", 1001),))),
        )

    def test_decision_evidence_is_bound_to_exact_request_digest(self):
        request = _request()
        decision = evaluate(request, _bundle(), _validated_authority())

        self.assertEqual(decision.evidence.request_digest, sha256_digest(request))
        self.assertEqual(
            decision.evidence.authority_applicability.request_digest,
            sha256_digest(request),
        )
        self.assertEqual(
            decision.evidence.authority_chain_digest,
            decision.evidence.authority_applicability.chain_digest,
        )

    def test_decision_evidence_rejects_applicability_for_another_request(self):
        request = _request()
        applicability = check_authority_applicability(
            request,
            _validated_authority(),
        )
        different_request = _request(context=(("amount", 999),))

        with self.assertRaisesRegex(ValueError, "bind the evidence request"):
            DecisionEvidence(
                sha256_digest(_bundle()),
                sha256_digest(different_request),
                authority_applicability=applicability,
            )

    def test_every_bound_is_evaluated_despite_other_failures(self):
        authority = _validated_authority(
            bounds=(("amount", 1000), ("daily_count", 5)),
        )
        request = _request(
            action="payments.refund",
            context=(("amount", 5000),),
        )

        result = check_authority_applicability(request, authority)

        self.assertIs(
            result.status,
            AuthorityApplicabilityStatus.ACTION_MISMATCH,
        )
        self.assertEqual(len(result.bound_evaluations), 2)
        self.assertEqual(
            tuple(item.status for item in result.bound_evaluations),
            (
                AuthorityApplicabilityStatus.BOUND_EXCEEDED,
                AuthorityApplicabilityStatus.MISSING_CONTEXT,
            ),
        )

    def test_authority_context_alone_cannot_permit(self):
        decision = evaluate(_request(), _bundle(), None)

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(
            decision.reasons[0].code,
            "VALIDATED_AUTHORITY_REQUIRED",
        )

    def test_new_records_have_explicit_canonical_schemas(self):
        result = check_authority_applicability(
            _request(),
            _validated_authority(),
        )
        encoded = canonical_bytes(result)

        self.assertIn(b"nest-authz/authority-applicability-result@1", encoded)
        self.assertIn(b"nest-authz/authority-applicability-status@1", encoded)
        self.assertIn(b"nest-authz/authority-bound-evaluation@1", encoded)

        decision = evaluate(_request(), _bundle(), _validated_authority())
        decision_bytes = canonical_bytes(decision)
        self.assertIn(b"nest-authz/decision-evidence@5", decision_bytes)
        self.assertIn(b"nest-authz/decision@4", decision_bytes)

    def test_applicability_and_evaluator_read_no_external_state(self):
        prohibited_import_roots = {
            "datetime",
            "os",
            "pathlib",
            "random",
            "secrets",
            "socket",
            "subprocess",
            "time",
            "urllib",
            "uuid",
        }
        for module_name in ("nest_authz.applicability", "nest_authz.evaluator"):
            with self.subTest(module=module_name):
                module = importlib.import_module(module_name)
                tree = ast.parse(inspect.getsource(module))
                imported_roots = set()
                names = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported_roots.update(
                            alias.name.split(".", maxsplit=1)[0]
                            for alias in node.names
                        )
                    elif isinstance(node, ast.ImportFrom) and node.level == 0:
                        imported_roots.add(
                            (node.module or "").split(".", maxsplit=1)[0]
                        )
                    elif isinstance(node, ast.Name):
                        names.add(node.id)

                self.assertTrue(
                    prohibited_import_roots.isdisjoint(imported_roots)
                )
                self.assertNotIn("open", names)


if __name__ == "__main__":
    unittest.main()
