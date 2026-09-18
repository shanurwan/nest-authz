import ast
import importlib
import inspect
import os
import subprocess
import sys
import unittest

import nest_authz
from nest_authz import (
    Action,
    ApprovalRequirement,
    AuthorityContext,
    AuthorityGrant,
    AuthorityScope,
    AuthorizationRequest,
    AuthorizationState,
    Condition,
    ConditionOperator,
    Decision,
    DecisionEvidence,
    DelegationChain,
    FieldNamespace,
    FieldReference,
    Outcome,
    Policy,
    PolicyBundle,
    Principal,
    Reason,
    RequestContext,
    Resource,
    Rule,
    RuleEffect,
    Subject,
    SubjectAuthorityBindingStatus,
    SubjectPrincipalBinding,
    canonical_bytes,
    check_subject_authority_binding,
    evaluate,
    sha256_digest,
    validate_authority,
)


def _authority():
    grant = AuthorityGrant(
        "grant:alice",
        Principal("issuer:root"),
        Principal("principal:alice"),
        AuthorityScope(
            Action("payments.transfer"),
            Resource("account:alice"),
            (("amount", 1000),),
        ),
        None,
        0,
        100,
    )
    return validate_authority(
        DelegationChain((grant,)),
        AuthorizationState(50),
    ).verified_authority


def _request(subject="agent:alice", amount=500):
    return AuthorizationRequest(
        Subject(subject),
        Action("payments.transfer"),
        Resource("account:alice"),
        RequestContext((("amount", amount),)),
        AuthorityContext("identity-adapter", (("assurance", "external"),)),
    )


def _binding(subject="agent:alice", principal="principal:alice"):
    return SubjectPrincipalBinding(Subject(subject), Principal(principal))


def _bundle(effect=RuleEffect.PERMIT):
    condition = Condition(
        "transfer_action",
        FieldReference(FieldNamespace.ACTION, "name"),
        ConditionOperator.EQUALS,
        "payments.transfer",
    )
    requirements = (
        (
            ApprovalRequirement(
                "OWNER_APPROVAL",
                (Principal("principal:owner-approver"),),
            ),
        )
        if effect is RuleEffect.APPROVAL_REQUIRED
        else ()
    )
    return PolicyBundle(
        (
            Policy(
                "policy:payments",
                (
                    Rule(
                        "rule:transfer",
                        effect,
                        (condition,),
                        approval_requirements=requirements,
                    ),
                ),
            ),
        )
    )


class SubjectAuthorityBindingTests(unittest.TestCase):
    def test_binding_status_is_closed_and_explicit(self):
        self.assertEqual(
            tuple(SubjectAuthorityBindingStatus),
            (
                SubjectAuthorityBindingStatus.BOUND,
                SubjectAuthorityBindingStatus.SUBJECT_MISMATCH,
                SubjectAuthorityBindingStatus.PRINCIPAL_MISMATCH,
            ),
        )

    def test_matching_subject_and_principal_are_bound(self):
        request = _request()
        authority = _authority()

        result = check_subject_authority_binding(
            request,
            _binding(),
            authority,
        )

        self.assertIs(result.status, SubjectAuthorityBindingStatus.BOUND)
        self.assertEqual(result.request_subject, request.subject)
        self.assertEqual(result.authority_principal, authority.principal)

    def test_different_request_subject_is_subject_mismatch(self):
        result = check_subject_authority_binding(
            _request("agent:mallory"),
            _binding("agent:alice", "principal:alice"),
            _authority(),
        )

        self.assertIs(
            result.status,
            SubjectAuthorityBindingStatus.SUBJECT_MISMATCH,
        )

    def test_different_authority_holder_is_principal_mismatch(self):
        result = check_subject_authority_binding(
            _request("agent:mallory"),
            _binding("agent:mallory", "principal:mallory"),
            _authority(),
        )

        self.assertIs(
            result.status,
            SubjectAuthorityBindingStatus.PRINCIPAL_MISMATCH,
        )

    def test_permit_cannot_override_subject_mismatch(self):
        request = _request("agent:mallory")
        decision = evaluate(
            request,
            _bundle(),
            _authority(),
            _binding("agent:alice", "principal:alice"),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(decision.reasons[0].code, "HOLDER_SUBJECT_MISMATCH")

    def test_permit_cannot_override_principal_mismatch(self):
        request = _request("agent:mallory")
        decision = evaluate(
            request,
            _bundle(),
            _authority(),
            _binding("agent:mallory", "principal:mallory"),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(decision.reasons[0].code, "HOLDER_PRINCIPAL_MISMATCH")

    def test_approval_required_cannot_override_failed_binding(self):
        decision = evaluate(
            _request("agent:mallory"),
            _bundle(RuleEffect.APPROVAL_REQUIRED),
            _authority(),
            _binding("agent:mallory", "principal:mallory"),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(decision.approval_requirements, ())

    def test_valid_binding_and_applicability_allow_permit(self):
        decision = evaluate(_request(), _bundle(), _authority(), _binding())

        self.assertIs(decision.outcome, Outcome.PERMIT)
        self.assertIs(
            decision.evidence.subject_authority_binding.status,
            SubjectAuthorityBindingStatus.BOUND,
        )

    def test_valid_binding_does_not_override_policy_deny(self):
        decision = evaluate(
            _request(),
            _bundle(RuleEffect.DENY),
            _authority(),
            _binding(),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(decision.reasons[0].code, "DENY_RULE_MATCHED")

    def test_missing_binding_fails_closed(self):
        decision = evaluate(_request(), _bundle(), _authority(), None)

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(
            decision.reasons[0].code,
            "SUBJECT_PRINCIPAL_BINDING_REQUIRED",
        )

    def test_similar_identifiers_do_not_create_an_implicit_binding(self):
        request = _request("principal:alice")
        binding = _binding("principal:alice", "principal:mallory")
        result = check_subject_authority_binding(
            request,
            binding,
            _authority(),
        )
        decision = evaluate(request, _bundle(), _authority(), binding)

        self.assertEqual(
            request.subject.identifier,
            _authority().principal.identifier,
        )
        self.assertIs(
            result.status,
            SubjectAuthorityBindingStatus.PRINCIPAL_MISMATCH,
        )
        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(decision.reasons[0].code, "HOLDER_PRINCIPAL_MISMATCH")

    def test_repeated_binding_checks_are_equal(self):
        request = _request()
        authority = _authority()
        binding = _binding()

        first = check_subject_authority_binding(request, binding, authority)
        second = check_subject_authority_binding(request, binding, authority)

        self.assertEqual(first, second)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(sha256_digest(first), sha256_digest(second))

    def test_python_hash_seed_does_not_change_result_or_bytes(self):
        script = "\n".join(
            (
                "from nest_authz import *",
                "request = AuthorizationRequest(Subject('agent:alice'), Action('payments.transfer'), Resource('account:alice'), RequestContext({'amount': 500}), AuthorityContext('identity-adapter'))",
                "grant = AuthorityGrant('grant:alice', Principal('issuer:root'), Principal('principal:alice'), AuthorityScope(Action('payments.transfer'), Resource('account:alice'), {'amount': 1000}), None, 0, 100)",
                "authority = validate_authority(DelegationChain((grant,)), AuthorizationState(50)).verified_authority",
                "binding = SubjectPrincipalBinding(Subject('agent:alice'), Principal('principal:alice'))",
                "result = check_subject_authority_binding(request, binding, authority)",
                "condition = Condition('transfer_action', FieldReference(FieldNamespace.ACTION, 'name'), ConditionOperator.EQUALS, 'payments.transfer')",
                "bundle = PolicyBundle((Policy('policy:payments', (Rule('rule:transfer', RuleEffect.PERMIT, (condition,)),)),))",
                "decision = evaluate(request, bundle, authority, binding)",
                "print(result.status.value)",
                "print(canonical_bytes(result).hex())",
                "print(decision.outcome.value)",
                "print(canonical_bytes(decision).hex())",
            )
        )
        outputs = []
        for seed in ("5", "424242"):
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
        self.assertTrue(outputs[0].startswith("BOUND\n"))

    def test_decision_evidence_contains_exact_binding_evidence(self):
        request = _request()
        authority = _authority()
        binding = _binding()
        expected = check_subject_authority_binding(request, binding, authority)

        decision = evaluate(request, _bundle(), authority, binding)

        self.assertEqual(decision.evidence.subject_authority_binding, expected)
        self.assertEqual(
            decision.evidence.subject_authority_binding.authority_digest,
            sha256_digest(authority),
        )
        self.assertEqual(
            decision.evidence.subject_authority_binding.effective_grant_id,
            authority.grant_id,
        )

    def test_binding_evidence_request_digest_is_exact(self):
        request = _request()
        result = check_subject_authority_binding(
            request,
            _binding(),
            _authority(),
        )

        self.assertEqual(result.request_digest, sha256_digest(request))

    def test_failed_binding_cannot_construct_non_deny_decision(self):
        request = _request("agent:mallory")
        authority = _authority()
        failed = check_subject_authority_binding(
            request,
            _binding("agent:mallory", "principal:mallory"),
            authority,
        )
        denied = evaluate(
            request,
            _bundle(),
            authority,
            _binding("agent:mallory", "principal:mallory"),
        )
        forged_evidence = DecisionEvidence(
            policy_bundle_digest=denied.evidence.policy_bundle_digest,
            request_digest=denied.evidence.request_digest,
            rule_evaluations=denied.evidence.rule_evaluations,
            authority_applicability=denied.evidence.authority_applicability,
            subject_authority_binding=failed,
        )

        with self.assertRaisesRegex(ValueError, "successful.*binding"):
            Decision(
                Outcome.PERMIT,
                (Reason("FORGED_PERMIT"),),
                forged_evidence,
            )

    def test_credential_substitution_regression_is_denied(self):
        request = _request("agent:mallory", amount=500)
        decision = evaluate(
            request,
            _bundle(RuleEffect.PERMIT),
            _authority(),
            _binding("agent:mallory", "principal:mallory"),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(decision.reasons[0].code, "HOLDER_PRINCIPAL_MISMATCH")
        self.assertEqual(
            decision.evidence.subject_authority_binding.authority_principal,
            Principal("principal:alice"),
        )

    def test_new_records_and_renamed_context_have_versioned_schemas(self):
        request = _request()
        result = check_subject_authority_binding(
            request,
            _binding(),
            _authority(),
        )
        decision = evaluate(request, _bundle(), _authority(), _binding())

        self.assertIn(
            b"nest-authz/authority-context@1",
            canonical_bytes(request),
        )
        self.assertIn(
            b"nest-authz/authorization-request@2",
            canonical_bytes(request),
        )
        self.assertIn(
            b"nest-authz/subject-principal-binding@1",
            canonical_bytes(result),
        )
        self.assertIn(
            b"nest-authz/subject-authority-binding-status@1",
            canonical_bytes(result),
        )
        self.assertIn(
            b"nest-authz/subject-authority-binding-result@1",
            canonical_bytes(result),
        )
        self.assertIn(b"nest-authz/decision-evidence@5", canonical_bytes(decision))
        self.assertIn(b"nest-authz/decision@5", canonical_bytes(decision))
        self.assertFalse(hasattr(nest_authz, "Authority"))

    def test_binding_module_reads_no_external_state(self):
        module = importlib.import_module("nest_authz.binding")
        tree = ast.parse(inspect.getsource(module))
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
        imported_roots = set()
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.split(".", maxsplit=1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                imported_roots.add((node.module or "").split(".", maxsplit=1)[0])
            elif isinstance(node, ast.Name):
                names.add(node.id)

        self.assertTrue(prohibited_import_roots.isdisjoint(imported_roots))
        self.assertNotIn("open", names)


if __name__ == "__main__":
    unittest.main()
