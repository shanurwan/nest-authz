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
    AuthorityGrant,
    AuthorityScope,
    AuthorizationRequest,
    AuthorizationState,
    Condition,
    ConditionOperator,
    ConditionStatus,
    DelegationChain,
    FieldNamespace,
    FieldReference,
    Obligation,
    Outcome,
    Policy,
    PolicyBundle,
    Principal,
    RequestContext,
    Resource,
    Rule,
    RuleEffect,
    RuleEvaluationStatus,
    RevocationSet,
    Subject,
    SubjectPrincipalBinding,
    canonical_bytes,
    evaluate as _evaluate_with_authority,
    sha256_digest,
    validate_authority,
)


_DEFAULT_AUTHORITY = object()


def _verified_authority():
    grant = AuthorityGrant(
        "grant:messages",
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


def evaluate(request, bundle, authority=_DEFAULT_AUTHORITY):
    if authority is _DEFAULT_AUTHORITY:
        authority = _verified_authority()
    binding = SubjectPrincipalBinding(
        Subject("agent:7"),
        Principal("agent:7"),
    )
    return _evaluate_with_authority(request, bundle, authority, binding)


def _request(context=(), authority=True):
    request_authority = (
        AuthorityContext("grant:1", {"scope": "messages", "active": True})
        if authority
        else None
    )
    return AuthorizationRequest(
        Subject("agent:7"),
        Action("message.send"),
        Resource("room:general"),
        RequestContext(context),
        request_authority,
    )


def _condition(
    identifier,
    namespace=FieldNamespace.CONTEXT,
    name="allowed",
    operator=ConditionOperator.EQUALS,
    value=True,
):
    return Condition(
        identifier,
        FieldReference(namespace, name),
        operator,
        value,
    )


def _rule(
    identifier,
    effect=RuleEffect.PERMIT,
    conditions=None,
    obligations=(),
    approval_requirements=None,
):
    requirements = approval_requirements
    if requirements is None:
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
    return Rule(
        identifier,
        effect,
        conditions or (_condition(f"{identifier}:allowed"),),
        obligations,
        requirements,
    )


def _bundle(*rules):
    return PolicyBundle((Policy("policy:1", rules),))


def _status(decision, rule_id, condition_id):
    for evaluation in decision.evidence.rule_evaluations:
        if evaluation.rule_id == rule_id:
            return dict(evaluation.condition_results)[condition_id]
    raise AssertionError(f"rule evidence not found: {rule_id}")


def _rule_status(decision, rule_id):
    for evaluation in decision.evidence.rule_evaluations:
        if evaluation.rule_id == rule_id:
            return evaluation.status
    raise AssertionError(f"rule evidence not found: {rule_id}")


class EvaluatorOutcomeTests(unittest.TestCase):
    def test_empty_bundle_is_explicit_default_deny(self):
        decision = evaluate(_request(), PolicyBundle())

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(decision.reasons[0].code, "NO_MATCHING_RULE")
        self.assertEqual(decision.evidence.rule_evaluations, ())

    def test_no_matching_rule_defaults_to_deny(self):
        rule = _rule(
            "rule:permit",
            conditions=(
                _condition("tenant_matches", name="tenant", value="north"),
            ),
        )

        decision = evaluate(_request({"tenant": "south"}), _bundle(rule))

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(decision.reasons[0].code, "NO_MATCHING_RULE")

    def test_matching_permit_returns_permit(self):
        decision = evaluate(_request({"allowed": True}), _bundle(_rule("rule:permit")))

        self.assertIs(decision.outcome, Outcome.PERMIT)

    def test_matching_deny_returns_deny(self):
        decision = evaluate(
            _request({"allowed": True}),
            _bundle(_rule("rule:deny", RuleEffect.DENY)),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(decision.reasons[0].code, "DENY_RULE_MATCHED")

    def test_matching_approval_returns_all_requirements(self):
        requirements = (
            ApprovalRequirement(
                "SECURITY_APPROVAL",
                (Principal("principal:security-approver"),),
            ),
            ApprovalRequirement(
                "OWNER_APPROVAL",
                (Principal("principal:owner-approver"),),
            ),
        )
        decision = evaluate(
            _request({"allowed": True}),
            _bundle(
                _rule(
                    "rule:approval",
                    RuleEffect.APPROVAL_REQUIRED,
                    approval_requirements=requirements,
                )
            ),
        )

        self.assertIs(decision.outcome, Outcome.APPROVAL_REQUIRED)
        self.assertEqual(
            decision.approval_requirements,
            (
                ApprovalRequirement(
                    "OWNER_APPROVAL",
                    (Principal("principal:owner-approver"),),
                ),
                ApprovalRequirement(
                    "SECURITY_APPROVAL",
                    (Principal("principal:security-approver"),),
                ),
            ),
        )

    def test_deny_beats_permit(self):
        decision = evaluate(
            _request({"allowed": True}),
            _bundle(
                _rule("rule:permit"),
                _rule("rule:deny", RuleEffect.DENY),
            ),
        )

        self.assertIs(decision.outcome, Outcome.DENY)

    def test_deny_beats_approval(self):
        decision = evaluate(
            _request({"allowed": True}),
            _bundle(
                _rule("rule:approval", RuleEffect.APPROVAL_REQUIRED),
                _rule("rule:deny", RuleEffect.DENY),
            ),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(decision.approval_requirements, ())

    def test_approval_beats_permit(self):
        decision = evaluate(
            _request({"allowed": True}),
            _bundle(
                _rule("rule:permit"),
                _rule("rule:approval", RuleEffect.APPROVAL_REQUIRED),
            ),
        )

        self.assertIs(decision.outcome, Outcome.APPROVAL_REQUIRED)

    def test_multiple_simultaneous_effects_are_deny_overrides(self):
        rules = (
            _rule("rule:permit:a"),
            _rule("rule:approval:a", RuleEffect.APPROVAL_REQUIRED),
            _rule("rule:permit:b"),
            _rule("rule:deny:a", RuleEffect.DENY),
            _rule("rule:approval:b", RuleEffect.APPROVAL_REQUIRED),
            _rule("rule:deny:b", RuleEffect.DENY),
        )

        decision = evaluate(_request({"allowed": True}), _bundle(*rules))

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(len(decision.evidence.matched_rule_ids), len(rules))


class EvaluatorDeterminismTests(unittest.TestCase):
    def test_rule_order_does_not_change_decision(self):
        permit = _rule("rule:permit")
        deny = _rule("rule:deny", RuleEffect.DENY)
        first = PolicyBundle((Policy("policy:1", (permit, deny)),))
        second = PolicyBundle((Policy("policy:1", (deny, permit)),))

        self.assertEqual(first, second)
        self.assertEqual(
            evaluate(_request({"allowed": True}), first),
            evaluate(_request({"allowed": True}), second),
        )

    def test_policy_order_does_not_change_decision(self):
        permit_policy = Policy("policy:permit", (_rule("rule:permit"),))
        approval_policy = Policy(
            "policy:approval",
            (_rule("rule:approval", RuleEffect.APPROVAL_REQUIRED),),
        )
        first = PolicyBundle((permit_policy, approval_policy))
        second = PolicyBundle((approval_policy, permit_policy))

        self.assertEqual(
            evaluate(_request({"allowed": True}), first),
            evaluate(_request({"allowed": True}), second),
        )

    def test_repeated_evaluation_is_equal_and_canonical(self):
        request = _request({"allowed": True})
        bundle = _bundle(_rule("rule:permit"))

        first = evaluate(request, bundle)
        second = evaluate(request, bundle)

        self.assertEqual(first, second)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))

    def test_python_hash_seed_does_not_change_decision_or_canonical_bytes(self):
        script = "\n".join(
            (
                "from nest_authz import *",
                "request = AuthorizationRequest(Subject('agent:7'), Action('message.send'), Resource('room:general'), RequestContext({'allowed': True}), AuthorityContext('grant:1'))",
                "condition = Condition('allowed', FieldReference(FieldNamespace.CONTEXT, 'allowed'), ConditionOperator.EQUALS, True)",
                "rule = Rule('rule:permit', RuleEffect.PERMIT, (condition,))",
                "bundle = PolicyBundle((Policy('policy:1', (rule,)),))",
                "grant = AuthorityGrant('grant:messages', Principal('issuer:root'), Principal('agent:7'), AuthorityScope(Action('message.send'), Resource('room:general')), None, 0, 100)",
                "authority = validate_authority(DelegationChain((grant,)), AuthorizationState(50)).verified_authority",
                "binding = SubjectPrincipalBinding(Subject('agent:7'), Principal('agent:7'))",
                "decision = evaluate(request, bundle, authority, binding)",
                "print(decision.outcome.value)",
                "print(','.join('/'.join(value) for value in decision.evidence.matched_rule_ids))",
                "print(canonical_bytes(decision).hex())",
            )
        )
        outputs = []
        for seed in ("2", "314159"):
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


class EvaluatorConditionTests(unittest.TestCase):
    def test_absent_authority_cannot_permit(self):
        decision = evaluate(
            _request({"allowed": True}),
            _bundle(_rule("rule:permit")),
            None,
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(
            decision.reasons[0].code,
            "VALIDATED_AUTHORITY_REQUIRED",
        )
        self.assertIsNone(decision.evidence.authority_applicability)

    def test_absent_authority_reference_is_missing_input(self):
        condition = _condition(
            "authority_scope",
            FieldNamespace.AUTHORITY,
            "scope",
            value="messages",
        )
        decision = evaluate(
            _request(authority=False),
            _bundle(_rule("rule:permit", conditions=(condition,))),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertIs(
            _status(decision, "rule:permit", "authority_scope"),
            ConditionStatus.MISSING_INPUT,
        )

    def test_missing_context_on_applicable_rule_is_indeterminate_and_denied(self):
        condition = _condition("required_region", name="region", value="north")
        decision = evaluate(
            _request(),
            _bundle(_rule("rule:permit", conditions=(condition,))),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertIs(
            _rule_status(decision, "rule:permit"),
            RuleEvaluationStatus.INDETERMINATE,
        )
        self.assertIs(
            _status(decision, "rule:permit", "required_region"),
            ConditionStatus.MISSING_INPUT,
        )

    def test_unknown_on_already_unsatisfied_rule_does_not_poison_valid_rule(self):
        unrelated = _rule(
            "rule:unrelated",
            conditions=(
                _condition("a_wrong_tenant", name="tenant", value="north"),
                _condition("b_missing_region", name="region", value="west"),
            ),
        )
        permit = _rule("rule:permit")

        decision = evaluate(
            _request({"allowed": True, "tenant": "south"}),
            _bundle(unrelated, permit),
        )

        self.assertIs(decision.outcome, Outcome.PERMIT)
        self.assertIs(
            _rule_status(decision, "rule:unrelated"),
            RuleEvaluationStatus.NOT_MATCHED,
        )
        self.assertIs(
            _status(decision, "rule:unrelated", "b_missing_region"),
            ConditionStatus.MISSING_INPUT,
        )

    def test_bool_is_not_accepted_as_integer_runtime_value(self):
        condition = _condition(
            "attempts_positive",
            name="attempts",
            operator=ConditionOperator.INTEGER_GREATER_THAN,
            value=0,
        )
        decision = evaluate(
            _request({"attempts": True}),
            _bundle(_rule("rule:permit", conditions=(condition,))),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertIs(
            _status(decision, "rule:permit", "attempts_positive"),
            ConditionStatus.ERROR,
        )

    def test_equality_distinguishes_true_and_one(self):
        condition = _condition("exact_one", name="value", value=1)
        decision = evaluate(
            _request({"value": True}),
            _bundle(_rule("rule:permit", conditions=(condition,))),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertIs(
            _status(decision, "rule:permit", "exact_one"),
            ConditionStatus.ERROR,
        )

    def test_exists_treats_present_none_as_present(self):
        condition = _condition(
            "optional_present",
            name="optional",
            operator=ConditionOperator.EXISTS,
            value=None,
        )
        decision = evaluate(
            _request({"optional": None}),
            _bundle(_rule("rule:permit", conditions=(condition,))),
        )

        self.assertIs(decision.outcome, Outcome.PERMIT)
        self.assertIs(
            _status(decision, "rule:permit", "optional_present"),
            ConditionStatus.SATISFIED,
        )

    def test_exists_treats_missing_context_key_as_unsatisfied(self):
        condition = _condition(
            "optional_present",
            name="optional",
            operator=ConditionOperator.EXISTS,
            value=None,
        )
        decision = evaluate(
            _request(),
            _bundle(_rule("rule:permit", conditions=(condition,))),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertIs(
            _status(decision, "rule:permit", "optional_present"),
            ConditionStatus.UNSATISFIED,
        )
        self.assertIs(
            _rule_status(decision, "rule:permit"),
            RuleEvaluationStatus.NOT_MATCHED,
        )

    def test_not_equals_type_mismatch_is_error_not_a_grant(self):
        condition = _condition(
            "not_one",
            name="value",
            operator=ConditionOperator.NOT_EQUALS,
            value=1,
        )
        decision = evaluate(
            _request({"value": "1"}),
            _bundle(_rule("rule:permit", conditions=(condition,))),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertIs(
            _status(decision, "rule:permit", "not_one"),
            ConditionStatus.ERROR,
        )

    def test_wrong_integer_runtime_type_is_error_and_fails_closed(self):
        condition = _condition(
            "attempts_below_limit",
            name="attempts",
            operator=ConditionOperator.INTEGER_LESS_THAN,
            value=3,
        )
        decision = evaluate(
            _request({"attempts": "2"}),
            _bundle(_rule("rule:permit", conditions=(condition,))),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertIs(
            _status(decision, "rule:permit", "attempts_below_limit"),
            ConditionStatus.ERROR,
        )

    def test_permit_cannot_mask_an_indeterminate_rule(self):
        indeterminate = _rule(
            "rule:indeterminate",
            conditions=(
                _condition("missing_region", name="region", value="north"),
            ),
        )
        decision = evaluate(
            _request({"allowed": True}),
            _bundle(_rule("rule:permit"), indeterminate),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(
            decision.evidence.indeterminate_rule_ids,
            (("policy:1", "rule:indeterminate"),),
        )

    def test_closed_field_resolution_supports_declared_direct_fields(self):
        conditions = (
            _condition(
                "subject",
                FieldNamespace.SUBJECT,
                "identifier",
                value="agent:7",
            ),
            _condition(
                "action",
                FieldNamespace.ACTION,
                "name",
                value="message.send",
            ),
            _condition(
                "resource",
                FieldNamespace.RESOURCE,
                "identifier",
                value="room:general",
            ),
            _condition(
                "authority_id",
                FieldNamespace.AUTHORITY,
                "identifier",
                value="grant:1",
            ),
            _condition(
                "authority_scope",
                FieldNamespace.AUTHORITY,
                "scope",
                value="messages",
            ),
        )

        decision = evaluate(_request(), _bundle(_rule("rule:permit", conditions=conditions)))

        self.assertIs(decision.outcome, Outcome.PERMIT)

    def test_unsupported_fixed_field_is_error(self):
        condition = _condition(
            "unsupported_subject_field",
            FieldNamespace.SUBJECT,
            "display_name",
            value="Agent 7",
        )
        decision = evaluate(
            _request(),
            _bundle(_rule("rule:permit", conditions=(condition,))),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertIs(
            _status(decision, "rule:permit", "unsupported_subject_field"),
            ConditionStatus.ERROR,
        )


class EvaluatorAggregationAndEvidenceTests(unittest.TestCase):
    def test_multiple_approval_requirements_survive_combination(self):
        owner = ApprovalRequirement(
            "OWNER_APPROVAL",
            (Principal("principal:owner-approver"),),
        )
        security = ApprovalRequirement(
            "SECURITY_APPROVAL",
            (Principal("principal:security-approver"),),
        )
        first = _rule(
            "rule:approval:a",
            RuleEffect.APPROVAL_REQUIRED,
            approval_requirements=(owner,),
        )
        second = _rule(
            "rule:approval:b",
            RuleEffect.APPROVAL_REQUIRED,
            approval_requirements=(security, owner),
        )

        decision = evaluate(
            _request({"allowed": True}),
            _bundle(second, first),
        )

        self.assertIs(decision.outcome, Outcome.APPROVAL_REQUIRED)
        self.assertEqual(decision.approval_requirements, (owner, security))

    def test_obligations_combine_and_deduplicate_deterministically(self):
        audit = Obligation("AUDIT")
        redact = Obligation("REDACT")
        trace = Obligation("TRACE")
        permit = _rule(
            "rule:permit",
            obligations=(audit, trace),
        )
        approval = _rule(
            "rule:approval",
            RuleEffect.APPROVAL_REQUIRED,
            obligations=(trace, redact),
        )
        bundle = _bundle(permit, approval)

        first = evaluate(_request({"allowed": True}), bundle)
        second = evaluate(_request({"allowed": True}), bundle)

        self.assertEqual(first.obligations, (trace, redact, audit))
        self.assertEqual(first.obligations, second.obligations)

    def test_deny_does_not_carry_permit_obligations(self):
        decision = evaluate(
            _request({"allowed": True}),
            _bundle(
                _rule("rule:permit", obligations=(Obligation("AUDIT"),)),
                _rule("rule:deny", RuleEffect.DENY),
            ),
        )

        self.assertIs(decision.outcome, Outcome.DENY)
        self.assertEqual(decision.obligations, ())

    def test_evidence_binds_exact_bundle_digest_and_all_rule_results(self):
        matched = _rule("rule:permit")
        not_matched = _rule(
            "rule:other",
            conditions=(_condition("wrong", name="zone", value="north"),),
        )
        bundle = _bundle(not_matched, matched)

        decision = evaluate(
            _request({"allowed": True, "zone": "south"}),
            bundle,
        )

        self.assertEqual(decision.evidence.policy_bundle_digest, sha256_digest(bundle))
        self.assertEqual(
            decision.evidence.matched_policy_ids,
            ("policy:1",),
        )
        self.assertEqual(
            decision.evidence.matched_rule_ids,
            (("policy:1", "rule:permit"),),
        )
        self.assertEqual(len(decision.evidence.rule_evaluations), 2)
        self.assertEqual(len(decision.evidence.condition_results), 2)
        self.assertEqual(decision.evidence.request_digest, sha256_digest(_request({"allowed": True, "zone": "south"})))
        self.assertEqual(
            decision.evidence.effective_grant_id,
            "grant:messages",
        )

    def test_evaluator_source_has_no_prohibited_external_state_dependencies(self):
        evaluator_module = importlib.import_module("nest_authz.evaluator")
        source = inspect.getsource(evaluator_module)
        tree = ast.parse(source)
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
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.split(".", maxsplit=1)[0]
                    for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                imported_roots.add((node.module or "").split(".", maxsplit=1)[0])

        self.assertTrue(prohibited_import_roots.isdisjoint(imported_roots))
        self.assertNotIn("open", {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)})

        mutable_global_literals = []
        for node in tree.body:
            value = None
            if isinstance(node, ast.Assign):
                value = node.value
            elif isinstance(node, ast.AnnAssign):
                value = node.value
            if isinstance(value, (ast.Dict, ast.List, ast.Set)):
                mutable_global_literals.append(value)
        self.assertEqual(mutable_global_literals, [])


if __name__ == "__main__":
    unittest.main()
