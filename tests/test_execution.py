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
    ApprovalStatus,
    ApprovalTransitionError,
    ApproverAuthorizationStatus,
    ApproverSubjectPrincipalBinding,
    AuthorityApplicabilityStatus,
    AuthorityGrant,
    AuthorityScope,
    AuthorityValidationStatus,
    AuthorizationRequest,
    AuthorizationState,
    Condition,
    ConditionOperator,
    DelegationChain,
    ExecutionAuthorizationStatus,
    ExecutionPermit,
    FieldNamespace,
    FieldReference,
    Outcome,
    Policy,
    PolicyBundle,
    Principal,
    RequestContext,
    Resource,
    RevocationSet,
    Rule,
    RuleEffect,
    Subject,
    SubjectPrincipalBinding,
    approve_requirement,
    canonical_bytes,
    check_approver_authorization,
    consume_approval,
    create_decision_receipt,
    create_pending_approval,
    evaluate,
    expire_requirement,
    reject_requirement,
    revalidate_for_execution,
    sha256_digest,
    validate_authority,
)

MANAGER = Principal("principal:manager")
SECURITY = Principal("principal:security")
MALLORY = Principal("principal:mallory")
MANAGER_APPROVAL = ApprovalRequirement("MANAGER_APPROVAL", (MANAGER,))
SECURITY_APPROVAL = ApprovalRequirement("SECURITY_APPROVAL", (SECURITY,))


def _request(
    *,
    amount=800,
    action="payments.transfer",
    resource="account:alice",
):
    return AuthorizationRequest(
        Subject("agent:alice"),
        Action(action),
        Resource(resource),
        RequestContext((("amount", amount),)),
        None,
    )


def _chain(*, max_amount=1000, valid_until=200):
    action = Action("payments.transfer")
    resource = Resource("account:alice")
    root = AuthorityGrant(
        "grant:root",
        Principal("issuer:root"),
        Principal("principal:delegator"),
        AuthorityScope(action, resource, (("amount", 5000),)),
        None,
        0,
        valid_until,
    )
    leaf = AuthorityGrant(
        "grant:leaf",
        Principal("principal:delegator"),
        Principal("principal:alice"),
        AuthorityScope(action, resource, (("amount", max_amount),)),
        root.identifier,
        0,
        valid_until,
    )
    return DelegationChain((root, leaf))


def _state(logical_time=100, revoked=()):
    return AuthorizationState(logical_time, RevocationSet(revoked))


def _subject_binding(principal="principal:alice"):
    return SubjectPrincipalBinding(
        Subject("agent:alice"),
        Principal(principal),
    )


def _bundle(
    *,
    requirements=(MANAGER_APPROVAL,),
    effect=RuleEffect.APPROVAL_REQUIRED,
    policy_id="policy:payments",
):
    condition = Condition(
        "transfer_action",
        FieldReference(FieldNamespace.ACTION, "name"),
        ConditionOperator.EQUALS,
        "payments.transfer",
    )
    approval_requirements = (
        requirements if effect is RuleEffect.APPROVAL_REQUIRED else ()
    )
    rule = Rule(
        "rule:transfer",
        effect,
        (condition,),
        approval_requirements=approval_requirements,
    )
    return PolicyBundle((Policy(policy_id, (rule,)),))


def _authorization(
    *,
    request=None,
    bundle=None,
    chain=None,
    state=None,
    binding=None,
):
    request = request or _request()
    bundle = bundle or _bundle()
    chain = chain or _chain()
    state = state or _state()
    binding = binding or _subject_binding()
    validation = validate_authority(chain, state)
    decision = evaluate(
        request,
        bundle,
        validation.verified_authority,
        binding,
    )
    receipt = create_decision_receipt(decision)
    return {
        "request": request,
        "bundle": bundle,
        "chain": chain,
        "state": state,
        "binding": binding,
        "validation": validation,
        "decision": decision,
        "receipt": receipt,
    }


def _approver_evidence(
    requirement=MANAGER_APPROVAL,
    *,
    principal=MANAGER,
    actor_identifier="approver:manager",
    binding_subject=None,
    attempted_requirement=None,
):
    actor = Subject(actor_identifier)
    binding = ApproverSubjectPrincipalBinding(
        Subject(binding_subject or actor_identifier),
        principal,
    )
    return check_approver_authorization(
        actor,
        binding,
        requirement,
        attempted_requirement or requirement,
    )


def _approve(values):
    approval = create_pending_approval(values["receipt"], 100)
    for offset, requirement in enumerate(
        values["receipt"].approval_requirements,
        start=1,
    ):
        principal = requirement.allowed_principals[0]
        authorization = _approver_evidence(
            requirement,
            principal=principal,
            actor_identifier=f"approver:{principal.identifier}",
        )
        approval = approve_requirement(
            approval,
            requirement,
            authorization,
            100 + offset,
        )
    return approval


def _revalidate(original, approval, *, current=None):
    current = current or original
    return revalidate_for_execution(
        original["receipt"],
        approval,
        current["request"],
        current["bundle"],
        current["chain"],
        current["state"],
        current["binding"],
    )


class ApproverAuthorizationTests(unittest.TestCase):
    def test_allowed_principal_can_approve_requirement(self):
        result = _approver_evidence()

        self.assertIs(result.status, ApproverAuthorizationStatus.AUTHORIZED)

    def test_unlisted_principal_cannot_approve(self):
        result = _approver_evidence(principal=MALLORY)

        self.assertIs(
            result.status,
            ApproverAuthorizationStatus.PRINCIPAL_NOT_ALLOWED,
        )

    def test_approver_subject_mismatch_fails(self):
        result = _approver_evidence(binding_subject="approver:someone-else")

        self.assertIs(
            result.status,
            ApproverAuthorizationStatus.SUBJECT_MISMATCH,
        )

    def test_requirement_mismatch_fails(self):
        result = _approver_evidence(
            attempted_requirement=SECURITY_APPROVAL,
        )

        self.assertIs(
            result.status,
            ApproverAuthorizationStatus.REQUIREMENT_MISMATCH,
        )

    def test_knowing_requirement_code_does_not_grant_authority(self):
        forged = ApprovalRequirement("MANAGER_APPROVAL", (MALLORY,))
        result = _approver_evidence(attempted_requirement=forged)

        self.assertEqual(forged.code, MANAGER_APPROVAL.code)
        self.assertIs(
            result.status,
            ApproverAuthorizationStatus.REQUIREMENT_MISMATCH,
        )

    def test_bound_identity_alone_does_not_imply_approval_authority(self):
        actor = Subject("approver:mallory")
        binding = ApproverSubjectPrincipalBinding(actor, MALLORY)

        result = check_approver_authorization(
            actor,
            binding,
            MANAGER_APPROVAL,
            MANAGER_APPROVAL,
        )

        self.assertEqual(result.actor, binding.subject)
        self.assertIs(
            result.status,
            ApproverAuthorizationStatus.PRINCIPAL_NOT_ALLOWED,
        )

    def test_unauthorized_evidence_cannot_transition_requirement(self):
        values = _authorization()
        pending = create_pending_approval(values["receipt"], 100)
        unauthorized = _approver_evidence(principal=MALLORY)

        with self.assertRaises(ApprovalTransitionError):
            approve_requirement(
                pending,
                MANAGER_APPROVAL,
                unauthorized,
                101,
            )

    def test_rejection_requires_the_same_explicit_authority(self):
        values = _authorization()
        pending = create_pending_approval(values["receipt"], 100)

        with self.assertRaises(ApprovalTransitionError):
            reject_requirement(
                pending,
                MANAGER_APPROVAL,
                _approver_evidence(principal=MALLORY),
                101,
            )

    def test_allowed_principal_order_is_nonsemantic_and_copied(self):
        source = [SECURITY, MANAGER]
        first = ApprovalRequirement("DUAL_APPROVAL", source)
        second = ApprovalRequirement("DUAL_APPROVAL", (MANAGER, SECURITY))
        source.append(MALLORY)

        self.assertEqual(first, second)
        self.assertEqual(first.allowed_principals, (MANAGER, SECURITY))

    def test_approval_requirement_requires_explicit_unique_principals(self):
        with self.assertRaises(ValueError):
            ApprovalRequirement("MANAGER_APPROVAL", ())
        with self.assertRaises(ValueError):
            ApprovalRequirement("MANAGER_APPROVAL", (MANAGER, MANAGER))


class ExecutionRevalidationTests(unittest.TestCase):
    def test_exact_same_state_succeeds(self):
        original = _authorization()
        approved = _approve(original)

        result = _revalidate(original, approved)

        self.assertIs(result.status, ExecutionAuthorizationStatus.AUTHORIZED)
        self.assertIsInstance(result.execution_permit, ExecutionPermit)

    def test_logical_time_advances_while_authority_valid(self):
        original = _authorization(state=_state(100))
        approved = _approve(original)
        current = _authorization(state=_state(130))

        result = _revalidate(original, approved, current=current)

        self.assertIs(result.status, ExecutionAuthorizationStatus.AUTHORIZED)
        self.assertNotEqual(
            original["receipt"].authorization_state_digest,
            result.execution_permit.current_authorization_state_digest,
        )

    def test_logical_time_beyond_valid_until_fails(self):
        chain = _chain(valid_until=120)
        original = _authorization(chain=chain, state=_state(100))
        approved = _approve(original)
        current = _authorization(chain=chain, state=_state(130))

        result = _revalidate(original, approved, current=current)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.AUTHORITY_INVALID,
        )
        self.assertIs(
            result.authority_validation.status,
            AuthorityValidationStatus.EXPIRED,
        )

    def test_unrelated_revocation_does_not_invalidate_relevant_chain(self):
        original = _authorization(state=_state(100))
        approved = _approve(original)
        current = _authorization(
            state=_state(130, ("grant:unrelated",)),
        )

        result = _revalidate(original, approved, current=current)

        self.assertIs(result.status, ExecutionAuthorizationStatus.AUTHORIZED)
        self.assertNotEqual(
            original["receipt"].authorization_state_digest,
            result.current_authorization_state_digest,
        )

    def test_revoked_ancestor_fails(self):
        original = _authorization()
        approved = _approve(original)
        current = _authorization(state=_state(110, ("grant:root",)))

        result = _revalidate(original, approved, current=current)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.AUTHORITY_INVALID,
        )
        self.assertEqual(
            result.authority_validation.offending_grant_id,
            "grant:root",
        )

    def test_revoked_leaf_fails(self):
        original = _authorization()
        approved = _approve(original)
        current = _authorization(state=_state(110, ("grant:leaf",)))

        result = _revalidate(original, approved, current=current)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.AUTHORITY_INVALID,
        )
        self.assertEqual(
            result.authority_validation.offending_grant_id,
            "grant:leaf",
        )

    def test_request_amount_change_fails(self):
        original = _authorization(request=_request(amount=800))
        approved = _approve(original)
        current = _authorization(request=_request(amount=900))

        result = _revalidate(original, approved, current=current)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.REQUEST_MISMATCH,
        )

    def test_request_resource_change_fails(self):
        original = _authorization()
        approved = _approve(original)
        current = _authorization(request=_request(resource="account:bob"))

        result = _revalidate(original, approved, current=current)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.REQUEST_MISMATCH,
        )

    def test_request_action_change_fails(self):
        original = _authorization()
        approved = _approve(original)
        current = _authorization(request=_request(action="payments.refund"))

        result = _revalidate(original, approved, current=current)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.REQUEST_MISMATCH,
        )

    def test_policy_bundle_change_fails(self):
        original = _authorization()
        approved = _approve(original)
        current = _authorization(
            bundle=_bundle(policy_id="policy:payments:v2"),
        )

        result = _revalidate(original, approved, current=current)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.POLICY_BUNDLE_MISMATCH,
        )

    def test_approval_requirement_set_change_fails(self):
        original = _authorization()
        approved = _approve(original)
        current = _authorization(
            bundle=_bundle(
                requirements=(MANAGER_APPROVAL, SECURITY_APPROVAL),
            ),
        )

        result = _revalidate(original, approved, current=current)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.APPROVAL_REQUIREMENTS_CHANGED,
        )

    def test_holder_binding_change_fails(self):
        original = _authorization()
        approved = _approve(original)
        current = _authorization(binding=_subject_binding("principal:mallory"))

        result = _revalidate(original, approved, current=current)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.HOLDER_BINDING_FAILED,
        )

    def test_authority_scope_change_cannot_cover_request(self):
        original = _authorization()
        approved = _approve(original)
        current = _authorization(chain=_chain(max_amount=500))

        result = _revalidate(original, approved, current=current)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.DELEGATION_CHAIN_MISMATCH,
        )
        self.assertIs(
            result.authority_applicability.status,
            AuthorityApplicabilityStatus.BOUND_EXCEEDED,
        )

    def test_pending_approval_cannot_produce_execution_permit(self):
        original = _authorization()
        pending = create_pending_approval(original["receipt"], 100)

        result = _revalidate(original, pending)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.APPROVAL_NOT_APPROVED,
        )
        self.assertIsNone(result.execution_permit)

    def test_rejected_approval_cannot_produce_execution_permit(self):
        original = _authorization()
        pending = create_pending_approval(original["receipt"], 100)
        rejected = reject_requirement(
            pending,
            MANAGER_APPROVAL,
            _approver_evidence(),
            101,
        )

        result = _revalidate(original, rejected)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.APPROVAL_NOT_APPROVED,
        )

    def test_expired_approval_cannot_produce_execution_permit(self):
        original = _authorization()
        pending = create_pending_approval(original["receipt"], 100)
        expired = expire_requirement(pending, MANAGER_APPROVAL, 101)

        result = _revalidate(original, expired)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.APPROVAL_NOT_APPROVED,
        )

    def test_consumed_approval_cannot_produce_execution_permit(self):
        original = _authorization()
        approved = _approve(original)
        permit = _revalidate(original, approved).execution_permit
        consumed = consume_approval(approved, permit, 102)

        result = _revalidate(original, consumed)

        self.assertIs(consumed.status, ApprovalStatus.CONSUMED)
        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.APPROVAL_NOT_APPROVED,
        )

    def test_current_deny_policy_cannot_be_overridden(self):
        original = _authorization()
        approved = _approve(original)
        current = _authorization(bundle=_bundle(effect=RuleEffect.DENY))

        result = _revalidate(original, approved, current=current)

        self.assertIs(result.decision.outcome, Outcome.DENY)
        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.POLICY_DENIED,
        )

    def test_current_permit_requires_explicit_reauthorization(self):
        original = _authorization()
        approved = _approve(original)
        current = _authorization(bundle=_bundle(effect=RuleEffect.PERMIT))

        result = _revalidate(original, approved, current=current)

        self.assertIs(result.decision.outcome, Outcome.PERMIT)
        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.POLICY_REAUTHORIZATION_REQUIRED,
        )

    def test_successful_result_produces_content_addressed_permit(self):
        original = _authorization()
        approved = _approve(original)

        result = _revalidate(original, approved)
        permit = result.execution_permit

        self.assertEqual(
            permit.original_receipt_digest,
            sha256_digest(original["receipt"]),
        )
        self.assertEqual(permit.approved_state_digest, sha256_digest(approved))
        self.assertEqual(
            permit.current_validated_authority_digest,
            sha256_digest(original["validation"].verified_authority),
        )
        self.assertEqual(permit.decision, result.decision)
        self.assertEqual(sha256_digest(permit), sha256_digest(permit))

    def test_execution_permit_cannot_be_constructed_directly(self):
        with self.assertRaisesRegex(TypeError, "successful revalidation"):
            ExecutionPermit()

    def test_repeated_revalidation_is_equal(self):
        original = _authorization()
        approved = _approve(original)

        first = _revalidate(original, approved)
        second = _revalidate(original, approved)

        self.assertEqual(first, second)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))

    def test_execution_permit_is_required_for_consumption(self):
        original = _authorization()
        approved = _approve(original)

        with self.assertRaises(TypeError):
            consume_approval(approved, original["receipt"], 102)

        permit = _revalidate(original, approved).execution_permit
        consumed = consume_approval(approved, permit, 102)
        self.assertEqual(
            consumed.execution_permit_digest,
            sha256_digest(permit),
        )

    def test_execution_permit_for_another_approval_cannot_consume(self):
        original = _authorization()
        approved = _approve(original)
        other = _authorization(
            bundle=_bundle(policy_id="policy:other"),
        )
        other_approved = _approve(other)
        other_permit = _revalidate(other, other_approved).execution_permit

        with self.assertRaises(ApprovalTransitionError):
            consume_approval(approved, other_permit, 102)

    def test_new_types_have_stable_canonical_schemas(self):
        authorization = _approver_evidence()
        original = _authorization()
        approved = _approve(original)
        result = _revalidate(original, approved)
        permit = result.execution_permit

        values_and_schemas = (
            (
                authorization.binding,
                b"nest-authz/approver-subject-principal-binding@1",
            ),
            (
                authorization.status,
                b"nest-authz/approver-authorization-status@1",
            ),
            (
                authorization,
                b"nest-authz/approver-authorization-result@1",
            ),
            (
                result.status,
                b"nest-authz/execution-authorization-status@1",
            ),
            (
                result,
                b"nest-authz/execution-authorization-result@1",
            ),
            (permit, b"nest-authz/execution-permit@1"),
        )
        for value, schema in values_and_schemas:
            with self.subTest(schema=schema):
                self.assertIn(schema, canonical_bytes(value))

        policy_bytes = canonical_bytes(original["bundle"])
        receipt_bytes = canonical_bytes(original["receipt"])
        pending_bytes = canonical_bytes(approved)
        self.assertIn(b"nest-authz/approval-requirement@2", policy_bytes)
        self.assertIn(b"nest-authz/rule@3", policy_bytes)
        self.assertIn(b"nest-authz/policy@3", policy_bytes)
        self.assertIn(b"nest-authz/policy-bundle@3", policy_bytes)
        self.assertIn(b"nest-authz/decision-receipt@2", receipt_bytes)
        self.assertIn(b"nest-authz/approval-requirement-state@2", pending_bytes)
        self.assertIn(b"nest-authz/pending-approval@2", pending_bytes)

    def test_python_hash_seed_does_not_change_revalidation(self):
        script = "\n".join(
            (
                "from nest_authz import *",
                "manager = Principal('principal:manager')",
                "requirement = ApprovalRequirement('MANAGER_APPROVAL', (manager,))",
                "request = AuthorizationRequest(Subject('agent:alice'), Action('payments.transfer'), Resource('account:alice'), RequestContext({'amount': 800}), None)",
                "scope = AuthorityScope(Action('payments.transfer'), Resource('account:alice'), {'amount': 1000})",
                "grant = AuthorityGrant('grant:leaf', Principal('issuer:root'), Principal('principal:alice'), scope, None, 0, 200)",
                "chain = DelegationChain((grant,))",
                "state = AuthorizationState(100)",
                "authority = validate_authority(chain, state).verified_authority",
                "holder = SubjectPrincipalBinding(request.subject, Principal('principal:alice'))",
                "condition = Condition('action', FieldReference(FieldNamespace.ACTION, 'name'), ConditionOperator.EQUALS, 'payments.transfer')",
                "rule = Rule('rule:approval', RuleEffect.APPROVAL_REQUIRED, (condition,), approval_requirements=(requirement,))",
                "bundle = PolicyBundle((Policy('policy:payments', (rule,)),))",
                "receipt = create_decision_receipt(evaluate(request, bundle, authority, holder))",
                "pending = create_pending_approval(receipt, 100)",
                "actor = Subject('approver:manager')",
                "approver_binding = ApproverSubjectPrincipalBinding(actor, manager)",
                "authorization = check_approver_authorization(actor, approver_binding, requirement, requirement)",
                "approved = approve_requirement(pending, requirement, authorization, 101)",
                "result = revalidate_for_execution(receipt, approved, request, bundle, chain, AuthorizationState(130), holder)",
                "print(result.status.value)",
                "print(canonical_bytes(result).hex())",
                "print(str(sha256_digest(result.execution_permit)))",
            )
        )
        outputs = []
        for seed in ("11", "8675309"):
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
        self.assertTrue(outputs[0].startswith("AUTHORIZED\n"))

    def test_approval_and_execution_source_read_no_external_state(self):
        prohibited_import_roots = {
            "datetime",
            "os",
            "pathlib",
            "random",
            "secrets",
            "socket",
            "sqlite3",
            "subprocess",
            "time",
            "urllib",
            "uuid",
        }
        for module_name in (
            "nest_authz.approver",
            "nest_authz.approval",
            "nest_authz.execution",
        ):
            with self.subTest(module=module_name):
                module = importlib.import_module(module_name)
                tree = ast.parse(inspect.getsource(module))
                imported_roots = set()
                names = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported_roots.update(
                            alias.name.split(".", maxsplit=1)[0] for alias in node.names
                        )
                    elif isinstance(node, ast.ImportFrom) and node.level == 0:
                        imported_roots.add(
                            (node.module or "").split(".", maxsplit=1)[0]
                        )
                    elif isinstance(node, ast.Name):
                        names.add(node.id)

                self.assertTrue(prohibited_import_roots.isdisjoint(imported_roots))
                self.assertNotIn("open", names)


class ExecutionAdversarialTests(unittest.TestCase):
    def test_mallory_cannot_satisfy_manager_approval(self):
        original = _authorization()
        pending = create_pending_approval(original["receipt"], 100)
        mallory = _approver_evidence(
            principal=MALLORY,
            actor_identifier="approver:mallory",
        )

        self.assertIs(
            mallory.status,
            ApproverAuthorizationStatus.PRINCIPAL_NOT_ALLOWED,
        )
        with self.assertRaises(ApprovalTransitionError):
            approve_requirement(
                pending,
                MANAGER_APPROVAL,
                mallory,
                101,
            )

    def test_revocation_after_approval_cannot_resurrect_authority(self):
        original = _authorization(state=_state(100))
        approved = _approve(original)
        current = _authorization(state=_state(110, ("grant:leaf",)))

        result = _revalidate(original, approved, current=current)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.AUTHORITY_INVALID,
        )
        self.assertIsNone(result.execution_permit)

    def test_modified_amount_cannot_execute(self):
        original = _authorization(request=_request(amount=800))
        approved = _approve(original)
        current = _authorization(request=_request(amount=900))

        result = _revalidate(original, approved, current=current)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.REQUEST_MISMATCH,
        )
        self.assertIsNone(result.execution_permit)

    def test_unrelated_revocation_uses_relevant_chain_semantics(self):
        original = _authorization(state=_state(100))
        approved = _approve(original)
        current = _authorization(
            state=_state(130, ("grant:unrelated",)),
        )

        result = _revalidate(original, approved, current=current)

        self.assertNotEqual(
            sha256_digest(original["state"]),
            sha256_digest(current["state"]),
        )
        self.assertIs(result.status, ExecutionAuthorizationStatus.AUTHORIZED)

    def test_old_approval_cannot_satisfy_new_second_requirement(self):
        original = _authorization(
            bundle=_bundle(requirements=(MANAGER_APPROVAL,)),
        )
        approved = _approve(original)
        current = _authorization(
            bundle=_bundle(
                requirements=(MANAGER_APPROVAL, SECURITY_APPROVAL),
            ),
        )

        result = _revalidate(original, approved, current=current)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.APPROVAL_REQUIREMENTS_CHANGED,
        )
        self.assertIsNone(result.execution_permit)


if __name__ == "__main__":
    unittest.main()
