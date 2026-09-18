import ast
import importlib
import inspect
import os
import subprocess
import sys
import unittest
from dataclasses import fields

from nest_authz import (
    Action,
    ApprovalRequirement,
    ApprovalRequirementState,
    ApprovalRequirementStatus,
    ApprovalStatus,
    ApprovalTransitionError,
    ApproverSubjectPrincipalBinding,
    AuthorityGrant,
    AuthorityScope,
    AuthorityValidationStatus,
    AuthorizationRequest,
    AuthorizationState,
    Condition,
    ConditionOperator,
    DelegationChain,
    ExecutionAuthorizationStatus,
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

OWNER_PRINCIPAL = Principal("principal:owner-approver")
SECURITY_PRINCIPAL = Principal("principal:security-approver")
OWNER = ApprovalRequirement("OWNER_APPROVAL", (OWNER_PRINCIPAL,))
SECURITY = ApprovalRequirement("SECURITY_APPROVAL", (SECURITY_PRINCIPAL,))


def _approver_authorization(requirement, principal):
    actor = Subject(f"approver:{principal.identifier}")
    binding = ApproverSubjectPrincipalBinding(actor, principal)
    return check_approver_authorization(
        actor,
        binding,
        requirement,
        requirement,
    )


def _authorization(
    *,
    effect=RuleEffect.APPROVAL_REQUIRED,
    requirements=(OWNER,),
    subject="agent:alice",
    action="payments.transfer",
    authority_action="payments.transfer",
    resource="account:alice",
    authority_resource="account:alice",
    amount=800,
    policy_id="policy:payments:a",
    grant_id="grant:alice:a",
    state_time=50,
    revoked=(),
    binding_principal="principal:alice",
):
    request = AuthorizationRequest(
        Subject(subject),
        Action(action),
        Resource(resource),
        RequestContext((("amount", amount),)),
        None,
    )
    grant = AuthorityGrant(
        grant_id,
        Principal("issuer:root"),
        Principal("principal:alice"),
        AuthorityScope(
            Action(authority_action),
            Resource(authority_resource),
            (("amount", 10000),),
        ),
        None,
        0,
        100,
    )
    chain = DelegationChain((grant,))
    state = AuthorizationState(state_time, RevocationSet(revoked))
    validation = validate_authority(chain, state)
    binding = SubjectPrincipalBinding(
        request.subject,
        Principal(binding_principal),
    )
    condition = Condition(
        "requested_action",
        FieldReference(FieldNamespace.ACTION, "name"),
        ConditionOperator.EQUALS,
        action,
    )
    approval_requirements = (
        requirements if effect is RuleEffect.APPROVAL_REQUIRED else ()
    )
    bundle = PolicyBundle(
        (
            Policy(
                policy_id,
                (
                    Rule(
                        "rule:payments",
                        effect,
                        (condition,),
                        approval_requirements=approval_requirements,
                    ),
                ),
            ),
        )
    )
    decision = evaluate(
        request,
        bundle,
        validation.verified_authority,
        binding,
    )
    receipt = create_decision_receipt(decision)
    return {
        "request": request,
        "chain": chain,
        "state": state,
        "validation": validation,
        "binding": binding,
        "bundle": bundle,
        "decision": decision,
        "receipt": receipt,
    }


def _pending(*, requirements=(OWNER,), logical_time=50):
    values = _authorization(requirements=requirements)
    return create_pending_approval(values["receipt"], logical_time)


def _state_for(approval, requirement):
    for state in approval.requirement_states:
        if state.requirement == requirement:
            return state
    raise AssertionError("requirement state not found")


def _revalidate(original_values, approved, current_values=None):
    current = current_values or original_values
    return revalidate_for_execution(
        original_values["receipt"],
        approved,
        current["request"],
        current["bundle"],
        current["chain"],
        current["state"],
        current["binding"],
    )


def _fully_approved(values):
    approval = create_pending_approval(values["receipt"], 50)
    for offset, requirement in enumerate(
        values["receipt"].approval_requirements,
        start=1,
    ):
        principal = requirement.allowed_principals[0]
        approval = approve_requirement(
            approval,
            requirement,
            _approver_authorization(requirement, principal),
            50 + offset,
        )
    return approval


def _execution_permit(values, approved):
    result = _revalidate(values, approved)
    if result.execution_permit is None:
        raise AssertionError(f"execution revalidation failed: {result.status}")
    return result.execution_permit


class DecisionReceiptTests(unittest.TestCase):
    def test_receipt_binds_complete_decision_evidence(self):
        values = _authorization()
        decision = values["decision"]
        receipt = values["receipt"]

        self.assertEqual(receipt.request_digest, decision.evidence.request_digest)
        self.assertEqual(
            receipt.policy_bundle_digest,
            decision.evidence.policy_bundle_digest,
        )
        self.assertEqual(
            receipt.validated_authority_digest,
            decision.evidence.authority_applicability.authority_digest,
        )
        self.assertEqual(
            receipt.delegation_chain_digest,
            decision.evidence.authority_applicability.chain_digest,
        )
        self.assertEqual(
            receipt.authorization_state_digest,
            decision.evidence.authority_applicability.state_digest,
        )
        self.assertEqual(receipt.decision_digest, sha256_digest(decision))
        self.assertNotIn("receipt_digest", {item.name for item in fields(receipt)})

    def test_approval_required_decision_can_produce_pending_approval(self):
        values = _authorization()

        approval = create_pending_approval(values["receipt"], 50)

        self.assertIs(approval.status, ApprovalStatus.PENDING)
        self.assertEqual(approval.approval_requirements, (OWNER,))

    def test_permit_receipt_cannot_produce_pending_approval(self):
        receipt = _authorization(effect=RuleEffect.PERMIT)["receipt"]

        with self.assertRaisesRegex(ValueError, "APPROVAL_REQUIRED"):
            create_pending_approval(receipt, 50)

    def test_deny_receipt_cannot_produce_pending_approval(self):
        receipt = _authorization(effect=RuleEffect.DENY)["receipt"]

        with self.assertRaisesRegex(ValueError, "APPROVAL_REQUIRED"):
            create_pending_approval(receipt, 50)

    def test_pending_identity_is_exact_receipt_identity(self):
        receipt = _authorization()["receipt"]
        approval = create_pending_approval(receipt, 50)

        self.assertEqual(approval.receipt, receipt)
        self.assertEqual(approval.receipt_digest, sha256_digest(receipt))

    def test_receipt_has_stable_content_identity_but_no_authenticity_claim(self):
        receipt = _authorization()["receipt"]

        self.assertEqual(sha256_digest(receipt), sha256_digest(receipt))
        self.assertFalse(hasattr(receipt, "signature"))
        self.assertFalse(hasattr(receipt, "issuer"))

    def test_changing_action_changes_receipt_digest(self):
        first = _authorization()["receipt"]
        changed = _authorization(action="payments.refund")["receipt"]

        self.assertNotEqual(first.request_digest, changed.request_digest)
        self.assertNotEqual(sha256_digest(first), sha256_digest(changed))

    def test_changing_subject_changes_receipt_digest(self):
        first = _authorization()["receipt"]
        changed = _authorization(subject="agent:mallory")["receipt"]

        self.assertNotEqual(first.request_digest, changed.request_digest)
        self.assertNotEqual(sha256_digest(first), sha256_digest(changed))

    def test_changing_resource_changes_receipt_digest(self):
        first = _authorization()["receipt"]
        changed = _authorization(resource="account:bob")["receipt"]

        self.assertNotEqual(first.request_digest, changed.request_digest)
        self.assertNotEqual(sha256_digest(first), sha256_digest(changed))

    def test_changing_policy_bundle_changes_receipt_digest(self):
        first = _authorization(policy_id="policy:a")["receipt"]
        changed = _authorization(policy_id="policy:b")["receipt"]

        self.assertNotEqual(
            first.policy_bundle_digest,
            changed.policy_bundle_digest,
        )
        self.assertNotEqual(sha256_digest(first), sha256_digest(changed))

    def test_changing_authority_chain_changes_receipt_digest(self):
        first = _authorization(grant_id="grant:a")["receipt"]
        changed = _authorization(grant_id="grant:b")["receipt"]

        self.assertNotEqual(
            first.delegation_chain_digest,
            changed.delegation_chain_digest,
        )
        self.assertNotEqual(sha256_digest(first), sha256_digest(changed))

    def test_changing_authorization_state_changes_receipt_digest(self):
        first = _authorization(state_time=50)["receipt"]
        changed = _authorization(state_time=51)["receipt"]

        self.assertNotEqual(
            first.authorization_state_digest,
            changed.authorization_state_digest,
        )
        self.assertNotEqual(sha256_digest(first), sha256_digest(changed))

    def test_changing_holder_binding_changes_receipt_digest(self):
        first = _authorization()["receipt"]
        changed = _authorization(binding_principal="principal:mallory")["receipt"]

        self.assertNotEqual(
            first.subject_principal_binding_evidence_digest,
            changed.subject_principal_binding_evidence_digest,
        )
        self.assertNotEqual(sha256_digest(first), sha256_digest(changed))

    def test_changing_applicability_evidence_changes_receipt_digest(self):
        first = _authorization(amount=800)["receipt"]
        changed = _authorization(amount=900)["receipt"]

        self.assertNotEqual(
            first.authority_applicability_evidence_digest,
            changed.authority_applicability_evidence_digest,
        )
        self.assertNotEqual(sha256_digest(first), sha256_digest(changed))

    def test_new_records_have_explicit_versioned_canonical_schemas(self):
        receipt = _authorization()["receipt"]
        pending = create_pending_approval(receipt, 50)
        state = pending.requirement_states[0]

        self.assertIn(b"nest-authz/decision-receipt@2", canonical_bytes(receipt))
        self.assertIn(
            b"nest-authz/approval-requirement-status@1",
            canonical_bytes(state.status),
        )
        self.assertIn(
            b"nest-authz/approval-status@1",
            canonical_bytes(pending.status),
        )
        self.assertIn(
            b"nest-authz/approval-requirement-state@2",
            canonical_bytes(state),
        )
        self.assertIn(
            b"nest-authz/pending-approval@2",
            canonical_bytes(pending),
        )

    def test_changing_final_decision_changes_receipt_digest(self):
        approval = _authorization(effect=RuleEffect.APPROVAL_REQUIRED)["receipt"]
        permit = _authorization(effect=RuleEffect.PERMIT)["receipt"]

        self.assertNotEqual(approval.decision_digest, permit.decision_digest)
        self.assertNotEqual(sha256_digest(approval), sha256_digest(permit))


class ApprovalTransitionTests(unittest.TestCase):
    def test_approval_status_enums_are_closed_and_explicit(self):
        self.assertEqual(
            set(ApprovalRequirementStatus),
            {
                ApprovalRequirementStatus.PENDING,
                ApprovalRequirementStatus.APPROVED,
                ApprovalRequirementStatus.REJECTED,
                ApprovalRequirementStatus.EXPIRED,
            },
        )
        self.assertEqual(
            set(ApprovalStatus),
            {
                ApprovalStatus.PENDING,
                ApprovalStatus.APPROVED,
                ApprovalStatus.REJECTED,
                ApprovalStatus.EXPIRED,
                ApprovalStatus.CONSUMED,
            },
        )

    def test_requirement_state_actor_semantics_fail_construction(self):
        with self.assertRaises(ValueError):
            ApprovalRequirementState(
                OWNER,
                ApprovalRequirementStatus.APPROVED,
                None,
                50,
            )
        with self.assertRaises(ValueError):
            ApprovalRequirementState(
                OWNER,
                ApprovalRequirementStatus.PENDING,
                _approver_authorization(OWNER, OWNER_PRINCIPAL),
                50,
            )
        with self.assertRaises(TypeError):
            ApprovalRequirementState(
                OWNER,
                ApprovalRequirementStatus.PENDING,
                None,
                True,
            )

    def test_one_requirement_pending_to_approved(self):
        approval = approve_requirement(
            _pending(),
            OWNER,
            _approver_authorization(OWNER, OWNER_PRINCIPAL),
            51,
        )

        self.assertIs(approval.status, ApprovalStatus.APPROVED)
        self.assertIs(
            _state_for(approval, OWNER).status,
            ApprovalRequirementStatus.APPROVED,
        )
        self.assertEqual(
            _state_for(approval, OWNER).decided_by,
            OWNER_PRINCIPAL,
        )

    def test_one_requirement_pending_to_rejected(self):
        approval = reject_requirement(
            _pending(),
            OWNER,
            _approver_authorization(OWNER, OWNER_PRINCIPAL),
            51,
        )

        self.assertIs(approval.status, ApprovalStatus.REJECTED)
        self.assertIs(
            _state_for(approval, OWNER).status,
            ApprovalRequirementStatus.REJECTED,
        )

    def test_one_requirement_pending_to_expired(self):
        approval = expire_requirement(_pending(), OWNER, 51)

        self.assertIs(approval.status, ApprovalStatus.EXPIRED)
        self.assertIsNone(_state_for(approval, OWNER).decided_by)

    def test_one_approved_one_pending_is_overall_pending(self):
        approval = approve_requirement(
            _pending(requirements=(OWNER, SECURITY)),
            OWNER,
            _approver_authorization(OWNER, OWNER_PRINCIPAL),
            51,
        )

        self.assertIs(approval.status, ApprovalStatus.PENDING)

    def test_all_requirements_approved_is_overall_approved(self):
        approval = approve_requirement(
            _pending(requirements=(OWNER, SECURITY)),
            OWNER,
            _approver_authorization(OWNER, OWNER_PRINCIPAL),
            51,
        )
        approval = approve_requirement(
            approval,
            SECURITY,
            _approver_authorization(SECURITY, SECURITY_PRINCIPAL),
            52,
        )

        self.assertIs(approval.status, ApprovalStatus.APPROVED)

    def test_any_rejection_is_overall_rejected(self):
        approval = approve_requirement(
            _pending(requirements=(OWNER, SECURITY)),
            OWNER,
            _approver_authorization(OWNER, OWNER_PRINCIPAL),
            51,
        )
        approval = reject_requirement(
            approval,
            SECURITY,
            _approver_authorization(SECURITY, SECURITY_PRINCIPAL),
            52,
        )

        self.assertIs(approval.status, ApprovalStatus.REJECTED)

    def test_rejection_precedes_expiry(self):
        approval = expire_requirement(
            _pending(requirements=(OWNER, SECURITY)),
            SECURITY,
            51,
        )
        approval = reject_requirement(
            approval,
            OWNER,
            _approver_authorization(OWNER, OWNER_PRINCIPAL),
            52,
        )

        self.assertIs(approval.status, ApprovalStatus.REJECTED)

    def test_approved_overall_state_can_be_consumed(self):
        values = _authorization()
        approval = _fully_approved(values)
        permit = _execution_permit(values, approval)

        consumed = consume_approval(approval, permit, 52)

        self.assertIs(consumed.status, ApprovalStatus.CONSUMED)
        self.assertEqual(consumed.consumed_at, 52)
        self.assertEqual(
            consumed.execution_permit_digest,
            sha256_digest(permit),
        )

    def test_pending_cannot_be_consumed(self):
        values = _authorization()
        approval = create_pending_approval(values["receipt"], 50)
        approved = _fully_approved(values)
        permit = _execution_permit(values, approved)

        with self.assertRaises(ApprovalTransitionError):
            consume_approval(approval, permit, 51)

    def test_rejected_cannot_be_consumed(self):
        values = _authorization()
        approval = reject_requirement(
            create_pending_approval(values["receipt"], 50),
            OWNER,
            _approver_authorization(OWNER, OWNER_PRINCIPAL),
            51,
        )
        approved = _fully_approved(values)
        permit = _execution_permit(values, approved)

        with self.assertRaises(ApprovalTransitionError):
            consume_approval(approval, permit, 52)

    def test_expired_cannot_be_consumed(self):
        values = _authorization()
        pending = create_pending_approval(values["receipt"], 50)
        approval = expire_requirement(pending, OWNER, 51)
        approved = _fully_approved(values)
        permit = _execution_permit(values, approved)

        with self.assertRaises(ApprovalTransitionError):
            consume_approval(approval, permit, 52)

    def test_consumed_cannot_transition_again(self):
        values = _authorization()
        approval = _fully_approved(values)
        permit = _execution_permit(values, approval)
        consumed = consume_approval(approval, permit, 52)

        with self.assertRaises(ApprovalTransitionError):
            consume_approval(consumed, permit, 53)
        with self.assertRaises(ApprovalTransitionError):
            expire_requirement(consumed, OWNER, 53)

    def test_approved_requirement_is_terminal(self):
        approval = approve_requirement(
            _pending(),
            OWNER,
            _approver_authorization(OWNER, OWNER_PRINCIPAL),
            51,
        )

        for transition in (
            lambda: approve_requirement(
                approval,
                OWNER,
                _approver_authorization(OWNER, OWNER_PRINCIPAL),
                52,
            ),
            lambda: reject_requirement(
                approval,
                OWNER,
                _approver_authorization(OWNER, OWNER_PRINCIPAL),
                52,
            ),
            lambda: expire_requirement(approval, OWNER, 52),
        ):
            with self.subTest(transition=transition):
                with self.assertRaises(ApprovalTransitionError):
                    transition()

    def test_rejected_requirement_is_terminal(self):
        approval = reject_requirement(
            _pending(),
            OWNER,
            _approver_authorization(OWNER, OWNER_PRINCIPAL),
            51,
        )

        with self.assertRaises(ApprovalTransitionError):
            approve_requirement(
                approval,
                OWNER,
                _approver_authorization(OWNER, OWNER_PRINCIPAL),
                52,
            )

    def test_expired_requirement_is_terminal(self):
        approval = expire_requirement(_pending(), OWNER, 51)

        with self.assertRaises(ApprovalTransitionError):
            approve_requirement(
                approval,
                OWNER,
                _approver_authorization(OWNER, OWNER_PRINCIPAL),
                52,
            )

    def test_repeated_transition_from_same_input_is_equal(self):
        pending = _pending()

        authorization = _approver_authorization(OWNER, OWNER_PRINCIPAL)
        first = approve_requirement(pending, OWNER, authorization, 51)
        second = approve_requirement(pending, OWNER, authorization, 51)

        self.assertEqual(first, second)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))

    def test_logical_time_cannot_move_backward(self):
        pending = _pending(logical_time=50)

        with self.assertRaises(ApprovalTransitionError):
            approve_requirement(
                pending,
                OWNER,
                _approver_authorization(OWNER, OWNER_PRINCIPAL),
                49,
            )

    def test_unknown_requirement_cannot_transition(self):
        with self.assertRaises(ApprovalTransitionError):
            approve_requirement(
                _pending(),
                SECURITY,
                _approver_authorization(SECURITY, SECURITY_PRINCIPAL),
                51,
            )


class ApprovalAdversarialTests(unittest.TestCase):
    def _approved(self, values):
        pending = create_pending_approval(values["receipt"], 50)
        return approve_requirement(
            pending,
            OWNER,
            _approver_authorization(OWNER, OWNER_PRINCIPAL),
            51,
        )

    def test_approval_for_receipt_a_cannot_satisfy_receipt_b(self):
        first = _authorization(policy_id="policy:a")
        second = _authorization(policy_id="policy:b")
        approved = self._approved(first)

        result = _revalidate(first, approved, second)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.POLICY_BUNDLE_MISMATCH,
        )
        self.assertIsNone(result.execution_permit)

    def test_stale_policy_approval_is_rejected(self):
        original = _authorization(policy_id="policy:a")
        changed = _authorization(policy_id="policy:b")
        approved = self._approved(original)

        self.assertNotEqual(
            approved.receipt.policy_bundle_digest,
            changed["receipt"].policy_bundle_digest,
        )
        result = _revalidate(original, approved, changed)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.POLICY_BUNDLE_MISMATCH,
        )

    def test_revoked_authority_after_approval_cannot_be_revived(self):
        original = _authorization()
        approved = self._approved(original)
        revoked = _authorization(revoked=("grant:alice:a",))

        self.assertIs(
            revoked["validation"].status,
            AuthorityValidationStatus.REVOKED,
        )
        self.assertIs(revoked["decision"].outcome, Outcome.DENY)
        result = _revalidate(original, approved, revoked)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.AUTHORITY_INVALID,
        )

    def test_modified_request_cannot_reuse_approval(self):
        original = _authorization(amount=8000)
        modified = _authorization(amount=9000)
        approved = self._approved(original)

        self.assertNotEqual(
            approved.receipt.request_digest,
            modified["receipt"].request_digest,
        )
        result = _revalidate(original, approved, modified)

        self.assertIs(
            result.status,
            ExecutionAuthorizationStatus.REQUEST_MISMATCH,
        )

    def test_consumed_approval_replay_fails_deterministically(self):
        values = _authorization()
        approved = self._approved(values)
        permit = _execution_permit(values, approved)
        consumed = consume_approval(approved, permit, 52)

        for _ in range(2):
            with self.assertRaisesRegex(
                ApprovalTransitionError,
                "consumed",
            ):
                consume_approval(consumed, permit, 53)

    def test_python_hash_seed_does_not_change_receipt_or_approval_identity(self):
        script = "\n".join(
            (
                "from nest_authz import *",
                "request = AuthorizationRequest(Subject('agent:alice'), Action('payments.transfer'), Resource('account:alice'), RequestContext({'amount': 800}), None)",
                "grant = AuthorityGrant('grant:alice', Principal('issuer:root'), Principal('principal:alice'), AuthorityScope(Action('payments.transfer'), Resource('account:alice'), {'amount': 10000}), None, 0, 100)",
                "authority = validate_authority(DelegationChain((grant,)), AuthorizationState(50)).verified_authority",
                "binding = SubjectPrincipalBinding(Subject('agent:alice'), Principal('principal:alice'))",
                "condition = Condition('action', FieldReference(FieldNamespace.ACTION, 'name'), ConditionOperator.EQUALS, 'payments.transfer')",
                "approver = Principal('principal:owner')",
                "requirement = ApprovalRequirement('OWNER_APPROVAL', (approver,))",
                "rule = Rule('rule:approve', RuleEffect.APPROVAL_REQUIRED, (condition,), approval_requirements=(requirement,))",
                "bundle = PolicyBundle((Policy('policy:payments', (rule,)),))",
                "decision = evaluate(request, bundle, authority, binding)",
                "receipt = create_decision_receipt(decision)",
                "pending = create_pending_approval(receipt, 50)",
                "actor = Subject('approver:owner')",
                "approver_binding = ApproverSubjectPrincipalBinding(actor, approver)",
                "authorization = check_approver_authorization(actor, approver_binding, requirement, requirement)",
                "approved = approve_requirement(pending, requirement, authorization, 51)",
                "print(str(sha256_digest(receipt)))",
                "print(canonical_bytes(receipt).hex())",
                "print(str(sha256_digest(approved)))",
                "print(canonical_bytes(approved).hex())",
            )
        )
        outputs = []
        for seed in ("7", "99991"):
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

    def test_receipt_and_approval_modules_read_no_external_state(self):
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
        for module_name in ("nest_authz.receipt", "nest_authz.approval"):
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


if __name__ == "__main__":
    unittest.main()
