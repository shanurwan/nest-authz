import ast
import inspect
import os
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import nest_authz.execution_enforcement as enforcement_module
import nest_authz.sqlite_execution_store as sqlite_store_module
from nest_authz import (
    Action,
    ApprovalRequirement,
    ApproverSubjectPrincipalBinding,
    AuthorityGrant,
    AuthorityScope,
    AuthorizationRequest,
    AuthorizationState,
    Condition,
    ConditionOperator,
    DelegationChain,
    ExecutionId,
    ExecutionPermitMismatchError,
    ExecutionRecord,
    ExecutionReservationResult,
    ExecutionReservationStatus,
    ExecutionStatus,
    ExecutionStore,
    ExecutionStoreError,
    ExecutionTransitionError,
    FieldNamespace,
    FieldReference,
    Policy,
    PolicyBundle,
    Principal,
    RequestContext,
    Resource,
    Rule,
    RuleEffect,
    SQLiteExecutionStore,
    Subject,
    SubjectPrincipalBinding,
    approve_requirement,
    canonical_bytes,
    check_approver_authorization,
    create_decision_receipt,
    create_pending_approval,
    evaluate,
    execution_id_for,
    revalidate_for_execution,
    sha256_digest,
    validate_authority,
)


def _permit(
    *,
    amount=800,
    action="payments.transfer",
    resource="account:alice",
    current_logical_time=100,
):
    request = AuthorizationRequest(
        Subject("agent:alice"),
        Action(action),
        Resource(resource),
        RequestContext((("amount", amount),)),
        None,
    )
    approver = Principal("principal:manager")
    requirement = ApprovalRequirement(
        "MANAGER_APPROVAL",
        (approver,),
    )
    bundle = PolicyBundle(
        (
            Policy(
                "policy:payments",
                (
                    Rule(
                        "rule:transfer",
                        RuleEffect.APPROVAL_REQUIRED,
                        (
                            Condition(
                                "action_matches",
                                FieldReference(
                                    FieldNamespace.ACTION,
                                    "name",
                                ),
                                ConditionOperator.EQUALS,
                                action,
                            ),
                        ),
                        approval_requirements=(requirement,),
                    ),
                ),
            ),
        )
    )
    root = AuthorityGrant(
        "grant:root",
        Principal("issuer:root"),
        Principal("principal:delegator"),
        AuthorityScope(
            request.action,
            request.resource,
            (("amount", 5000),),
        ),
        None,
        0,
        200,
    )
    leaf = AuthorityGrant(
        "grant:leaf",
        Principal("principal:delegator"),
        Principal("principal:alice"),
        AuthorityScope(
            request.action,
            request.resource,
            (("amount", 1000),),
        ),
        root.identifier,
        0,
        200,
    )
    chain = DelegationChain((root, leaf))
    original_state = AuthorizationState(100)
    authority = validate_authority(chain, original_state).verified_authority
    binding = SubjectPrincipalBinding(
        request.subject,
        Principal("principal:alice"),
    )
    decision = evaluate(request, bundle, authority, binding)
    receipt = create_decision_receipt(decision)
    pending = create_pending_approval(receipt, 100)
    actor = Subject("approver:manager")
    authorization = check_approver_authorization(
        actor,
        ApproverSubjectPrincipalBinding(actor, approver),
        requirement,
        requirement,
    )
    approved = approve_requirement(
        pending,
        requirement,
        authorization,
        101,
    )
    result = revalidate_for_execution(
        receipt,
        approved,
        request,
        bundle,
        chain,
        AuthorizationState(current_logical_time),
        binding,
    )
    if result.execution_permit is None:
        raise AssertionError(f"failed to construct permit: {result.status}")
    return result.execution_permit


class AtomicExecutionEnforcementTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database_path = os.path.join(
            self.temporary_directory.name,
            "execution.sqlite3",
        )
        self.store = SQLiteExecutionStore(self.database_path)
        self.permit = _permit()

    def _row_count(self):
        with closing(sqlite3.connect(self.database_path)) as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM execution_records"
            ).fetchone()[0]

    def test_01_first_reservation_is_new(self):
        result = self.store.reserve(self.permit)

        self.assertIs(
            result.status,
            ExecutionReservationStatus.NEW_RESERVATION,
        )
        self.assertIs(result.record.status, ExecutionStatus.RESERVED)
        self.assertEqual(
            result.record.execution_id,
            execution_id_for(self.permit),
        )

    def test_02_second_reservation_has_same_execution_identity(self):
        first = self.store.reserve(self.permit)
        second = self.store.reserve(self.permit)

        self.assertIs(
            second.status,
            ExecutionReservationStatus.EXISTING_RESERVED,
        )
        self.assertEqual(first.record.execution_id, second.record.execution_id)

    def test_03_duplicate_reservation_produces_one_database_row(self):
        self.store.reserve(self.permit)
        self.store.reserve(self.permit)

        self.assertEqual(self._row_count(), 1)

    def test_04_two_independent_connections_racing_create_one_row(self):
        stores = (
            SQLiteExecutionStore(self.database_path),
            SQLiteExecutionStore(self.database_path),
        )
        barrier = threading.Barrier(2)

        def reserve(store):
            barrier.wait()
            return store.reserve(self.permit)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(reserve, stores))

        self.assertEqual(
            sum(
                result.status is ExecutionReservationStatus.NEW_RESERVATION
                for result in results
            ),
            1,
        )
        self.assertEqual(self._row_count(), 1)

    def test_05_different_permits_create_different_execution_ids(self):
        other = _permit(current_logical_time=101)

        first = self.store.reserve(self.permit)
        second = self.store.reserve(other)

        self.assertNotEqual(first.record.execution_id, second.record.execution_id)
        self.assertEqual(self._row_count(), 2)

    def test_06_reserved_to_succeeded(self):
        reservation = self.store.reserve(self.permit)

        record = self.store.mark_succeeded(
            reservation.record.execution_id,
            self.permit,
            "operation:result:123",
        )

        self.assertIs(record.status, ExecutionStatus.SUCCEEDED)
        self.assertEqual(record.result_reference, "operation:result:123")
        self.assertIsNone(record.failure_reference)

    def test_07_reserved_to_failed(self):
        reservation = self.store.reserve(self.permit)

        record = self.store.mark_failed(
            reservation.record.execution_id,
            self.permit,
            "operation:failure:123",
        )

        self.assertIs(record.status, ExecutionStatus.FAILED)
        self.assertEqual(record.failure_reference, "operation:failure:123")
        self.assertIsNone(record.result_reference)

    def test_08_succeeded_is_terminal(self):
        execution_id = self.store.reserve(self.permit).record.execution_id
        self.store.mark_succeeded(
            execution_id,
            self.permit,
            "operation:result:123",
        )

        for transition in (
            lambda: self.store.mark_succeeded(
                execution_id,
                self.permit,
                "operation:result:again",
            ),
            lambda: self.store.mark_failed(
                execution_id,
                self.permit,
                "operation:failure:late",
            ),
        ):
            with self.subTest(transition=transition):
                with self.assertRaises(ExecutionTransitionError):
                    transition()

    def test_09_failed_is_terminal(self):
        execution_id = self.store.reserve(self.permit).record.execution_id
        self.store.mark_failed(
            execution_id,
            self.permit,
            "operation:failure:123",
        )

        for transition in (
            lambda: self.store.mark_failed(
                execution_id,
                self.permit,
                "operation:failure:again",
            ),
            lambda: self.store.mark_succeeded(
                execution_id,
                self.permit,
                "operation:result:late",
            ),
        ):
            with self.subTest(transition=transition):
                with self.assertRaises(ExecutionTransitionError):
                    transition()

    def test_10_replay_after_success_reports_already_succeeded(self):
        execution_id = self.store.reserve(self.permit).record.execution_id
        self.store.mark_succeeded(
            execution_id,
            self.permit,
            "operation:result:123",
        )

        replay = self.store.reserve(self.permit)

        self.assertIs(
            replay.status,
            ExecutionReservationStatus.ALREADY_SUCCEEDED,
        )
        self.assertEqual(replay.record.execution_id, execution_id)

    def test_11_replay_while_reserved_reports_existing_reserved(self):
        execution_id = self.store.reserve(self.permit).record.execution_id

        replay = self.store.reserve(self.permit)

        self.assertIs(
            replay.status,
            ExecutionReservationStatus.EXISTING_RESERVED,
        )
        self.assertEqual(replay.record.execution_id, execution_id)

    def test_12_replay_after_failure_reports_failed_existing(self):
        execution_id = self.store.reserve(self.permit).record.execution_id
        self.store.mark_failed(
            execution_id,
            self.permit,
            "operation:failure:123",
        )

        replay = self.store.reserve(self.permit)

        self.assertIs(
            replay.status,
            ExecutionReservationStatus.FAILED_EXISTING,
        )
        self.assertEqual(replay.record.execution_id, execution_id)

    def test_13_wrong_permit_cannot_update_another_execution(self):
        reservation = self.store.reserve(self.permit)
        other = _permit(current_logical_time=101)

        with self.assertRaises(ExecutionPermitMismatchError):
            self.store.mark_succeeded(
                reservation.record.execution_id,
                other,
                "operation:result:forged",
            )

        current = self.store.get(reservation.record.execution_id)
        self.assertIs(current.status, ExecutionStatus.RESERVED)

    def test_14_execution_identity_is_stable_across_pythonhashseed(self):
        code = textwrap.dedent(
            """
            from nest_authz import *
            request = AuthorizationRequest(Subject('agent:a'), Action('payments.transfer'), Resource('account:a'), RequestContext((('amount', 8),)), None)
            approver = Principal('principal:manager')
            requirement = ApprovalRequirement('MANAGER_APPROVAL', (approver,))
            condition = Condition('action', FieldReference(FieldNamespace.ACTION, 'name'), ConditionOperator.EQUALS, 'payments.transfer')
            bundle = PolicyBundle((Policy('policy:p', (Rule('rule:r', RuleEffect.APPROVAL_REQUIRED, (condition,), approval_requirements=(requirement,)),)),))
            grant = AuthorityGrant('grant:g', Principal('issuer:root'), Principal('principal:a'), AuthorityScope(request.action, request.resource, (('amount', 10),)), None, 0, 200)
            chain = DelegationChain((grant,))
            state = AuthorizationState(100)
            authority = validate_authority(chain, state).verified_authority
            binding = SubjectPrincipalBinding(request.subject, Principal('principal:a'))
            receipt = create_decision_receipt(evaluate(request, bundle, authority, binding))
            pending = create_pending_approval(receipt, 100)
            actor = Subject('approver:manager')
            evidence = check_approver_authorization(actor, ApproverSubjectPrincipalBinding(actor, approver), requirement, requirement)
            approved = approve_requirement(pending, requirement, evidence, 101)
            permit = revalidate_for_execution(receipt, approved, request, bundle, chain, state, binding).execution_permit
            identity = execution_id_for(permit)
            print(identity)
            print(canonical_bytes(identity).hex())
            """
        )
        outputs = []
        for seed in ("1", "97531"):
            environment = os.environ.copy()
            environment["PYTHONHASHSEED"] = seed
            outputs.append(
                subprocess.check_output(
                    [sys.executable, "-c", code],
                    env=environment,
                    text=True,
                )
            )
        self.assertEqual(outputs[0], outputs[1])

    def test_15_execution_identity_changes_when_permit_changes(self):
        other = _permit(current_logical_time=101)

        self.assertNotEqual(
            execution_id_for(self.permit),
            execution_id_for(other),
        )

    def test_16_database_unique_permit_constraint_is_exercised(self):
        reservation = self.store.reserve(self.permit)
        digest = str(sha256_digest(self.permit))
        forged_id = "execution:sha256:" + "0" * 64
        self.assertNotEqual(forged_id, str(reservation.record.execution_id))

        with closing(sqlite3.connect(self.database_path)) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT INTO execution_records (
                        execution_id,
                        execution_permit_digest,
                        status
                    ) VALUES (?, ?, 'RESERVED')
                    """,
                    (forged_id, digest),
                )

        self.assertEqual(self._row_count(), 1)

    def test_17_failed_transaction_rolls_back_cleanly(self):
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute(
                """
                CREATE TRIGGER reject_execution_reservation
                BEFORE INSERT ON execution_records
                BEGIN
                    SELECT RAISE(ABORT, 'forced reservation failure');
                END
                """
            )
            connection.commit()

        with self.assertRaises(ExecutionStoreError):
            self.store.reserve(self.permit)
        self.assertEqual(self._row_count(), 0)

        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute("DROP TRIGGER reject_execution_reservation")
            connection.commit()
        result = self.store.reserve(self.permit)
        self.assertIs(
            result.status,
            ExecutionReservationStatus.NEW_RESERVATION,
        )

    def test_18_reopening_store_preserves_records(self):
        reservation = self.store.reserve(self.permit)

        reopened = SQLiteExecutionStore(self.database_path)
        record = reopened.get(reservation.record.execution_id)

        self.assertEqual(record, reservation.record)

    def test_19_two_store_instances_observe_same_durable_state(self):
        first = SQLiteExecutionStore(self.database_path)
        second = SQLiteExecutionStore(self.database_path)

        reservation = first.reserve(self.permit)

        self.assertEqual(
            second.get(reservation.record.execution_id),
            reservation.record,
        )

    def test_20_execution_identity_uses_no_uuid_or_randomness(self):
        source = inspect.getsource(enforcement_module)
        tree = ast.parse(source)
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(imports.isdisjoint({"random", "secrets", "uuid"}))
        self.assertNotIn("uuid4", source)

    def test_21_execution_identity_reads_no_wall_clock(self):
        source = inspect.getsource(enforcement_module)
        tree = ast.parse(source)
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(imports.isdisjoint({"datetime", "time"}))

    def test_22_pure_authorization_modules_do_not_import_sqlite(self):
        module_names = (
            "applicability",
            "approval",
            "approver",
            "attestation",
            "authenticated_delegation",
            "binding",
            "canonical",
            "delegation",
            "domain",
            "evaluator",
            "execution",
            "execution_enforcement",
            "receipt",
            "trusted",
        )
        package = __import__("nest_authz", fromlist=["irrelevant"])
        for module_name in module_names:
            module = __import__(
                f"nest_authz.{module_name}",
                fromlist=["irrelevant"],
            )
            with self.subTest(module=module_name):
                self.assertNotIn("sqlite", inspect.getsource(module))
        self.assertTrue(hasattr(package, "SQLiteExecutionStore"))

    def test_23_many_concurrent_reservations_have_one_winner(self):
        attempt_count = 12
        stores = tuple(
            SQLiteExecutionStore(self.database_path) for _ in range(attempt_count)
        )
        barrier = threading.Barrier(attempt_count)

        def reserve(store):
            barrier.wait()
            return store.reserve(self.permit)

        with ThreadPoolExecutor(max_workers=attempt_count) as executor:
            results = tuple(executor.map(reserve, stores))

        statuses = tuple(result.status for result in results)
        self.assertEqual(
            statuses.count(ExecutionReservationStatus.NEW_RESERVATION),
            1,
        )
        self.assertEqual(
            statuses.count(ExecutionReservationStatus.EXISTING_RESERVED),
            attempt_count - 1,
        )
        self.assertEqual(
            len({result.record.execution_id for result in results}),
            1,
        )
        self.assertEqual(self._row_count(), 1)

    def test_24_distinct_permits_can_reserve_concurrently(self):
        permits = (self.permit, _permit(current_logical_time=101))
        stores = (
            SQLiteExecutionStore(self.database_path),
            SQLiteExecutionStore(self.database_path),
        )
        barrier = threading.Barrier(2)

        def reserve(arguments):
            store, permit = arguments
            barrier.wait()
            return store.reserve(permit)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(reserve, zip(stores, permits, strict=True)))

        self.assertTrue(
            all(
                result.status is ExecutionReservationStatus.NEW_RESERVATION
                for result in results
            )
        )
        self.assertEqual(self._row_count(), 2)

    def test_25_permit_b_cannot_mark_permit_a_successful(self):
        permit_a = self.permit
        permit_b = _permit(current_logical_time=101)
        execution_a = self.store.reserve(permit_a).record.execution_id

        with self.assertRaises(ExecutionPermitMismatchError):
            self.store.mark_succeeded(
                execution_a,
                permit_b,
                "operation:result:forged",
            )

    def test_26_success_replay_never_creates_another_execution(self):
        execution_id = self.store.reserve(self.permit).record.execution_id
        self.store.mark_succeeded(
            execution_id,
            self.permit,
            "operation:result:123",
        )

        replays = tuple(self.store.reserve(self.permit) for _ in range(5))

        self.assertTrue(
            all(
                replay.status is ExecutionReservationStatus.ALREADY_SUCCEEDED
                for replay in replays
            )
        )
        self.assertEqual(
            {replay.record.execution_id for replay in replays},
            {execution_id},
        )
        self.assertEqual(self._row_count(), 1)

    def test_27_new_store_cannot_bypass_durable_uniqueness(self):
        first = self.store.reserve(self.permit)
        new_store = SQLiteExecutionStore(self.database_path)

        replay = new_store.reserve(self.permit)

        self.assertIs(
            replay.status,
            ExecutionReservationStatus.EXISTING_RESERVED,
        )
        self.assertEqual(first.record.execution_id, replay.record.execution_id)
        self.assertEqual(self._row_count(), 1)

    def test_28_execution_identity_is_exact_permit_digest(self):
        execution_id = execution_id_for(self.permit)

        self.assertEqual(execution_id.permit_digest, sha256_digest(self.permit))
        self.assertEqual(
            str(execution_id),
            f"execution:{sha256_digest(self.permit)}",
        )
        with self.assertRaises(TypeError):
            ExecutionId()

    def test_29_execution_record_invariants_fail_construction(self):
        execution_id = execution_id_for(self.permit)
        digest = sha256_digest(self.permit)

        invalid_values = (
            {
                "status": ExecutionStatus.RESERVED,
                "result_reference": "unexpected",
            },
            {"status": ExecutionStatus.SUCCEEDED},
            {"status": ExecutionStatus.FAILED},
            {
                "status": ExecutionStatus.SUCCEEDED,
                "result_reference": "result:1",
                "failure_reference": "failure:1",
            },
        )
        for values in invalid_values:
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    ExecutionRecord(
                        execution_id,
                        digest,
                        **values,
                    )

    def test_30_new_types_have_stable_canonical_schemas(self):
        reservation = self.store.reserve(self.permit)
        values = (
            (
                reservation.record.execution_id,
                b"nest-authz/execution-id@1",
            ),
            (ExecutionStatus.RESERVED, b"nest-authz/execution-status@1"),
            (reservation.record, b"nest-authz/execution-record@1"),
            (
                reservation.status,
                b"nest-authz/execution-reservation-status@1",
            ),
            (
                reservation,
                b"nest-authz/execution-reservation-result@1",
            ),
        )
        for value, schema in values:
            with self.subTest(schema=schema):
                encoded = canonical_bytes(value)
                self.assertIn(schema, encoded)
                self.assertEqual(encoded, canonical_bytes(value))

    def test_31_store_satisfies_the_execution_store_port(self):
        self.assertIsInstance(self.store, ExecutionStore)

    def test_32_missing_execution_returns_none(self):
        missing = execution_id_for(_permit(current_logical_time=101))

        self.assertIsNone(self.store.get(missing))

    def test_33_reservation_results_are_immutable_and_consistent(self):
        reservation = self.store.reserve(self.permit)

        self.assertIsInstance(reservation, ExecutionReservationResult)
        with self.assertRaises(ValueError):
            ExecutionReservationResult(
                ExecutionReservationStatus.ALREADY_SUCCEEDED,
                reservation.record,
            )

    def test_34_adapter_uses_only_standard_library_sqlite(self):
        source = inspect.getsource(sqlite_store_module)
        self.assertIn("import sqlite3", source)
        self.assertNotIn("sqlalchemy", source.lower())
        self.assertNotIn("requests", source.lower())

    def test_35_in_memory_database_is_rejected_as_non_durable(self):
        with self.assertRaises(ValueError):
            SQLiteExecutionStore(":memory:")


if __name__ == "__main__":
    unittest.main()
