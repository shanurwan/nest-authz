import ast
import inspect
import os
import subprocess
import sys
import unittest

import nest_authz.delegation as delegation_module
from nest_authz import (
    Action,
    AuthorityGrant,
    AuthorityScope,
    AuthorityValidationResult,
    AuthorityValidationStatus,
    AuthorizationState,
    DelegationChain,
    Principal,
    Resource,
    RevocationSet,
    Sha256Digest,
    VerifiedAuthority,
    canonical_bytes,
    sha256_digest,
    validate_authority,
)


def _scope(
    *,
    action: str = "payments.transfer",
    resource: str = "account:alice",
    max_amount: int = 5000,
    extra_bounds=(),
) -> AuthorityScope:
    return AuthorityScope(
        Action(action),
        Resource(resource),
        (("max_amount", max_amount), *extra_bounds),
    )


def _grant(
    identifier: str,
    grantor: str,
    grantee: str,
    *,
    scope: AuthorityScope | None = None,
    parent: str | None = None,
    valid_from: int = 10,
    valid_until: int = 100,
) -> AuthorityGrant:
    return AuthorityGrant(
        identifier=identifier,
        grantor=Principal(grantor),
        grantee=Principal(grantee),
        scope=scope or _scope(),
        parent_grant_id=parent,
        valid_from=valid_from,
        valid_until=valid_until,
    )


def _root(**overrides) -> AuthorityGrant:
    values = {
        "identifier": "grant:root",
        "grantor": "issuer:root",
        "grantee": "principal:alice",
    }
    values.update(overrides)
    return _grant(**values)


def _one_hop(
    *,
    child_scope: AuthorityScope | None = None,
) -> DelegationChain:
    root = _root()
    child = _grant(
        "grant:child",
        "principal:alice",
        "principal:bob",
        scope=child_scope or _scope(max_amount=1000),
        parent=root.identifier,
    )
    return DelegationChain((root, child))


def _state(
    logical_time: int = 50,
    revoked=(),
) -> AuthorizationState:
    return AuthorizationState(logical_time, RevocationSet(revoked))


class DelegatedAuthorityValidationTests(unittest.TestCase):
    def assert_status(
        self,
        chain: DelegationChain,
        status: AuthorityValidationStatus,
        *,
        state: AuthorizationState | None = None,
        offending: str | None = None,
    ) -> AuthorityValidationResult:
        result = validate_authority(chain, state or _state())
        self.assertIs(result.status, status)
        self.assertEqual(result.offending_grant_id, offending)
        if status is AuthorityValidationStatus.VALID:
            self.assertIsInstance(result.verified_authority, VerifiedAuthority)
        else:
            self.assertIsNone(result.verified_authority)
        return result

    def test_valid_root_authority(self):
        chain = DelegationChain((_root(),))

        result = self.assert_status(chain, AuthorityValidationStatus.VALID)

        self.assertEqual(result.verified_authority.grant_id, "grant:root")
        self.assertEqual(
            result.verified_authority.principal,
            Principal("principal:alice"),
        )
        self.assertEqual(result.chain_digest, sha256_digest(chain))
        self.assertEqual(result.state_digest, sha256_digest(_state()))

    def test_valid_one_hop_delegation(self):
        result = self.assert_status(
            _one_hop(),
            AuthorityValidationStatus.VALID,
        )
        self.assertEqual(result.verified_authority.grant_id, "grant:child")
        self.assertEqual(
            result.verified_authority.principal,
            Principal("principal:bob"),
        )

    def test_valid_multi_hop_delegation(self):
        root = _root()
        child = _grant(
            "grant:child",
            "principal:alice",
            "principal:bob",
            scope=_scope(max_amount=2000),
            parent=root.identifier,
        )
        leaf = _grant(
            "grant:leaf",
            "principal:bob",
            "principal:carol",
            scope=_scope(max_amount=500),
            parent=child.identifier,
        )

        result = self.assert_status(
            DelegationChain((root, child, leaf)),
            AuthorityValidationStatus.VALID,
        )
        self.assertEqual(result.verified_authority.grant_id, "grant:leaf")

    def test_equal_scope_delegation_is_valid(self):
        self.assert_status(
            _one_hop(child_scope=_scope()),
            AuthorityValidationStatus.VALID,
        )

    def test_narrower_numeric_bound_is_valid(self):
        self.assert_status(
            _one_hop(child_scope=_scope(max_amount=1000)),
            AuthorityValidationStatus.VALID,
        )

    def test_additional_numeric_bound_is_valid_attenuation(self):
        self.assert_status(
            _one_hop(
                child_scope=_scope(
                    max_amount=1000,
                    extra_bounds=(("max_daily_count", 3),),
                )
            ),
            AuthorityValidationStatus.VALID,
        )

    def test_broader_numeric_bound_is_rejected(self):
        self.assert_status(
            _one_hop(child_scope=_scope(max_amount=10000)),
            AuthorityValidationStatus.BROADENED_AUTHORITY,
            offending="grant:child",
        )

    def test_omitting_parent_bound_is_rejected(self):
        root = _root()
        child = _grant(
            "grant:child",
            "principal:alice",
            "principal:bob",
            scope=AuthorityScope(
                Action("payments.transfer"),
                Resource("account:alice"),
            ),
            parent=root.identifier,
        )
        self.assert_status(
            DelegationChain((root, child)),
            AuthorityValidationStatus.BROADENED_AUTHORITY,
            offending="grant:child",
        )

    def test_changed_action_is_rejected(self):
        self.assert_status(
            _one_hop(child_scope=_scope(action="payments.refund")),
            AuthorityValidationStatus.BROADENED_AUTHORITY,
            offending="grant:child",
        )

    def test_changed_resource_is_rejected(self):
        self.assert_status(
            _one_hop(child_scope=_scope(resource="account:bob")),
            AuthorityValidationStatus.BROADENED_AUTHORITY,
            offending="grant:child",
        )

    def test_broken_grantor_grantee_provenance_is_rejected(self):
        root = _root()
        forged = _grant(
            "grant:child",
            "principal:mallory",
            "principal:bob",
            scope=_scope(max_amount=1000),
            parent=root.identifier,
        )
        self.assert_status(
            DelegationChain((root, forged)),
            AuthorityValidationStatus.BROKEN_PROVENANCE,
            offending="grant:child",
        )

    def test_forged_parent_reference_is_rejected(self):
        root = _root()
        forged = _grant(
            "grant:child",
            "principal:alice",
            "principal:bob",
            scope=_scope(max_amount=1000),
            parent="grant:not-the-parent",
        )
        self.assert_status(
            DelegationChain((root, forged)),
            AuthorityValidationStatus.BROKEN_PROVENANCE,
            offending="grant:child",
        )

    def test_root_with_parent_reference_is_rejected(self):
        root = _root(parent="grant:outside-chain")
        self.assert_status(
            DelegationChain((root,)),
            AuthorityValidationStatus.BROKEN_PROVENANCE,
            offending="grant:root",
        )

    def test_duplicate_grant_identifier_is_rejected(self):
        root = _root()
        duplicate = _grant(
            root.identifier,
            "principal:alice",
            "principal:bob",
            scope=_scope(max_amount=1000),
            parent=root.identifier,
        )
        self.assert_status(
            DelegationChain((root, duplicate)),
            AuthorityValidationStatus.INVALID_CHAIN,
            offending="grant:root",
        )

    def test_direct_parent_reference_cycle_is_rejected(self):
        cyclic = _root(parent="grant:root")
        self.assert_status(
            DelegationChain((cyclic,)),
            AuthorityValidationStatus.CYCLE,
            offending="grant:root",
        )

    def test_self_delegation_principal_cycle_is_rejected(self):
        cyclic = _root(grantor="principal:alice")
        self.assert_status(
            DelegationChain((cyclic,)),
            AuthorityValidationStatus.CYCLE,
            offending="grant:root",
        )

    def test_multi_hop_parent_reference_cycle_is_rejected(self):
        first = _root(parent="grant:leaf")
        second = _grant(
            "grant:child",
            "principal:alice",
            "principal:bob",
            parent=first.identifier,
        )
        leaf = _grant(
            "grant:leaf",
            "principal:bob",
            "principal:carol",
            parent=second.identifier,
        )
        self.assert_status(
            DelegationChain((first, second, leaf)),
            AuthorityValidationStatus.CYCLE,
            offending="grant:root",
        )

    def test_revoked_leaf_is_rejected(self):
        self.assert_status(
            _one_hop(),
            AuthorityValidationStatus.REVOKED,
            state=_state(revoked=("grant:child",)),
            offending="grant:child",
        )

    def test_revoked_parent_invalidates_descendant(self):
        self.assert_status(
            _one_hop(),
            AuthorityValidationStatus.REVOKED,
            state=_state(revoked=("grant:root",)),
            offending="grant:root",
        )

    def test_revoked_root_is_not_hidden_behind_valid_descendants(self):
        root = _root()
        child = _grant(
            "grant:child",
            "principal:alice",
            "principal:bob",
            scope=_scope(max_amount=2000),
            parent=root.identifier,
        )
        leaf = _grant(
            "grant:leaf",
            "principal:bob",
            "principal:carol",
            scope=_scope(max_amount=1000),
            parent=child.identifier,
        )
        self.assert_status(
            DelegationChain((root, child, leaf)),
            AuthorityValidationStatus.REVOKED,
            state=_state(revoked=("grant:root",)),
            offending="grant:root",
        )

    def test_before_valid_from_is_rejected(self):
        self.assert_status(
            DelegationChain((_root(),)),
            AuthorityValidationStatus.NOT_YET_VALID,
            state=_state(logical_time=9),
            offending="grant:root",
        )

    def test_exactly_valid_from_is_accepted(self):
        self.assert_status(
            DelegationChain((_root(),)),
            AuthorityValidationStatus.VALID,
            state=_state(logical_time=10),
        )

    def test_immediately_before_valid_until_is_accepted(self):
        self.assert_status(
            DelegationChain((_root(),)),
            AuthorityValidationStatus.VALID,
            state=_state(logical_time=99),
        )

    def test_exactly_valid_until_is_expired(self):
        self.assert_status(
            DelegationChain((_root(),)),
            AuthorityValidationStatus.EXPIRED,
            state=_state(logical_time=100),
            offending="grant:root",
        )

    def test_expired_ancestor_invalidates_otherwise_current_leaf(self):
        root = _root(valid_until=40)
        child = _grant(
            "grant:child",
            "principal:alice",
            "principal:bob",
            scope=_scope(max_amount=1000),
            parent=root.identifier,
            valid_from=20,
            valid_until=80,
        )
        self.assert_status(
            DelegationChain((root, child)),
            AuthorityValidationStatus.EXPIRED,
            state=_state(logical_time=50),
            offending="grant:root",
        )

    def test_same_chain_and_state_always_yield_equal_result(self):
        chain = _one_hop()
        state = _state()

        first = validate_authority(chain, state)
        second = validate_authority(chain, state)

        self.assertEqual(first, second)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(sha256_digest(first), sha256_digest(second))

    def test_nonsemantic_constructor_order_does_not_change_identity(self):
        left_bounds = [["z_limit", 9], ["max_amount", 5000]]
        right_bounds = [["max_amount", 5000], ["z_limit", 9]]
        left_scope = AuthorityScope(
            Action("payments.transfer"),
            Resource("account:alice"),
            left_bounds,
        )
        right_scope = AuthorityScope(
            Action("payments.transfer"),
            Resource("account:alice"),
            right_bounds,
        )
        left_state = _state(revoked=("grant:z", "grant:a"))
        right_state = _state(revoked=("grant:a", "grant:z"))

        self.assertEqual(left_scope, right_scope)
        self.assertEqual(canonical_bytes(left_scope), canonical_bytes(right_scope))
        self.assertEqual(sha256_digest(left_scope), sha256_digest(right_scope))
        self.assertEqual(left_state, right_state)
        self.assertEqual(sha256_digest(left_state), sha256_digest(right_state))

    def test_constructor_inputs_are_defensively_copied(self):
        bounds = [["max_amount", 5000]]
        revoked = ["grant:old"]
        grants = [
            _root(
                scope=AuthorityScope(
                    Action("payments.transfer"), Resource("account:alice"), bounds
                )
            )
        ]
        scope = grants[0].scope
        chain = DelegationChain(grants)
        revocations = RevocationSet(revoked)
        before = (
            sha256_digest(scope),
            sha256_digest(chain),
            sha256_digest(revocations),
        )

        bounds[0][1] = 10000
        bounds.append(["daily", 100])
        revoked.append("grant:new")
        grants.append(_root(identifier="grant:other"))

        self.assertEqual(
            before,
            (
                sha256_digest(scope),
                sha256_digest(chain),
                sha256_digest(revocations),
            ),
        )

    def test_python_hash_seed_cannot_change_identity_or_result(self):
        script = "\n".join(
            (
                "from nest_authz import *",
                "scope = AuthorityScope(Action('payments.transfer'), Resource('account:alice'), {'z': 9, 'max_amount': 5000})",
                "root = AuthorityGrant('grant:root', Principal('issuer:root'), Principal('principal:alice'), scope, None, 10, 100)",
                "chain = DelegationChain((root,))",
                "state = AuthorizationState(50, RevocationSet(('grant:z', 'grant:a')))",
                "result = validate_authority(chain, state)",
                "print(result.status.value)",
                "print(canonical_bytes(result).hex())",
                "print(str(sha256_digest(result)))",
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
            outputs.append(completed.stdout)

        self.assertEqual(outputs[0], outputs[1])
        self.assertTrue(outputs[0].startswith("VALID\n"))

    def test_scope_widening_several_hops_down_is_rejected(self):
        root = _root()
        child = _grant(
            "grant:child",
            "principal:alice",
            "principal:bob",
            scope=_scope(max_amount=1000),
            parent=root.identifier,
        )
        widened_leaf = _grant(
            "grant:leaf",
            "principal:bob",
            "principal:carol",
            scope=_scope(max_amount=2000),
            parent=child.identifier,
        )
        self.assert_status(
            DelegationChain((root, child, widened_leaf)),
            AuthorityValidationStatus.BROADENED_AUTHORITY,
            offending="grant:leaf",
        )

    def test_amplification_can_never_produce_verified_authority(self):
        result = validate_authority(
            _one_hop(child_scope=_scope(max_amount=10000)),
            _state(),
        )

        self.assertIs(result.status, AuthorityValidationStatus.BROADENED_AUTHORITY)
        self.assertIsNone(result.verified_authority)
        with self.assertRaisesRegex(TypeError, "only be created by validation"):
            VerifiedAuthority()

    def test_bool_is_not_an_integer_scope_bound_or_logical_time(self):
        with self.assertRaisesRegex(TypeError, "exact integers"):
            _scope(max_amount=True)
        with self.assertRaisesRegex(TypeError, "logical_time"):
            AuthorizationState(True)
        with self.assertRaisesRegex(TypeError, "valid_from"):
            _root(valid_from=False)
        with self.assertRaisesRegex(TypeError, "valid_until"):
            _root(valid_until=True)

    def test_malformed_logical_validity_boundaries_fail_construction(self):
        for valid_from, valid_until in ((10, 10), (11, 10)):
            with self.subTest(valid_from=valid_from, valid_until=valid_until):
                with self.assertRaisesRegex(ValueError, "less than"):
                    _root(valid_from=valid_from, valid_until=valid_until)

    def test_local_domain_invariants_reject_malformed_values(self):
        with self.assertRaisesRegex(ValueError, "must not be blank"):
            Principal(" ")
        with self.assertRaisesRegex(ValueError, "grant identifier"):
            _root(identifier=" ")
        with self.assertRaisesRegex(ValueError, "parent grant identifier"):
            _root(parent=" ")
        with self.assertRaisesRegex(ValueError, "at least one grant"):
            DelegationChain(())
        with self.assertRaisesRegex(ValueError, "duplicates"):
            RevocationSet(("grant:one", "grant:one"))
        with self.assertRaisesRegex(ValueError, "duplicate name"):
            AuthorityScope(
                Action("payments.transfer"),
                Resource("account:alice"),
                (("max_amount", 1), ("max_amount", 2)),
            )

    def test_result_invariants_prevent_unverified_success(self):
        digest = Sha256Digest(bytes(32))
        with self.assertRaisesRegex(ValueError, "require verified authority"):
            AuthorityValidationResult(
                AuthorityValidationStatus.VALID,
                digest,
                digest,
            )
        with self.assertRaisesRegex(ValueError, "cannot carry"):
            valid = validate_authority(DelegationChain((_root(),)), _state())
            AuthorityValidationResult(
                AuthorityValidationStatus.REVOKED,
                valid.chain_digest,
                valid.state_digest,
                "grant:root",
                valid.verified_authority,
            )

    def test_new_domain_types_have_stable_canonical_schemas(self):
        chain = DelegationChain((_root(),))
        state = _state()
        result = validate_authority(chain, state)
        values_and_schemas = (
            (chain.grants[0].grantor, b"nest-authz/principal@1"),
            (chain.grants[0].scope, b"nest-authz/authority-scope@1"),
            (chain.grants[0], b"nest-authz/authority-grant@1"),
            (chain, b"nest-authz/delegation-chain@1"),
            (state.revocations, b"nest-authz/revocation-set@1"),
            (state, b"nest-authz/authorization-state@1"),
            (
                AuthorityValidationStatus.VALID,
                b"nest-authz/authority-validation-status@1",
            ),
            (result.verified_authority, b"nest-authz/verified-authority@1"),
            (result, b"nest-authz/authority-validation-result@1"),
        )

        for value, schema in values_and_schemas:
            with self.subTest(schema=schema):
                encoded = canonical_bytes(value)
                self.assertIn(schema, encoded)
                self.assertEqual(encoded, canonical_bytes(value))
                self.assertEqual(len(sha256_digest(value).value), 32)

    def test_validator_source_reads_no_external_or_wall_clock_state(self):
        tree = ast.parse(inspect.getsource(delegation_module))
        forbidden_modules = {
            "datetime",
            "os",
            "pathlib",
            "random",
            "secrets",
            "socket",
            "sqlite3",
            "time",
            "urllib",
        }
        imported_modules = set()
        called_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_modules.update(
                    alias.name.split(".")[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                called_names.add(node.func.id)

        self.assertTrue(imported_modules.isdisjoint(forbidden_modules))
        self.assertNotIn("open", called_names)
        self.assertNotIn("eval", called_names)
        self.assertNotIn("exec", called_names)


if __name__ == "__main__":
    unittest.main()
