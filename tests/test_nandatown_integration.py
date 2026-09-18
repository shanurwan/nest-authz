import ast
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from nest_authz import (
    AuthorizationState,
    DelegationAuthenticationStatus,
    GrantAttestationSet,
    Outcome,
    Principal,
    Subject,
    SubjectAuthorityBindingStatus,
    SubjectPrincipalBinding,
)
from nest_authz.integrations.nandatown import (
    NandaTownAuthorizationAdapter,
    build_demo_security_material,
)

try:
    from nandatown.bundle import load_bundle
    from nandatown.layers import resolve
    from nandatown.sim.runner import run_lab
    from nandatown.sim.scenario import load_scenario_file
    from nandatown.sim.validators import evaluate_scenario
except ModuleNotFoundError:
    load_bundle = None
    resolve = None
    run_lab = None
    load_scenario_file = None
    evaluate_scenario = None


_ROOT = Path(__file__).parents[1]
_INTEGRATION = _ROOT / "src" / "nest_authz" / "integrations" / "nandatown"
_SCENARIO = _INTEGRATION / "delegated_authority.yaml"


def _profile(material, identifier):
    return next(
        item for item in material.authority_profiles if item.identifier == identifier
    )


def _with_profile(material, replacement):
    profiles = tuple(
        replacement if item.identifier == replacement.identifier else item
        for item in material.authority_profiles
    )
    return replace(material, authority_profiles=profiles)


def _authorize(material=None, *, amount=700):
    adapter = NandaTownAuthorizationAdapter(material or build_demo_security_material())
    return adapter.authorize_action(
        agent_name="payment-subagent",
        authority_profile="payment-subagent",
        action="payments.transfer",
        resource="account:alice",
        context={"amount": amount},
        state=AuthorizationState(1_000),
    )


class NandaTownAdapterTests(unittest.TestCase):
    def test_01_adapter_maps_nanda_identity_exactly(self):
        result = _authorize()

        self.assertEqual(
            result.request.subject,
            Subject("agent:payment-subagent"),
        )
        self.assertEqual(
            result.authority_profile.subject_binding,
            SubjectPrincipalBinding(
                Subject("agent:payment-subagent"),
                Principal("principal:payment-subagent"),
            ),
        )
        self.assertIs(result.outcome, Outcome.PERMIT)

    def test_02_authentication_is_not_authorization(self):
        material = build_demo_security_material()
        result = NandaTownAuthorizationAdapter(material).authorize_action(
            agent_name="mallory",
            authority_profile="payment-subagent",
            action="payments.transfer",
            resource="account:alice",
            context={"amount": 700},
            state=AuthorizationState(1_000),
        )

        self.assertIs(result.outcome, Outcome.DENY)
        self.assertEqual(result.status, "AUTHORITY_PROFILE_NOT_CONFIGURED")
        self.assertIsNone(result.trusted_authorization)

    def test_03_trusted_policy_wrapper_is_required(self):
        material = build_demo_security_material()

        with self.assertRaisesRegex(TypeError, "TrustedPolicyBundle"):
            replace(
                material,
                trusted_policy=material.trusted_policy.bundle,
            )
        with self.assertRaisesRegex(TypeError, "NandaSecurityMaterial"):
            NandaTownAuthorizationAdapter(material.trusted_policy)

    def test_04_authenticated_delegation_is_required(self):
        material = build_demo_security_material()
        profile = _profile(material, "payment-subagent")
        material = _with_profile(
            material,
            replace(profile, grant_attestations=GrantAttestationSet()),
        )

        result = _authorize(material)

        self.assertIs(result.outcome, Outcome.DENY)
        self.assertIs(
            result.delegation_authentication.status,
            DelegationAuthenticationStatus.MISSING_ATTESTATION,
        )
        self.assertIsNone(result.authenticated_authority)
        self.assertIsNone(result.trusted_authorization)

    def test_05_holder_binding_is_enforced(self):
        material = build_demo_security_material()
        profile = _profile(material, "payment-subagent")
        bad_binding = SubjectPrincipalBinding(
            Subject("agent:unrelated"),
            Principal("principal:payment-subagent"),
        )
        material = _with_profile(
            material,
            replace(profile, subject_binding=bad_binding),
        )

        result = _authorize(material)

        self.assertIs(result.outcome, Outcome.DENY)
        self.assertIsNotNone(result.trusted_authorization)
        evidence = (
            result.trusted_authorization.decision.evidence.subject_authority_binding
        )
        self.assertIs(
            evidence.status,
            SubjectAuthorityBindingStatus.SUBJECT_MISMATCH,
        )

    def test_06_amount_700_subagent_path_permits(self):
        self.assertIs(_authorize(amount=700).outcome, Outcome.PERMIT)

    def test_07_amount_4000_subagent_path_denies(self):
        result = _authorize(amount=4000)

        self.assertIs(result.outcome, Outcome.DENY)
        self.assertEqual(
            result.trusted_authorization.decision.evidence.authority_applicability.status.value,
            "BOUND_EXCEEDED",
        )

    def test_08_material_copies_and_orders_authority_profiles(self):
        material = build_demo_security_material()
        source = list(reversed(material.authority_profiles))
        copied = replace(material, authority_profiles=source)
        source.clear()

        self.assertEqual(
            tuple(item.identifier for item in copied.authority_profiles),
            tuple(sorted(item.identifier for item in material.authority_profiles)),
        )


@unittest.skipIf(run_lab is None, "Nanda Town optional dependency not installed")
class NandaTownScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary_directory = tempfile.TemporaryDirectory()
        cls.bundle_dir, cls.result = run_lab(
            str(_SCENARIO),
            cls.temporary_directory.name,
            seed=42,
        )
        cls.bundle = load_bundle(cls.bundle_dir)
        cls.events = cls.bundle["events"]
        cls.run_id = cls.bundle["run"].run_id
        cls.spec = cls.bundle["profile"]

    @classmethod
    def tearDownClass(cls):
        cls.temporary_directory.cleanup()

    @classmethod
    def events_for(cls, kind, subject=None):
        return [
            event
            for event in cls.events
            if event.kind == kind and (subject is None or event.subject == subject)
        ]

    def stage(self, name):
        return next(stage for stage in self.result.stages if stage.name == name)

    def test_09_scenario_uses_real_auth_plugin_interface(self):
        plugin = resolve("auth", "nest-authz.v1")

        self.assertTrue(callable(plugin.sign_as))
        self.assertTrue(callable(plugin.verify))
        self.assertEqual(self.spec.layers["auth"], "nest-authz.v1")
        self.assertEqual(self.spec.plugin_files, [str(_INTEGRATION / "plugin.py")])

    def test_10_approval_required_path_is_traced(self):
        events = self.events_for(
            "nest_authorization_decided",
            "operation:finance-primary",
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].detail["outcome"], "APPROVAL_REQUIRED")
        self.assertEqual(events[0].detail["effective_grant"], "grant:alice-finance")

    def test_11_mallory_approval_is_rejected(self):
        events = [
            event
            for event in self.events_for(
                "nest_approval_authorization",
                "operation:finance-primary",
            )
            if event.detail["requesting_agent"] == "mallory"
        ]

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].detail["status"], "PRINCIPAL_NOT_ALLOWED")

    def test_12_authorized_manager_approval_is_accepted(self):
        events = self.events_for(
            "nest_approval_state",
            "operation:finance-primary",
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].detail["status"], "APPROVED")
        self.assertEqual(
            events[0].detail["approved_by"],
            "principal:authorized-manager",
        )

    def test_13_revoked_before_execution_is_denied(self):
        events = self.events_for(
            "nest_execution_revalidation",
            "operation:finance-primary",
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].detail["authority_status"], "REVOKED")
        self.assertEqual(
            events[0].detail["status"],
            "DELEGATION_AUTHENTICATION_FAILED",
        )
        self.assertIsNone(events[0].detail["execution_permit_digest"])

    def test_14_replay_creates_no_second_logical_execution(self):
        events = self.events_for(
            "nest_execution_reservation",
            "operation:finance-replay",
        )

        self.assertEqual(
            [event.detail["status"] for event in events],
            ["NEW_RESERVATION", "EXISTING_RESERVED"],
        )
        self.assertEqual(
            len({event.detail["execution_id"] for event in events}),
            1,
        )
        self.assertEqual(
            {event.detail["logical_execution_count"] for event in events},
            {1},
        )

    def test_15_trace_contains_each_adversarial_attempt(self):
        self.assertTrue(
            self.events_for(
                "nest_authorization_decided",
                "operation:subagent-4000",
            )
        )
        self.assertTrue(
            self.events_for(
                "nest_approval_authorization",
                "operation:finance-primary",
            )
        )
        self.assertTrue(
            self.events_for(
                "nest_execution_revalidation",
                "operation:finance-primary",
            )
        )
        self.assertEqual(
            len(
                self.events_for(
                    "nest_execution_reservation",
                    "operation:finance-replay",
                )
            ),
            2,
        )

    def test_16_validator_detects_intentionally_unsafe_trace(self):
        unsafe = []
        for event in self.events:
            if (
                event.kind == "nest_authorization_decided"
                and event.subject == "operation:subagent-4000"
            ):
                detail = dict(event.detail)
                detail["outcome"] = "PERMIT"
                detail["applicability_status"] = "APPLICABLE"
                event = event.model_copy(update={"detail": detail})
            unsafe.append(event)

        result = evaluate_scenario(self.spec, self.run_id, unsafe)
        stage = next(
            item for item in result.stages if item.name == "out_of_scope_denied"
        )

        self.assertEqual(stage.status, "failed")
        self.assertTrue(stage.evidence)

    def test_17_hardened_end_to_end_scenario_passes_all_validators(self):
        expected = {
            "in_scope_delegated_action",
            "out_of_scope_denied",
            "approval_flow",
            "unauthorized_approver_rejected",
            "revoked_authority_blocked",
            "single_logical_execution",
        }
        stages = {stage.name: stage.status for stage in self.result.stages}

        self.assertEqual(self.result.verdict, "passed")
        self.assertTrue(expected <= stages.keys())
        self.assertTrue(all(stages[name] == "passed" for name in expected))

    def test_18_private_material_and_signatures_are_absent_from_trace(self):
        records = [event.model_dump() for event in self.events]
        encoded = json.dumps(records, sort_keys=True)

        def keys(value):
            if isinstance(value, dict):
                for key, nested in value.items():
                    yield key
                    yield from keys(nested)
            elif isinstance(value, list):
                for nested in value:
                    yield from keys(nested)

        self.assertNotIn("private_key", encoded.lower())
        self.assertNotIn("signature", set(keys(records)))
        self.assertNotIn("11" * 32, encoded)
        self.assertNotIn("22" * 32, encoded)
        self.assertNotIn("33" * 32, encoded)


def _authorization_semantics(bundle_dir):
    bundle = load_bundle(bundle_dir)
    return tuple(
        {key: value for key, value in event.model_dump().items() if key != "run_id"}
        for event in bundle["events"]
        if event.kind.startswith("nest_")
    )


@unittest.skipIf(run_lab is None, "Nanda Town optional dependency not installed")
class NandaTownDeterminismTests(unittest.TestCase):
    def test_19_repeated_scenario_has_equal_authorization_trace(self):
        with tempfile.TemporaryDirectory() as directory:
            first, _ = run_lab(str(_SCENARIO), directory, seed=42)
            second, _ = run_lab(str(_SCENARIO), directory, seed=42)

            self.assertEqual(
                _authorization_semantics(first),
                _authorization_semantics(second),
            )

    def test_20_seeds_do_not_change_authorization_semantics(self):
        traces = []
        with tempfile.TemporaryDirectory() as directory:
            for seed in (42, 7, 1337):
                bundle, _ = run_lab(str(_SCENARIO), directory, seed=seed)
                traces.append(_authorization_semantics(bundle))

        self.assertEqual(traces[0], traces[1])
        self.assertEqual(traces[0], traces[2])


class NandaTownSourceHygieneTests(unittest.TestCase):
    def test_21_no_wall_clock_random_uuid_network_or_llm_dependency(self):
        forbidden_imports = {
            "datetime",
            "httpx",
            "openai",
            "random",
            "requests",
            "socket",
            "time",
            "urllib",
            "uuid",
        }
        for path in (_INTEGRATION / "adapter.py", _INTEGRATION / "plugin.py"):
            source = path.read_text(encoding="utf-8")
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
            with self.subTest(path=path.name):
                self.assertTrue(imports.isdisjoint(forbidden_imports))
                self.assertNotIn("datetime.now", source)
                self.assertNotIn("time.time", source)
                self.assertNotIn("uuid.uuid4", source)

    def test_22_core_import_does_not_require_nandatown(self):
        code = """
import builtins
original = builtins.__import__
def blocked(name, *args, **kwargs):
    if name == 'nandatown' or name.startswith('nandatown.'):
        raise AssertionError('core import attempted to load Nanda Town')
    return original(name, *args, **kwargs)
builtins.__import__ = blocked
import nest_authz
print(nest_authz.__name__)
"""

        output = subprocess.check_output(
            [sys.executable, "-c", code],
            text=True,
        )

        self.assertEqual(output.strip(), "nest_authz")


if __name__ == "__main__":
    unittest.main()
