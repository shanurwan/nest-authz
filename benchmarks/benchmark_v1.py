"""Informational, reproducible NEST AuthZ v1 microbenchmark.

This is not a production throughput test and intentionally has no pass/fail
latency threshold.
"""

from __future__ import annotations

import argparse
import platform
import sys
from collections.abc import Callable
from statistics import median
from time import perf_counter_ns

from nest_authz import (
    ApproverSubjectPrincipalBinding,
    AuthorizationRequest,
    AuthorizationState,
    Principal,
    RequestContext,
    Subject,
    approve_requirement,
    authenticate_delegation_chain,
    authorize_trusted,
    canonical_bytes,
    check_approver_authorization,
    create_decision_receipt,
    create_pending_approval,
    evaluate,
    revalidate_trusted_for_execution,
    validate_authority,
)
from nest_authz.integrations.nandatown import build_demo_security_material


def _measure(
    function: Callable[[], object],
    *,
    iterations: int,
    repeats: int,
) -> float:
    for _ in range(min(25, iterations)):
        function()
    samples: list[float] = []
    for _ in range(repeats):
        started = perf_counter_ns()
        for _ in range(iterations):
            function()
        elapsed = perf_counter_ns() - started
        samples.append(elapsed / iterations / 1_000)
    return median(samples)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    if args.iterations < 1 or args.repeats < 1:
        parser.error("iterations and repeats must be positive")

    material = build_demo_security_material()
    policy = material.trusted_policy.bundle
    subagent_profile = material.profile("payment-subagent", "payment-subagent")
    finance_profile = material.profile("finance-primary", "finance-agent")
    if subagent_profile is None or finance_profile is None:
        raise AssertionError("demo authority profiles are missing")
    state = AuthorizationState(1_000)

    subagent_request = AuthorizationRequest(
        Subject("agent:payment-subagent"),
        subagent_profile.chain.grants[-1].scope.action,
        subagent_profile.chain.grants[-1].scope.resource,
        RequestContext({"amount": 700}),
        None,
    )
    subagent_validation = validate_authority(subagent_profile.chain, state)
    subagent_authentication = authenticate_delegation_chain(
        subagent_profile.chain,
        state,
        subagent_profile.grant_attestations,
        material.trust_store,
        material.principal_key_registry,
        material.trusted_authority_roots,
    )
    authenticated = subagent_authentication.authenticated_authority
    verified = subagent_validation.verified_authority
    if authenticated is None or verified is None:
        raise AssertionError("demo subagent authority did not validate")

    finance_request = AuthorizationRequest(
        Subject("agent:finance-agent"),
        finance_profile.chain.grants[-1].scope.action,
        finance_profile.chain.grants[-1].scope.resource,
        RequestContext({"amount": 4_000}),
        None,
    )
    finance_authentication = authenticate_delegation_chain(
        finance_profile.chain,
        state,
        finance_profile.grant_attestations,
        material.trust_store,
        material.principal_key_registry,
        material.trusted_authority_roots,
    )
    finance_authority = finance_authentication.authenticated_authority
    if finance_authority is None:
        raise AssertionError("demo finance authority did not authenticate")
    finance_result = authorize_trusted(
        finance_request,
        material.trusted_policy,
        finance_authority,
        finance_profile.subject_binding,
    )
    receipt = create_decision_receipt(finance_result.decision)
    pending = create_pending_approval(receipt, state.logical_time)
    requirement = material.approval_requirement
    approver = Subject("agent:authorized-manager")
    approver_binding = ApproverSubjectPrincipalBinding(
        approver,
        Principal("principal:authorized-manager"),
    )
    approver_authorization = check_approver_authorization(
        approver,
        approver_binding,
        requirement,
        requirement,
    )
    approved = approve_requirement(
        pending,
        requirement,
        approver_authorization,
        state.logical_time + 1,
    )

    operations: tuple[tuple[str, Callable[[], object]], ...] = (
        ("canonical policy bundle", lambda: canonical_bytes(policy)),
        (
            "policy evaluation (2 rules / 6 conditions)",
            lambda: evaluate(
                subagent_request,
                policy,
                verified,
                subagent_profile.subject_binding,
            ),
        ),
        (
            "delegation validation (2 hops)",
            lambda: validate_authority(subagent_profile.chain, state),
        ),
        (
            "authenticated delegation (2 hops)",
            lambda: authenticate_delegation_chain(
                subagent_profile.chain,
                state,
                subagent_profile.grant_attestations,
                material.trust_store,
                material.principal_key_registry,
                material.trusted_authority_roots,
            ),
        ),
        (
            "trusted authorization",
            lambda: authorize_trusted(
                subagent_request,
                material.trusted_policy,
                authenticated,
                subagent_profile.subject_binding,
            ),
        ),
        (
            "trusted execution revalidation",
            lambda: revalidate_trusted_for_execution(
                receipt,
                approved,
                finance_request,
                material.trusted_policy,
                finance_profile.chain,
                state,
                finance_profile.subject_binding,
                finance_profile.grant_attestations,
                material.trust_store,
                material.principal_key_registry,
                material.trusted_authority_roots,
            ),
        ),
    )

    print(f"Python: {sys.version.split()[0]}")
    print(f"Platform: {platform.platform()}")
    print("Policy: 1 policy, 2 rules, 6 conditions")
    print("Delegation: 2 grants for multi-hop operations")
    print(f"Samples: median of {args.repeats} x {args.iterations} iterations")
    for name, operation in operations:
        microseconds = _measure(
            operation,
            iterations=args.iterations,
            repeats=args.repeats,
        )
        print(f"{name}: {microseconds:.1f} us/op")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
