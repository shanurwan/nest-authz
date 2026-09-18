"""Nanda Town Auth plugin, scenario roles, and trace validators.

Nanda Town loads this file through the scenario ``plugin_files`` mechanism.
The plugin preserves Nanda Town's current ``sign_as``/``verify`` Auth surface:
HMAC establishes the simulated sender, while NEST AuthZ separately decides
whether tagged protected-action payloads may pass the delivery gate.
"""

from __future__ import annotations

from typing import Any

from nandatown.layers import register
from nandatown.layers.auth import HmacAuth
from nandatown.sim.agents import SimAgent, role
from nandatown.sim.validators import _check, validator

from nest_authz import (
    ApprovalRequirement,
    ApprovalStatus,
    ApproverAuthorizationStatus,
    ApproverSubjectPrincipalBinding,
    AuthorizationRequest,
    AuthorizationState,
    DecisionReceipt,
    ExecutionPermit,
    ExecutionRecord,
    ExecutionReservationResult,
    ExecutionReservationStatus,
    ExecutionStatus,
    Outcome,
    PendingApproval,
    Principal,
    RevocationSet,
    Subject,
    TrustedExecutionAuthorizationStatus,
    approve_requirement,
    check_approver_authorization,
    create_decision_receipt,
    create_pending_approval,
    execution_id_for,
    revalidate_trusted_for_execution,
    sha256_digest,
)
from nest_authz.integrations.nandatown.adapter import (
    NandaAuthorityProfile,
    NandaTownAuthorizationAdapter,
    build_demo_security_material,
)


_PLUGIN_ID = "nest-authz.v1"
_MARKER = "nest_authz"
_GATEWAY = "authorization-gateway"
_CONTROLLER = "scenario-controller"


def _text(value: object, field_name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{field_name} must be a nonblank string")
    value.encode("utf-8", errors="strict")
    return value


class _ScenarioExecutionStore:
    """Deterministic in-run reservation ledger for this scenario.

    This is intentionally not presented as durable persistence. It lets the
    Tier-1 simulator exercise the real ExecutionId and reservation result
    types without introducing an environment-selected database path. It does
    not implement the complete ExecutionStore port. Production/local
    durability remains SQLiteExecutionStore's job.
    """

    def __init__(self) -> None:
        self._records: dict[object, ExecutionRecord] = {}

    @property
    def record_count(self) -> int:
        return len(self._records)

    def reserve(self, permit: ExecutionPermit) -> ExecutionReservationResult:
        if type(permit) is not ExecutionPermit:
            raise TypeError("permit must be an ExecutionPermit")
        execution_id = execution_id_for(permit)
        existing = self._records.get(execution_id)
        if existing is None:
            record = ExecutionRecord(
                execution_id=execution_id,
                execution_permit_digest=sha256_digest(permit),
                status=ExecutionStatus.RESERVED,
            )
            self._records[execution_id] = record
            status = ExecutionReservationStatus.NEW_RESERVATION
        else:
            record = existing
            if record.status is ExecutionStatus.RESERVED:
                status = ExecutionReservationStatus.EXISTING_RESERVED
            elif record.status is ExecutionStatus.SUCCEEDED:
                status = ExecutionReservationStatus.ALREADY_SUCCEEDED
            else:
                status = ExecutionReservationStatus.FAILED_EXISTING
        return ExecutionReservationResult(status, record)


class _Operation:
    __slots__ = (
        "profile",
        "request",
        "receipt",
        "approval",
        "execution_permit",
    )

    def __init__(
        self,
        *,
        profile: NandaAuthorityProfile,
        request: AuthorizationRequest,
        receipt: DecisionReceipt,
        approval: PendingApproval,
    ) -> None:
        self.profile = profile
        self.request = request
        self.receipt = receipt
        self.approval = approval
        self.execution_permit: ExecutionPermit | None = None


@register("auth", _PLUGIN_ID)
class NestAuthzAuth:
    """Authenticate Town messages, then authorize tagged protected actions."""

    def __init__(self, engine) -> None:
        self.engine = engine
        self._authentication = HmacAuth(engine)
        self.material = build_demo_security_material()
        self.adapter = NandaTownAuthorizationAdapter(self.material)
        self._operations: dict[str, _Operation] = {}
        self._revoked_grants: set[str] = set()
        self._execution_store = _ScenarioExecutionStore()
        manager = Principal("principal:authorized-manager")
        self._approver_bindings = {
            "authorized-manager": ApproverSubjectPrincipalBinding(
                Subject("agent:authorized-manager"),
                manager,
            ),
            "mallory": ApproverSubjectPrincipalBinding(
                Subject("agent:mallory"),
                Principal("principal:mallory"),
            ),
        }

    def sign_as(self, name: str, payload: Any) -> str:
        """Use Nanda Town's deterministic reference authentication."""

        return self._authentication.sign_as(name, payload)

    def verify(
        self,
        claimed_name: str,
        payload: Any,
        signature: str,
        subject: str = "",
    ) -> bool:
        """Authenticate first; authorize only explicitly tagged payloads."""

        if not self._authentication.verify(
            claimed_name,
            payload,
            signature,
            subject,
        ):
            return False
        if not isinstance(payload, dict) or _MARKER not in payload:
            return True
        marker = payload[_MARKER]
        if not isinstance(marker, dict):
            self._emit_rejection(subject, claimed_name, "MALFORMED_MARKER")
            return False
        command = marker.get("command")
        if command == "authorize":
            return self._authorize(claimed_name, marker)
        if command == "approve":
            return self._approve(claimed_name, marker)
        if command in {"prepare_execution", "revoke_and_revalidate"}:
            return self._prepare_execution(claimed_name, marker)
        if command == "reserve_execution":
            return self._reserve_execution(claimed_name, marker)
        self._emit_rejection(subject, claimed_name, "UNSUPPORTED_COMMAND")
        return False

    def _logical_time(self) -> int:
        # Nanda Town logical seconds are mapped to exact integer milliseconds.
        return int(round(self.engine.now * 1000))

    def _state(self) -> AuthorizationState:
        return AuthorizationState(
            self._logical_time(),
            RevocationSet(tuple(self._revoked_grants)),
        )

    def _emit_rejection(
        self,
        subject: str,
        actor: str,
        status: str,
    ) -> None:
        self.engine.emit(
            "nest-authz",
            "nest_adapter_rejected",
            subject or actor,
            {"requesting_agent": actor, "status": status},
        )

    def _authorize(self, claimed_name: str, marker: dict[str, Any]) -> bool:
        operation_id = _text(marker.get("operation_id"), "operation_id")
        profile_id = _text(
            marker.get("authority_profile"),
            "authority_profile",
        )
        action = _text(marker.get("action"), "action")
        resource = _text(marker.get("resource"), "resource")
        amount = marker.get("amount")
        result = self.adapter.authorize_action(
            agent_name=claimed_name,
            authority_profile=profile_id,
            action=action,
            resource=resource,
            context={"amount": amount},
            state=self._state(),
        )

        trusted = result.trusted_authorization
        decision = trusted.decision if trusted is not None else None
        applicability = (
            decision.evidence.authority_applicability
            if decision is not None
            else None
        )
        authentication = result.delegation_authentication
        effective_grant = None
        if result.authenticated_authority is not None:
            effective_grant = (
                result.authenticated_authority.verified_authority.grant_id
            )
        detail = {
            "requesting_agent": claimed_name,
            "action": action,
            "resource": resource,
            "amount": amount,
            "outcome": result.outcome.value,
            "status": result.status,
            "delegation_status": (
                authentication.status.value
                if authentication is not None
                else "NOT_AUTHENTICATED"
            ),
            "applicability_status": (
                applicability.status.value
                if applicability is not None
                else "NOT_EVALUATED"
            ),
            "effective_grant": effective_grant,
            "request_digest": str(sha256_digest(result.request)),
            "policy_bundle_digest": str(
                sha256_digest(self.material.trusted_policy.bundle)
            ),
            "reason_codes": (
                [reason.code for reason in decision.reasons]
                if decision is not None
                else [result.status]
            ),
        }
        self.engine.emit(
            "nest-authz",
            "nest_authorization_decided",
            operation_id,
            detail,
        )

        if result.outcome is Outcome.APPROVAL_REQUIRED:
            if trusted is None or result.authority_profile is None:
                raise RuntimeError(
                    "approval outcome requires complete trusted evidence"
                )
            receipt = create_decision_receipt(trusted.decision)
            self._operations[operation_id] = _Operation(
                profile=result.authority_profile,
                request=result.request,
                receipt=receipt,
                approval=create_pending_approval(
                    receipt,
                    self._logical_time(),
                ),
            )
        return result.outcome is Outcome.PERMIT

    def _approve(self, claimed_name: str, marker: dict[str, Any]) -> bool:
        operation_id = _text(marker.get("operation_id"), "operation_id")
        operation = self._operations.get(operation_id)
        binding = self._approver_bindings.get(claimed_name)
        if operation is None or binding is None:
            status = (
                "OPERATION_NOT_FOUND"
                if operation is None
                else "APPROVER_BINDING_NOT_CONFIGURED"
            )
            self.engine.emit(
                "nest-authz",
                "nest_approval_authorization",
                operation_id,
                {
                    "requesting_agent": claimed_name,
                    "status": status,
                    "requirement": marker.get("requirement"),
                },
            )
            return False

        required = self.material.approval_requirement
        attempted_code = _text(
            marker.get("requirement"),
            "approval requirement",
        )
        attempted = (
            required
            if attempted_code == required.code
            else ApprovalRequirement(
                attempted_code,
                required.allowed_principals,
            )
        )
        actor = Subject(f"agent:{claimed_name}")
        authorization = check_approver_authorization(
            actor,
            binding,
            required,
            attempted,
        )
        self.engine.emit(
            "nest-authz",
            "nest_approval_authorization",
            operation_id,
            {
                "requesting_agent": claimed_name,
                "bound_principal": binding.principal.identifier,
                "requirement": attempted_code,
                "status": authorization.status.value,
            },
        )
        if authorization.status is not ApproverAuthorizationStatus.AUTHORIZED:
            return False

        operation.approval = approve_requirement(
            operation.approval,
            required,
            authorization,
            self._logical_time(),
        )
        self.engine.emit(
            "nest-authz",
            "nest_approval_state",
            operation_id,
            {
                "status": operation.approval.status.value,
                "requirement": required.code,
                "approved_by": binding.principal.identifier,
                "receipt_digest": str(operation.approval.receipt_digest),
            },
        )
        return operation.approval.status is ApprovalStatus.APPROVED

    def _prepare_execution(
        self,
        claimed_name: str,
        marker: dict[str, Any],
    ) -> bool:
        operation_id = _text(marker.get("operation_id"), "operation_id")
        if claimed_name != _CONTROLLER:
            self._emit_rejection(
                operation_id,
                claimed_name,
                "CONTROL_SUBJECT_MISMATCH",
            )
            return False
        operation = self._operations.get(operation_id)
        if operation is None:
            self._emit_rejection(
                operation_id,
                claimed_name,
                "OPERATION_NOT_FOUND",
            )
            return False

        if marker.get("command") == "revoke_and_revalidate":
            revocations = marker.get("revoke_grants", ())
            if not isinstance(revocations, list) or any(
                type(item) is not str or not item.strip()
                for item in revocations
            ):
                self._emit_rejection(
                    operation_id,
                    claimed_name,
                    "MALFORMED_REVOCATION_SET",
                )
                return False
            self._revoked_grants.update(revocations)

        result = revalidate_trusted_for_execution(
            operation.receipt,
            operation.approval,
            operation.request,
            self.material.trusted_policy,
            operation.profile.chain,
            self._state(),
            operation.profile.subject_binding,
            operation.profile.grant_attestations,
            self.material.trust_store,
            self.material.principal_key_registry,
            self.material.trusted_authority_roots,
        )
        authentication = result.delegation_authentication
        execution = result.execution_authorization
        permit = execution.execution_permit if execution is not None else None
        operation.execution_permit = permit
        self.engine.emit(
            "nest-authz",
            "nest_execution_revalidation",
            operation_id,
            {
                "requesting_agent": claimed_name,
                "status": result.status.value,
                "delegation_status": authentication.status.value,
                "authority_status": (
                    authentication.authority_validation.status.value
                ),
                "execution_status": (
                    execution.status.value
                    if execution is not None
                    else "NOT_EVALUATED"
                ),
                "offending_grant": authentication.offending_grant_id,
                "revoked_grants": sorted(self._revoked_grants),
                "execution_permit_digest": (
                    str(sha256_digest(permit)) if permit is not None else None
                ),
            },
        )
        return (
            result.status is TrustedExecutionAuthorizationStatus.AUTHORIZED
            and permit is not None
        )

    def _reserve_execution(
        self,
        claimed_name: str,
        marker: dict[str, Any],
    ) -> bool:
        operation_id = _text(marker.get("operation_id"), "operation_id")
        if claimed_name != _CONTROLLER:
            self._emit_rejection(
                operation_id,
                claimed_name,
                "CONTROL_SUBJECT_MISMATCH",
            )
            return False
        operation = self._operations.get(operation_id)
        if operation is None or operation.execution_permit is None:
            self._emit_rejection(
                operation_id,
                claimed_name,
                "EXECUTION_PERMIT_NOT_AVAILABLE",
            )
            return False

        reservation = self._execution_store.reserve(
            operation.execution_permit
        )
        self.engine.emit(
            "nest-authz",
            "nest_execution_reservation",
            operation_id,
            {
                "requesting_agent": claimed_name,
                "status": reservation.status.value,
                "execution_id": str(reservation.record.execution_id),
                "execution_permit_digest": str(
                    reservation.record.execution_permit_digest
                ),
                "logical_execution_count": (
                    self._execution_store.record_count
                ),
            },
        )
        return (
            reservation.status
            is ExecutionReservationStatus.NEW_RESERVATION
        )


@role("nest_authz_actor")
class NestAuthzActor(SimAgent):
    """Schedule deterministic tagged requests from one configured actor."""

    def on_start(self) -> None:
        for step in self.config.get("steps", []):
            delay = step["at"]
            marker = {key: value for key, value in step.items() if key != "at"}
            body = {_MARKER: marker}
            self.api.later(
                delay,
                lambda body=body: self.api.send(
                    _GATEWAY,
                    "nest_authz_request",
                    body,
                ),
            )


@role("nest_authz_gateway")
class NestAuthzGateway(SimAgent):
    """Record only requests admitted by the Auth-layer enforcement gate."""

    def handle_nest_authz_request(self, message: dict[str, Any]) -> None:
        marker = message["body"][_MARKER]
        command = marker["command"]
        operation_id = marker["operation_id"]
        self.api.observe(
            "nest_request_admitted",
            operation_id,
            {
                "requesting_agent": message["sender"],
                "command": command,
            },
        )


def _events(trace, kind: str, subject: str):
    return trace.find(kind, subject=subject)


def _ids(events) -> list[str]:
    return [event.event_id for event in events]


@validator("nest_authz_delegated_authority")
def delegated_authority_validator(spec, trace):
    """Prove the scenario's security claims from non-vacuous trace facts."""

    in_scope = _events(
        trace,
        "nest_authorization_decided",
        "operation:subagent-700",
    )
    in_scope_admitted = _events(
        trace,
        "nest_request_admitted",
        "operation:subagent-700",
    )
    in_scope_ok = (
        len(in_scope) == 1
        and in_scope[0].detail.get("outcome") == "PERMIT"
        and in_scope[0].detail.get("amount") == 700
        and in_scope[0].detail.get("effective_grant")
        == "grant:finance-payment-subagent"
        and len(in_scope_admitted) == 1
    )

    over_bound = _events(
        trace,
        "nest_authorization_decided",
        "operation:subagent-4000",
    )
    over_bound_ok = (
        len(over_bound) == 1
        and over_bound[0].detail.get("amount") == 4000
        and over_bound[0].detail.get("outcome") == "DENY"
        and over_bound[0].detail.get("applicability_status")
        == "BOUND_EXCEEDED"
        and not _events(
            trace,
            "nest_request_admitted",
            "operation:subagent-4000",
        )
    )

    approval_decisions = _events(
        trace,
        "nest_authorization_decided",
        "operation:finance-primary",
    )
    approved = _events(
        trace,
        "nest_approval_state",
        "operation:finance-primary",
    )
    approval_ok = (
        len(approval_decisions) == 1
        and approval_decisions[0].detail.get("outcome")
        == "APPROVAL_REQUIRED"
        and len(approved) == 1
        and approved[0].detail.get("status") == "APPROVED"
        and approved[0].detail.get("approved_by")
        == "principal:authorized-manager"
    )

    mallory = [
        event
        for event in _events(
            trace,
            "nest_approval_authorization",
            "operation:finance-primary",
        )
        if event.detail.get("requesting_agent") == "mallory"
    ]
    mallory_ok = (
        len(mallory) == 1
        and mallory[0].detail.get("status") == "PRINCIPAL_NOT_ALLOWED"
    )

    revoked = _events(
        trace,
        "nest_execution_revalidation",
        "operation:finance-primary",
    )
    revoked_ok = (
        len(revoked) == 1
        and revoked[0].detail.get("status")
        == "DELEGATION_AUTHENTICATION_FAILED"
        and revoked[0].detail.get("authority_status") == "REVOKED"
        and revoked[0].detail.get("offending_grant")
        == "grant:alice-finance"
        and revoked[0].detail.get("execution_permit_digest") is None
    )

    fresh_decision = _events(
        trace,
        "nest_authorization_decided",
        "operation:finance-replay",
    )
    fresh_approved = _events(
        trace,
        "nest_approval_state",
        "operation:finance-replay",
    )
    reservations = _events(
        trace,
        "nest_execution_reservation",
        "operation:finance-replay",
    )
    reservation_statuses = [
        event.detail.get("status") for event in reservations
    ]
    execution_ids = {
        event.detail.get("execution_id") for event in reservations
    }
    replay_ok = (
        len(fresh_decision) == 1
        and fresh_decision[0].detail.get("outcome")
        == "APPROVAL_REQUIRED"
        and len(fresh_approved) == 1
        and len(reservations) == 2
        and reservation_statuses
        == ["NEW_RESERVATION", "EXISTING_RESERVED"]
        and len(execution_ids) == 1
        and all(
            event.detail.get("logical_execution_count") == 1
            for event in reservations
        )
    )

    return [
        _check(
            "in_scope_delegated_action",
            in_scope_ok,
            _ids(in_scope + in_scope_admitted),
            "the amount-700 subagent attempt must exist and be admitted",
            "the attenuated subagent authority permits amount 700",
        ),
        _check(
            "out_of_scope_denied",
            over_bound_ok,
            _ids(over_bound),
            "the amount-4000 subagent attempt must exist and be denied by its bound",
            "the attempted scope excess was denied before delivery",
        ),
        _check(
            "approval_flow",
            approval_ok,
            _ids(approval_decisions + approved),
            "the Finance Agent approval path must be requested and approved",
            "the authorized manager satisfied the exact requirement",
        ),
        _check(
            "unauthorized_approver_rejected",
            mallory_ok,
            _ids(mallory),
            "Mallory's approval attempt must exist and be rejected",
            "the unauthorized approver attempt was explicitly rejected",
        ),
        _check(
            "revoked_authority_blocked",
            revoked_ok,
            _ids(revoked),
            "the approved operation must be revalidated after relevant revocation",
            "fresh revalidation denied the revoked authority",
        ),
        _check(
            "single_logical_execution",
            replay_ok,
            _ids(fresh_decision + fresh_approved + reservations),
            "the fresh approved operation must reserve once and reject its replay",
            "one permit produced one logical execution despite replay",
        ),
    ]
