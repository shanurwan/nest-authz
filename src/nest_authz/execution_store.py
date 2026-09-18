"""Persistence port for durable single-use execution enforcement."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .domain import (
    ExecutionId,
    ExecutionPermit,
    ExecutionRecord,
    ExecutionReservationResult,
)


@runtime_checkable
class ExecutionStore(Protocol):
    """Narrow storage boundary for atomic execution reservation and state."""

    def reserve(
        self,
        execution_permit: ExecutionPermit,
    ) -> ExecutionReservationResult:
        """Atomically reserve the exact permit or return its existing state."""

        ...

    def get(self, execution_id: ExecutionId) -> ExecutionRecord | None:
        """Return the durable logical record for an execution identity."""

        ...

    def mark_succeeded(
        self,
        execution_id: ExecutionId,
        execution_permit: ExecutionPermit,
        result_reference: str,
    ) -> ExecutionRecord:
        """Atomically transition the exact reserved permit to success."""

        ...

    def mark_failed(
        self,
        execution_id: ExecutionId,
        execution_permit: ExecutionPermit,
        failure_reference: str,
    ) -> ExecutionRecord:
        """Atomically transition the exact reserved permit to failure."""

        ...
