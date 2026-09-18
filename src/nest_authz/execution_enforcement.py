"""Pure execution identity derivation for durable enforcement adapters."""

from __future__ import annotations

from .canonical import sha256_digest
from .domain import ExecutionId, ExecutionPermit, _EXECUTION_ID_TOKEN


def execution_id_for(execution_permit: ExecutionPermit) -> ExecutionId:
    """Derive the sole logical execution identity for an exact permit."""

    if type(execution_permit) is not ExecutionPermit:
        raise TypeError("execution_permit must be an ExecutionPermit")
    return ExecutionId._from_permit_digest(
        sha256_digest(execution_permit),
        _token=_EXECUTION_ID_TOKEN,
    )
