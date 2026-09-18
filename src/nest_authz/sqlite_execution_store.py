"""Standard-library SQLite adapter for atomic execution enforcement."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from .canonical import sha256_digest
from .domain import (
    ExecutionId,
    ExecutionPermit,
    ExecutionRecord,
    ExecutionReservationResult,
    ExecutionReservationStatus,
    ExecutionStatus,
    Sha256Digest,
)
from .execution_enforcement import execution_id_for

_SCHEMA = """
CREATE TABLE IF NOT EXISTS execution_records (
    execution_id TEXT PRIMARY KEY
        CHECK (
            length(execution_id) = 81
            AND substr(execution_id, 1, 17) = 'execution:sha256:'
        ),
    execution_permit_digest TEXT NOT NULL UNIQUE
        CHECK (
            length(execution_permit_digest) = 71
            AND substr(execution_permit_digest, 1, 7) = 'sha256:'
        ),
    status TEXT NOT NULL
        CHECK (status IN ('RESERVED', 'SUCCEEDED', 'FAILED')),
    result_reference TEXT,
    failure_reference TEXT,
    CHECK (
        (status = 'RESERVED'
            AND result_reference IS NULL
            AND failure_reference IS NULL)
        OR
        (status = 'SUCCEEDED'
            AND result_reference IS NOT NULL
            AND length(result_reference) > 0
            AND failure_reference IS NULL)
        OR
        (status = 'FAILED'
            AND result_reference IS NULL
            AND failure_reference IS NOT NULL
            AND length(failure_reference) > 0)
    )
) WITHOUT ROWID
"""

_SELECT = """
SELECT
    execution_id,
    execution_permit_digest,
    status,
    result_reference,
    failure_reference
FROM execution_records
WHERE execution_id = ?
"""


class ExecutionStoreError(RuntimeError):
    """A deterministic failure at the execution persistence boundary."""


class ExecutionRecordNotFoundError(ExecutionStoreError):
    """The requested execution identity has no durable record."""


class ExecutionPermitMismatchError(ExecutionStoreError):
    """A supplied permit does not own the requested execution record."""


class ExecutionTransitionError(ExecutionStoreError):
    """The requested durable execution transition is illegal."""


def _reference(value: object, field_name: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be a string")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError(f"{field_name} must be encodable as strict UTF-8") from error
    if not value.strip():
        raise ValueError(f"{field_name} must not be blank")
    return value


def _digest_from_text(value: object) -> Sha256Digest:
    if type(value) is not str or not value.startswith("sha256:"):
        raise ExecutionStoreError("stored execution-permit digest is malformed")
    try:
        return Sha256Digest.from_hex(value.removeprefix("sha256:"))
    except (TypeError, ValueError) as error:
        raise ExecutionStoreError(
            "stored execution-permit digest is malformed"
        ) from error


class SQLiteExecutionStore:
    """A local durable SQLite implementation of the ExecutionStore port."""

    def __init__(
        self,
        database_path: str,
        *,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._database_path = _reference(database_path, "database_path")
        if self._database_path == ":memory:":
            raise ValueError("SQLiteExecutionStore requires a durable file database")
        if type(timeout_seconds) not in (int, float) or type(timeout_seconds) is bool:
            raise TypeError("timeout_seconds must be an integer or float")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        self._timeout_seconds = float(timeout_seconds)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database_path,
            timeout=self._timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(_SCHEMA)
        except sqlite3.DatabaseError as error:
            raise ExecutionStoreError(
                "failed to initialize the SQLite execution store"
            ) from error
        finally:
            connection.close()

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.DatabaseError as error:
            if connection.in_transaction:
                connection.rollback()
            raise ExecutionStoreError(
                "SQLite execution-store transaction failed"
            ) from error
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _record_from_row(
        self,
        row: sqlite3.Row,
        execution_id: ExecutionId,
    ) -> ExecutionRecord:
        if row["execution_id"] != str(execution_id):
            raise ExecutionStoreError(
                "stored execution identity does not match its lookup key"
            )
        try:
            status = ExecutionStatus(row["status"])
            return ExecutionRecord(
                execution_id=execution_id,
                execution_permit_digest=_digest_from_text(
                    row["execution_permit_digest"]
                ),
                status=status,
                result_reference=row["result_reference"],
                failure_reference=row["failure_reference"],
            )
        except (TypeError, ValueError) as error:
            raise ExecutionStoreError(
                "stored execution record violates domain invariants"
            ) from error

    @staticmethod
    def _reservation_status(
        record: ExecutionRecord,
        *,
        inserted: bool,
    ) -> ExecutionReservationStatus:
        if inserted:
            if record.status is not ExecutionStatus.RESERVED:
                raise ExecutionStoreError(
                    "new reservation did not produce RESERVED state"
                )
            return ExecutionReservationStatus.NEW_RESERVATION
        if record.status is ExecutionStatus.RESERVED:
            return ExecutionReservationStatus.EXISTING_RESERVED
        if record.status is ExecutionStatus.SUCCEEDED:
            return ExecutionReservationStatus.ALREADY_SUCCEEDED
        return ExecutionReservationStatus.FAILED_EXISTING

    def reserve(
        self,
        execution_permit: ExecutionPermit,
    ) -> ExecutionReservationResult:
        """Atomically reserve a permit or return its durable prior state."""

        if type(execution_permit) is not ExecutionPermit:
            raise TypeError("execution_permit must be an ExecutionPermit")
        execution_id = execution_id_for(execution_permit)
        permit_digest = sha256_digest(execution_permit)

        with self._write_transaction() as connection:
            cursor = connection.execute(
                """
                INSERT INTO execution_records (
                    execution_id,
                    execution_permit_digest,
                    status,
                    result_reference,
                    failure_reference
                ) VALUES (?, ?, 'RESERVED', NULL, NULL)
                ON CONFLICT(execution_id) DO NOTHING
                """,
                (str(execution_id), str(permit_digest)),
            )
            inserted = cursor.rowcount == 1
            row = connection.execute(
                _SELECT,
                (str(execution_id),),
            ).fetchone()
            if row is None:
                raise ExecutionStoreError(
                    "reservation transaction did not produce a record"
                )
            record = self._record_from_row(row, execution_id)

        return ExecutionReservationResult(
            status=self._reservation_status(record, inserted=inserted),
            record=record,
        )

    def get(self, execution_id: ExecutionId) -> ExecutionRecord | None:
        """Load one durable execution record by exact typed identity."""

        if type(execution_id) is not ExecutionId:
            raise TypeError("execution_id must be an ExecutionId")
        connection = self._connect()
        try:
            row = connection.execute(
                _SELECT,
                (str(execution_id),),
            ).fetchone()
        except sqlite3.DatabaseError as error:
            raise ExecutionStoreError(
                "failed to read the SQLite execution store"
            ) from error
        finally:
            connection.close()
        if row is None:
            return None
        return self._record_from_row(row, execution_id)

    def _mark_terminal(
        self,
        execution_id: ExecutionId,
        execution_permit: ExecutionPermit,
        status: ExecutionStatus,
        reference: str,
    ) -> ExecutionRecord:
        if type(execution_id) is not ExecutionId:
            raise TypeError("execution_id must be an ExecutionId")
        if type(execution_permit) is not ExecutionPermit:
            raise TypeError("execution_permit must be an ExecutionPermit")
        if status is ExecutionStatus.SUCCEEDED:
            reference = _reference(reference, "result_reference")
            result_reference = reference
            failure_reference = None
        elif status is ExecutionStatus.FAILED:
            reference = _reference(reference, "failure_reference")
            result_reference = None
            failure_reference = reference
        else:
            raise ValueError("terminal status must be SUCCEEDED or FAILED")

        expected_id = execution_id_for(execution_permit)
        permit_digest = sha256_digest(execution_permit)
        if execution_id != expected_id:
            raise ExecutionPermitMismatchError(
                "execution permit does not match the execution identity"
            )

        with self._write_transaction() as connection:
            row = connection.execute(
                _SELECT,
                (str(execution_id),),
            ).fetchone()
            if row is None:
                raise ExecutionRecordNotFoundError("execution record does not exist")
            current = self._record_from_row(row, execution_id)
            if current.execution_permit_digest != permit_digest:
                raise ExecutionPermitMismatchError(
                    "execution permit does not own the execution record"
                )
            if current.status is not ExecutionStatus.RESERVED:
                raise ExecutionTransitionError(
                    f"{current.status.value} execution is terminal"
                )

            cursor = connection.execute(
                """
                UPDATE execution_records
                SET status = ?, result_reference = ?, failure_reference = ?
                WHERE execution_id = ?
                  AND execution_permit_digest = ?
                  AND status = 'RESERVED'
                """,
                (
                    status.value,
                    result_reference,
                    failure_reference,
                    str(execution_id),
                    str(permit_digest),
                ),
            )
            if cursor.rowcount != 1:
                raise ExecutionTransitionError(
                    "execution state changed before terminal transition"
                )
            updated = connection.execute(
                _SELECT,
                (str(execution_id),),
            ).fetchone()
            if updated is None:
                raise ExecutionStoreError(
                    "terminal transition lost its execution record"
                )
            record = self._record_from_row(updated, execution_id)

        return record

    def mark_succeeded(
        self,
        execution_id: ExecutionId,
        execution_permit: ExecutionPermit,
        result_reference: str,
    ) -> ExecutionRecord:
        """Transition the exact reserved execution to terminal success."""

        return self._mark_terminal(
            execution_id,
            execution_permit,
            ExecutionStatus.SUCCEEDED,
            result_reference,
        )

    def mark_failed(
        self,
        execution_id: ExecutionId,
        execution_permit: ExecutionPermit,
        failure_reference: str,
    ) -> ExecutionRecord:
        """Transition the exact reserved execution to terminal failure."""

        return self._mark_terminal(
            execution_id,
            execution_permit,
            ExecutionStatus.FAILED,
            failure_reference,
        )
