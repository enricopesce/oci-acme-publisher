"""Durable, PEM-free SQLite state required for idempotent reconciliation."""

from __future__ import annotations

import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

from .clock import utc_now_rfc3339
from .migrations import apply_migrations


class OperationType(StrEnum):
    """Operation categories persisted for recovery."""

    BOOTSTRAP = "BOOTSTRAP"
    RENEW = "RENEW"
    PUBLISH = "PUBLISH"
    RECONCILE = "RECONCILE"
    AUDIT = "AUDIT"
    ROLLBACK = "ROLLBACK"


class OperationState(StrEnum):
    """Persisted state-machine states, including terminal failures."""

    DISCOVERED = "DISCOVERED"
    CONFIG_VALIDATED = "CONFIG_VALIDATED"
    HTTP01_PREFLIGHT_OK = "HTTP01_PREFLIGHT_OK"
    ACME_COMPLETED = "ACME_COMPLETED"
    LOCAL_CERT_VALIDATED = "LOCAL_CERT_VALIDATED"
    OCI_RECONCILED = "OCI_RECONCILED"
    OCI_PENDING_UPLOADED = "OCI_PENDING_UPLOADED"
    OCI_PENDING_VERIFIED = "OCI_PENDING_VERIFIED"
    OCI_CURRENT_CONFIRMED = "OCI_CURRENT_CONFIRMED"
    AUDIT_PENDING = "AUDIT_PENDING"
    AUDIT_SUCCESS = "AUDIT_SUCCESS"
    COMPLETED = "COMPLETED"
    CONFIG_FAILED = "CONFIG_FAILED"
    HTTP01_PREFLIGHT_FAILED = "HTTP01_PREFLIGHT_FAILED"
    ACME_FAILED = "ACME_FAILED"
    LOCAL_VALIDATION_FAILED = "LOCAL_VALIDATION_FAILED"
    OCI_UPLOAD_FAILED = "OCI_UPLOAD_FAILED"
    OCI_VERSION_FAILED = "OCI_VERSION_FAILED"
    OCI_PROMOTION_FAILED = "OCI_PROMOTION_FAILED"
    AUDIT_FAILED = "AUDIT_FAILED"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    MANUAL_INTERVENTION_REQUIRED = "MANUAL_INTERVENTION_REQUIRED"


_TERMINAL_STATES = (
    OperationState.COMPLETED,
    OperationState.CONFIG_FAILED,
    OperationState.HTTP01_PREFLIGHT_FAILED,
    OperationState.ACME_FAILED,
    OperationState.LOCAL_VALIDATION_FAILED,
    OperationState.OCI_UPLOAD_FAILED,
    OperationState.OCI_VERSION_FAILED,
    OperationState.OCI_PROMOTION_FAILED,
    OperationState.AUDIT_FAILED,
    OperationState.ROLLBACK_FAILED,
    OperationState.MANUAL_INTERVENTION_REQUIRED,
)


@dataclass(frozen=True, slots=True)
class Operation:
    """A safe subset of durable recovery data."""

    operation_id: str
    certificate_id: str
    operation_type: OperationType
    state: OperationState
    local_fingerprint: str | None
    oci_certificate_ocid: str | None
    oci_version_number: int | None


@dataclass(frozen=True, slots=True)
class CertificateState:
    """Safe last-known certificate facts for status output."""

    certificate_id: str
    last_local_fingerprint: str | None
    last_oci_current_fingerprint: str | None
    last_oci_current_version: int | None
    last_successful_renewal_at: str | None
    last_successful_publication_at: str | None
    last_successful_audit_at: str | None
    last_error_code: str | None
    updated_at: str


class StateStore:
    """Transactional state store; it never accepts PEM or key material."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    @classmethod
    def open(cls, path: Path) -> StateStore:
        """Open a mode-0600 database with WAL and required SQLite safeguards."""
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        os.close(descriptor)
        os.chmod(path, 0o600)
        # Reconciliation runs blocking OCI work in one dedicated executor thread.
        # The store is opened by the CLI thread before it is handed to that worker;
        # SQLite's default same-thread guard would reject this otherwise.  Each
        # operation uses a transaction and the publisher serializes reconciliation
        # per process, while WAL/busy_timeout coordinate independent processes.
        connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        apply_migrations(connection)
        return cls(connection)

    def close(self) -> None:
        """Close the SQLite connection."""
        self._connection.close()

    @classmethod
    def open_read_only(cls, path: Path) -> StateStore:
        """Open an existing state database without creating or migrating anything."""
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        connection.execute("PRAGMA foreign_keys=ON")
        return cls(connection)

    def start_operation(
        self,
        certificate_id: str,
        operation_type: OperationType,
        *,
        local_fingerprint: str | None = None,
        oci_certificate_ocid: str | None = None,
    ) -> Operation:
        """Persist the state before the caller performs a side effect."""
        operation_id = str(uuid.uuid4())
        now = utc_now_rfc3339()
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO operations(
                    operation_id, certificate_id, operation_type, state, local_fingerprint,
                    oci_certificate_ocid, started_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    operation_id,
                    certificate_id,
                    operation_type.value,
                    OperationState.DISCOVERED.value,
                    local_fingerprint,
                    oci_certificate_ocid,
                    now,
                    now,
                ),
            )
        return Operation(
            operation_id,
            certificate_id,
            operation_type,
            OperationState.DISCOVERED,
            local_fingerprint,
            oci_certificate_ocid,
            None,
        )

    def transition(
        self,
        operation_id: str,
        state: OperationState,
        *,
        oci_version_number: int | None = None,
        oci_certificate_ocid: str | None = None,
        opc_request_id: str | None = None,
        error_code: str | None = None,
        error_message_redacted: str | None = None,
    ) -> None:
        """Persist a state transition before/after the relevant external action."""
        if state in _TERMINAL_STATES:
            completed_at = utc_now_rfc3339()
        else:
            completed_at = None
        with self._connection:
            cursor = self._connection.execute(
                """
                UPDATE operations
                SET state = ?, oci_version_number = COALESCE(?, oci_version_number),
                    oci_certificate_ocid = COALESCE(?, oci_certificate_ocid),
                    opc_request_id = COALESCE(?, opc_request_id), error_code = ?,
                    error_message_redacted = ?, updated_at = ?, completed_at = ?
                WHERE operation_id = ?
                """,
                (
                    state.value,
                    oci_version_number,
                    oci_certificate_ocid,
                    opc_request_id,
                    error_code,
                    error_message_redacted,
                    utc_now_rfc3339(),
                    completed_at,
                    operation_id,
                ),
            )
        if cursor.rowcount != 1:
            raise KeyError("operation does not exist")

    def active_operations(self, certificate_id: str) -> tuple[Operation, ...]:
        """Return nonterminal operations for crash recovery decisions."""
        query = (
            "SELECT operation_id, certificate_id, operation_type, state, local_fingerprint, "
            "oci_certificate_ocid, oci_version_number "
            "FROM operations WHERE certificate_id = ? "
            "AND state NOT IN (?, ?, ?, ?, ?, ?, "
            "?, ?, ?, ?, ?) ORDER BY started_at ASC"
        )
        rows = self._connection.execute(
            query,
            (certificate_id, *(state.value for state in _TERMINAL_STATES)),
        )
        return tuple(
            Operation(
                operation_id=row[0],
                certificate_id=row[1],
                operation_type=OperationType(row[2]),
                state=OperationState(row[3]),
                local_fingerprint=row[4],
                oci_certificate_ocid=row[5],
                oci_version_number=row[6],
            )
            for row in rows
        )

    def confirmed_oci_certificate_ocid(self, certificate_id: str) -> str | None:
        """Return the last OCI identity durably confirmed by this publisher."""
        row = self._connection.execute(
            "SELECT oci_certificate_ocid FROM operations "
            "WHERE certificate_id = ? AND state = ? AND oci_certificate_ocid IS NOT NULL "
            "ORDER BY completed_at DESC LIMIT 1",
            (certificate_id, OperationState.COMPLETED.value),
        ).fetchone()
        return row[0] if row is not None and isinstance(row[0], str) else None

    def record_publication_success(
        self,
        certificate_id: str,
        *,
        local_fingerprint: str,
        current_fingerprint: str,
        current_version: int,
    ) -> None:
        """Upsert the last confirmed local/remote agreement without sensitive data."""
        now = utc_now_rfc3339()
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO certificate_state(
                    certificate_id, last_local_fingerprint, last_oci_current_fingerprint,
                    last_oci_current_version, last_successful_publication_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(certificate_id) DO UPDATE SET
                    last_local_fingerprint = excluded.last_local_fingerprint,
                    last_oci_current_fingerprint = excluded.last_oci_current_fingerprint,
                    last_oci_current_version = excluded.last_oci_current_version,
                    last_successful_publication_at = excluded.last_successful_publication_at,
                    last_error_code = NULL,
                    updated_at = excluded.updated_at
                """,
                (certificate_id, local_fingerprint, current_fingerprint, current_version, now, now),
            )

    def complete_reconciled_operations(
        self,
        certificate_id: str,
        *,
        local_fingerprint: str,
        current_version: int,
        excluding_operation_id: str,
    ) -> int:
        """Close interrupted operations once OCI CURRENT proves the same local material won."""
        terminal_states = tuple(state.value for state in _TERMINAL_STATES)
        now = utc_now_rfc3339()
        with self._connection:
            cursor = self._connection.execute(
                """
                UPDATE operations
                SET state = ?, oci_version_number = ?, error_code = NULL,
                    error_message_redacted = NULL, updated_at = ?, completed_at = ?
                WHERE certificate_id = ? AND local_fingerprint = ? AND operation_id != ?
                  AND state NOT IN (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    OperationState.COMPLETED.value,
                    current_version,
                    now,
                    now,
                    certificate_id,
                    local_fingerprint,
                    excluding_operation_id,
                    *terminal_states,
                ),
            )
        return cursor.rowcount

    def record_audit_success(self, certificate_id: str) -> None:
        """Persist only the successful audit timestamp, never endpoint certificate material."""
        now = utc_now_rfc3339()
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO certificate_state(
                    certificate_id, last_successful_audit_at, updated_at
                ) VALUES (?, ?, ?)
                ON CONFLICT(certificate_id) DO UPDATE SET
                    last_successful_audit_at = excluded.last_successful_audit_at,
                    last_error_code = NULL,
                    updated_at = excluded.updated_at
                """,
                (certificate_id, now, now),
            )

    def complete_interrupted_audits(
        self, certificate_id: str, *, excluding_operation_id: str
    ) -> int:
        """Close stale audit attempts once a newer audit has independently succeeded.

        An audit has no OCI mutation to reconcile.  A process crash can therefore
        leave only an ``AUDIT_PENDING`` row behind; the next successful audit is
        the durable proof that this certificate's configured endpoint is again
        observable.  Never close the active attempt itself.
        """
        now = utc_now_rfc3339()
        with self._connection:
            cursor = self._connection.execute(
                """
                UPDATE operations
                SET state = ?, error_code = NULL, error_message_redacted = NULL,
                    updated_at = ?, completed_at = ?
                WHERE certificate_id = ? AND operation_type = ?
                  AND state = ? AND operation_id != ?
                """,
                (
                    OperationState.COMPLETED.value,
                    now,
                    now,
                    certificate_id,
                    OperationType.AUDIT.value,
                    OperationState.AUDIT_PENDING.value,
                    excluding_operation_id,
                ),
            )
        return cursor.rowcount

    def record_rollback_success(
        self, certificate_id: str, *, current_fingerprint: str, current_version: int
    ) -> None:
        """Record OCI CURRENT after rollback without overwriting the local lineage fact."""
        now = utc_now_rfc3339()
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO certificate_state(
                    certificate_id, last_oci_current_fingerprint,
                    last_oci_current_version, updated_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(certificate_id) DO UPDATE SET
                    last_oci_current_fingerprint = excluded.last_oci_current_fingerprint,
                    last_oci_current_version = excluded.last_oci_current_version,
                    last_error_code = NULL,
                    updated_at = excluded.updated_at
                """,
                (certificate_id, current_fingerprint, current_version, now),
            )

    def record_renewal_success(self, certificate_id: str) -> None:
        """Persist the renewal timestamp independently from the OCI publication timestamp."""
        now = utc_now_rfc3339()
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO certificate_state(
                    certificate_id, last_successful_renewal_at, updated_at
                ) VALUES (?, ?, ?)
                ON CONFLICT(certificate_id) DO UPDATE SET
                    last_successful_renewal_at = excluded.last_successful_renewal_at,
                    last_error_code = NULL,
                    updated_at = excluded.updated_at
                """,
                (certificate_id, now, now),
            )

    def should_send_alert(
        self, dedup_key: str, status: str, *, minimum_repeat_interval_minutes: int
    ) -> bool:
        """Return whether a safe alert event is outside its durable cooldown window."""
        row = self._connection.execute(
            "SELECT last_sent_at, last_status FROM alert_dedup WHERE dedup_key = ?", (dedup_key,)
        ).fetchone()
        if row is None or row[1] != status:
            return True
        try:
            last_sent_at = datetime.fromisoformat(row[0].replace("Z", "+00:00"))
        except (AttributeError, ValueError):
            return True
        cutoff = datetime.now(UTC) - timedelta(minutes=minimum_repeat_interval_minutes)
        return last_sent_at < cutoff

    def record_alert_sent(self, dedup_key: str, status: str) -> None:
        """Record only event identity and time after a notification is delivered."""
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO alert_dedup(dedup_key, last_sent_at, last_status)
                VALUES (?, ?, ?)
                ON CONFLICT(dedup_key) DO UPDATE SET
                    last_sent_at = excluded.last_sent_at,
                    last_status = excluded.last_status
                """,
                (dedup_key, utc_now_rfc3339(), status),
            )

    def certificate_state(self, certificate_id: str) -> CertificateState | None:
        """Return last-known safe state for one configured certificate."""
        row = self._connection.execute(
            """
            SELECT certificate_id, last_local_fingerprint, last_oci_current_fingerprint,
                   last_oci_current_version, last_successful_renewal_at,
                   last_successful_publication_at, last_successful_audit_at,
                   last_error_code, updated_at
            FROM certificate_state WHERE certificate_id = ?
            """,
            (certificate_id,),
        ).fetchone()
        if row is None:
            return None
        return CertificateState(*row)

    def operation_counts(self, certificate_id: str) -> tuple[tuple[str, str, int], ...]:
        """Return aggregate operation facts suitable for metrics, never operation payloads."""
        rows = self._connection.execute(
            """
            SELECT operation_type, state, COUNT(*)
            FROM operations
            WHERE certificate_id = ?
            GROUP BY operation_type, state
            """,
            (certificate_id,),
        )
        return tuple((str(row[0]), str(row[1]), int(row[2])) for row in rows)

    def average_completed_operation_durations(
        self, certificate_id: str
    ) -> tuple[tuple[str, float], ...]:
        """Return average completed durations by operation type in seconds."""
        rows = self._connection.execute(
            """
            SELECT operation_type,
                   AVG((julianday(completed_at) - julianday(started_at)) * 86400.0)
            FROM operations
            WHERE certificate_id = ? AND completed_at IS NOT NULL
            GROUP BY operation_type
            """,
            (certificate_id,),
        )
        return tuple((str(row[0]), float(row[1])) for row in rows if row[1] is not None)

    def known_oci_versions(self, certificate_id: str) -> int:
        """Count distinct OCI version numbers observed by this publisher."""
        row = self._connection.execute(
            """
            SELECT COUNT(DISTINCT oci_version_number)
            FROM operations
            WHERE certificate_id = ? AND oci_version_number IS NOT NULL
            """,
            (certificate_id,),
        ).fetchone()
        return int(row[0]) if row is not None else 0
