from __future__ import annotations

import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from oci_acme_publisher.state_store import OperationState, OperationType, StateStore


def test_state_store_migrates_persists_and_tracks_active_operation(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite3"
    store = StateStore.open(database)
    try:
        operation = store.start_operation("main-site", OperationType.RENEW, local_fingerprint="abc")
        assert operation.state is OperationState.DISCOVERED
        store.transition(
            operation.operation_id, OperationState.OCI_PENDING_UPLOADED, oci_version_number=4
        )
        active = store.active_operations("main-site")
        assert active[0].oci_version_number == 4
        store.transition(operation.operation_id, OperationState.COMPLETED)
        assert store.active_operations("main-site") == ()
    finally:
        store.close()
    assert stat.S_IMODE(database.stat().st_mode) == 0o600


def test_state_store_records_audit_success_without_certificate_material(tmp_path: Path) -> None:
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        store.record_audit_success("main-site")
        state = store.certificate_state("main-site")
    finally:
        store.close()

    assert state is not None
    assert state.last_successful_audit_at is not None
    assert state.last_local_fingerprint is None


def test_state_store_deduplicates_alerts_within_the_cooldown(tmp_path: Path) -> None:
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        assert store.should_send_alert(
            "AUDIT_FAILED:main-site", "AUDIT_FAILED", minimum_repeat_interval_minutes=60
        )
        store.record_alert_sent("AUDIT_FAILED:main-site", "AUDIT_FAILED")
        assert not store.should_send_alert(
            "AUDIT_FAILED:main-site", "AUDIT_FAILED", minimum_repeat_interval_minutes=60
        )
        assert store.should_send_alert(
            "AUDIT_FAILED:main-site", "RECOVERED", minimum_repeat_interval_minutes=60
        )
    finally:
        store.close()


def test_state_store_records_renewal_success_independently(tmp_path: Path) -> None:
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        store.record_renewal_success("main-site")
        state = store.certificate_state("main-site")
    finally:
        store.close()

    assert state is not None
    assert state.last_successful_renewal_at is not None
    assert state.last_successful_publication_at is None


def test_state_store_records_rollback_current_without_overwriting_local_lineage(
    tmp_path: Path,
) -> None:
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        store.record_publication_success(
            "main-site",
            local_fingerprint="new-local",
            current_fingerprint="new-local",
            current_version=2,
        )
        store.record_rollback_success(
            "main-site", current_fingerprint="previous-remote", current_version=1
        )
        state = store.certificate_state("main-site")
    finally:
        store.close()

    assert state is not None
    assert state.last_local_fingerprint == "new-local"
    assert state.last_oci_current_fingerprint == "previous-remote"
    assert state.last_oci_current_version == 1


def test_state_store_closes_interrupted_operation_after_reconciliation(tmp_path: Path) -> None:
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        interrupted = store.start_operation(
            "main-site", OperationType.PUBLISH, local_fingerprint="fingerprint"
        )
        store.transition(interrupted.operation_id, OperationState.OCI_PENDING_VERIFIED)
        current = store.start_operation(
            "main-site", OperationType.RECONCILE, local_fingerprint="fingerprint"
        )

        assert (
            store.complete_reconciled_operations(
                "main-site",
                local_fingerprint="fingerprint",
                current_version=2,
                excluding_operation_id=current.operation_id,
            )
            == 1
        )
        active = store.active_operations("main-site")
        assert len(active) == 1
        assert active[0].operation_id == current.operation_id
        assert active[0].state is OperationState.DISCOVERED
    finally:
        store.close()


def test_state_store_closes_only_stale_pending_audits_after_new_success(tmp_path: Path) -> None:
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        interrupted = store.start_operation("main-site", OperationType.AUDIT)
        store.transition(interrupted.operation_id, OperationState.AUDIT_PENDING)
        failed = store.start_operation("main-site", OperationType.AUDIT)
        store.transition(failed.operation_id, OperationState.AUDIT_FAILED)
        current = store.start_operation("main-site", OperationType.AUDIT)
        store.transition(current.operation_id, OperationState.AUDIT_PENDING)

        assert (
            store.complete_interrupted_audits(
                "main-site", excluding_operation_id=current.operation_id
            )
            == 1
        )
        active = store.active_operations("main-site")
        assert len(active) == 1
        assert active[0].operation_id == current.operation_id
        assert active[0].state is OperationState.AUDIT_PENDING
    finally:
        store.close()


def test_state_store_supports_the_dedicated_oci_executor_thread(tmp_path: Path) -> None:
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            operation = executor.submit(
                store.start_operation, "main-site", OperationType.PUBLISH
            ).result()
        assert operation.state is OperationState.DISCOVERED
    finally:
        store.close()
