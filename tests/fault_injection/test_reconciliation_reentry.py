"""Crash/re-entry tests that exercise the real SQLite recovery state."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from oci_acme_publisher import publication_service
from oci_acme_publisher.chain_builder import OciCertificateChain
from oci_acme_publisher.config import load_config
from oci_acme_publisher.fingerprint import certificate_sha256
from oci_acme_publisher.oci_certificates import (
    OciCertificate,
    OciCertificateVersion,
    OciPublicBundle,
)
from oci_acme_publisher.publication_service import PublicationService
from oci_acme_publisher.reconciler import PublicationReconciler
from oci_acme_publisher.retention_service import plan_retention
from oci_acme_publisher.state_store import OperationState, OperationType, StateStore
from tests.unit.test_certificate_validator import material_with_root


class _Management:
    def __init__(self) -> None:
        self.current = 3
        self.upload_calls = 0
        self.promote_calls = 0

    def get_certificate(self, certificate_id: str, *, opc_request_id: str) -> OciCertificate:
        return OciCertificate(certificate_id, "etag", self.current)

    def list_versions(
        self, certificate_id: str, *, opc_request_id: str
    ) -> tuple[OciCertificateVersion, ...]:
        return (
            OciCertificateVersion(3, "old", ("CURRENT",)),
            OciCertificateVersion(4, "interrupted-upload", ("PENDING", "LATEST")),
        )

    def upload_pending_version(self, certificate_id: str, **_: object) -> None:
        self.upload_calls += 1
        raise AssertionError("re-entry must reuse the persisted PENDING version")

    def promote_current(self, certificate_id: str, version_number: int, **_: object) -> None:
        self.promote_calls += 1
        self.current = version_number


class _Retrieval:
    def __init__(self, old_pem: str, pending_pem: str, management: _Management) -> None:
        self._old_pem = old_pem
        self._pending_pem = pending_pem
        self._management = management

    def get_public_bundle(
        self,
        certificate_id: str,
        *,
        opc_request_id: str,
        version_number: int | None = None,
    ) -> OciPublicBundle:
        number = self._management.current if version_number is None else version_number
        certificate_pem = self._pending_pem if number == 4 else self._old_pem
        stages = ("CURRENT",) if number == self._management.current else ("PENDING", "LATEST")
        return OciPublicBundle(certificate_pem, "chain", number, str(number), stages)


class _UploadManagement(_Management):
    """A fresh remote certificate whose first re-entry must create one PENDING version."""

    def __init__(self) -> None:
        super().__init__()
        self.pending_available = False

    def list_versions(
        self, certificate_id: str, *, opc_request_id: str
    ) -> tuple[OciCertificateVersion, ...]:
        versions = [OciCertificateVersion(3, "old", ("CURRENT",))]
        if self.pending_available:
            versions.append(OciCertificateVersion(4, "recovered-upload", ("PENDING", "LATEST")))
        return tuple(versions)

    def upload_pending_version(self, certificate_id: str, **_: object) -> None:
        self.upload_calls += 1
        self.pending_available = True


def test_reentry_after_pending_upload_promotes_without_duplicate_upload(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    old_material, _ = material_with_root()
    local_material, root = material_with_root()
    local_fingerprint = certificate_sha256(local_material.leaf)
    management = _Management()
    retrieval = _Retrieval(
        old_material.leaf_pem.decode("ascii"),
        local_material.leaf_pem.decode("ascii"),
        management,
    )
    chain = OciCertificateChain(root, local_material.intermediates, local_material.chain_pem)
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        interrupted = store.start_operation(
            "main-site", OperationType.PUBLISH, local_fingerprint=local_fingerprint
        )
        store.transition(interrupted.operation_id, OperationState.OCI_PENDING_UPLOADED)

        result = PublicationReconciler(management, retrieval, store).publish(
            config,
            config.certificates[0],
            local_material,
            chain,
            local_fingerprint,
            now=datetime.now(UTC),
            operation_type=OperationType.RECONCILE,
        )

        assert result.changed is True
        assert result.current_version_number == 4
        assert management.current == 4
        assert management.upload_calls == 0
        assert store.active_operations("main-site") == ()
        assert ("PUBLISH", "COMPLETED", 1) in store.operation_counts("main-site")
        assert ("RECONCILE", "COMPLETED", 1) in store.operation_counts("main-site")
    finally:
        store.close()


def test_reentry_after_pending_verification_promotes_without_reimport(tmp_path: Path) -> None:
    """A crash after bundle validation must retain the verified PENDING candidate."""
    config = load_config("config/config.example.yaml")
    old_material, _ = material_with_root()
    local_material, root = material_with_root()
    local_fingerprint = certificate_sha256(local_material.leaf)
    management = _Management()
    retrieval = _Retrieval(
        old_material.leaf_pem.decode("ascii"),
        local_material.leaf_pem.decode("ascii"),
        management,
    )
    chain = OciCertificateChain(root, local_material.intermediates, local_material.chain_pem)
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        interrupted = store.start_operation(
            "main-site", OperationType.PUBLISH, local_fingerprint=local_fingerprint
        )
        store.transition(
            interrupted.operation_id,
            OperationState.OCI_PENDING_VERIFIED,
            oci_version_number=4,
        )

        result = PublicationReconciler(management, retrieval, store).publish(
            config,
            config.certificates[0],
            local_material,
            chain,
            local_fingerprint,
            now=datetime.now(UTC),
            operation_type=OperationType.RECONCILE,
        )

        assert result.changed is True
        assert result.current_version_number == 4
        assert management.upload_calls == 0
        assert management.promote_calls == 1
        assert store.active_operations("main-site") == ()
    finally:
        store.close()


def test_reentry_after_promotion_confirms_current_without_another_mutation(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    old_material, _ = material_with_root()
    local_material, root = material_with_root()
    local_fingerprint = certificate_sha256(local_material.leaf)
    management = _Management()
    management.current = 4
    retrieval = _Retrieval(
        old_material.leaf_pem.decode("ascii"),
        local_material.leaf_pem.decode("ascii"),
        management,
    )
    chain = OciCertificateChain(root, local_material.intermediates, local_material.chain_pem)
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        interrupted = store.start_operation(
            "main-site", OperationType.PUBLISH, local_fingerprint=local_fingerprint
        )
        store.transition(
            interrupted.operation_id,
            OperationState.OCI_PENDING_VERIFIED,
            oci_version_number=4,
        )

        result = PublicationReconciler(management, retrieval, store).publish(
            config,
            config.certificates[0],
            local_material,
            chain,
            local_fingerprint,
            now=datetime.now(UTC),
            operation_type=OperationType.RECONCILE,
        )

        assert result.changed is False
        assert result.current_version_number == 4
        assert management.upload_calls == 0
        assert management.promote_calls == 0
        assert store.active_operations("main-site") == ()
        assert ("PUBLISH", "COMPLETED", 1) in store.operation_counts("main-site")
        assert ("RECONCILE", "COMPLETED", 1) in store.operation_counts("main-site")
    finally:
        store.close()


def test_reentry_after_local_validation_imports_exactly_one_pending_version(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    old_material, _ = material_with_root()
    local_material, root = material_with_root()
    local_fingerprint = certificate_sha256(local_material.leaf)
    management = _UploadManagement()
    retrieval = _Retrieval(
        old_material.leaf_pem.decode("ascii"),
        local_material.leaf_pem.decode("ascii"),
        management,
    )
    chain = OciCertificateChain(root, local_material.intermediates, local_material.chain_pem)
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        interrupted = store.start_operation(
            "main-site", OperationType.RENEW, local_fingerprint=local_fingerprint
        )
        store.transition(interrupted.operation_id, OperationState.LOCAL_CERT_VALIDATED)

        result = PublicationReconciler(management, retrieval, store).publish(
            config,
            config.certificates[0],
            local_material,
            chain,
            local_fingerprint,
            now=datetime.now(UTC),
            operation_type=OperationType.RECONCILE,
        )

        assert result.changed is True
        assert result.current_version_number == 4
        assert management.upload_calls == 1
        assert management.promote_calls == 1
        assert store.active_operations("main-site") == ()
        assert ("RENEW", "COMPLETED", 1) in store.operation_counts("main-site")
        assert ("RECONCILE", "COMPLETED", 1) in store.operation_counts("main-site")
    finally:
        store.close()


def test_successful_audit_closes_audit_pending_left_by_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A later independent audit is the only proof that closes a stale audit attempt."""
    base = load_config("config/config.example.yaml")
    config = base.model_copy(
        update={"global_": base.global_.model_copy(update={"state_dir": str(tmp_path)})}
    )
    state_path = tmp_path / "state.sqlite3"
    store = StateStore.open(state_path)
    try:
        interrupted = store.start_operation("main-site", OperationType.AUDIT)
        store.transition(interrupted.operation_id, OperationState.AUDIT_PENDING)
    finally:
        store.close()

    adapters = SimpleNamespace(
        retrieval=SimpleNamespace(
            get_public_bundle=lambda *_args, **_keywords: OciPublicBundle(
                "leaf", "chain", 3, "v3", ("CURRENT",)
            )
        )
    )

    class SuccessfulAudit:
        async def audit(self, _: str) -> object:
            return SimpleNamespace(successful=True)

    service = PublicationService(adapters_factory=lambda *_: adapters, expected_owner_uid=0)
    monkeypatch.setattr(service, "_audit_service", lambda *_: SuccessfulAudit())
    monkeypatch.setattr(
        publication_service,
        "validate_public_certificate",
        lambda *_args, **_keywords: "a" * 64,
    )

    assert service.audit(config, "main-site") is True

    reopened = StateStore.open_read_only(state_path)
    try:
        assert reopened.active_operations("main-site") == ()
        assert ("AUDIT", "COMPLETED", 2) in reopened.operation_counts("main-site")
    finally:
        reopened.close()


def test_retention_reentry_skips_version_already_scheduled_for_deletion() -> None:
    """A restart after OCI accepted scheduling must not schedule the version again."""
    configuration = (
        load_config("config/config.example.yaml")
        .certificates[0]
        .retention.model_copy(update={"enabled": True, "keep_deprecated_versions": 1})
    )
    now = datetime(2026, 8, 7, tzinfo=UTC)
    old = OciCertificateVersion(1, "old", ("DEPRECATED",), now - timedelta(days=91))
    retained = OciCertificateVersion(2, "new", ("DEPRECATED",), now - timedelta(days=90))
    first_plan = plan_retention(
        configuration,
        (old, retained),
        referenced_versions=frozenset(),
        now=now,
    )
    scheduled = OciCertificateVersion(
        1,
        "old",
        ("DEPRECATED",),
        now - timedelta(days=90),
        time_of_deletion=first_plan.deletion_time,
    )

    reentry_plan = plan_retention(
        configuration,
        (scheduled, retained),
        referenced_versions=frozenset(),
        now=now + timedelta(minutes=1),
    )

    assert first_plan.version_numbers == (1,)
    assert reentry_plan.version_numbers == ()
