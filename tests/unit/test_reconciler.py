from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from oci.exceptions import ServiceError

from oci_acme_publisher import reconciler
from oci_acme_publisher.chain_builder import OciCertificateChain
from oci_acme_publisher.config import load_config
from oci_acme_publisher.fingerprint import certificate_sha256
from oci_acme_publisher.oci_certificates import (
    OciCertificate,
    OciCertificateVersion,
    OciPublicBundle,
)
from oci_acme_publisher.reconciler import PublicationReconciler
from oci_acme_publisher.state_store import OperationType, StateStore

from .test_certificate_validator import material_with_root


class _Management:
    def __init__(self) -> None:
        self.current = 3
        self.pending_uploaded = False

    def get_certificate(self, certificate_id: str, *, opc_request_id: str) -> OciCertificate:
        return OciCertificate(certificate_id, "etag", self.current)

    def list_versions(
        self, certificate_id: str, *, opc_request_id: str
    ) -> tuple[OciCertificateVersion, ...]:
        versions = [OciCertificateVersion(3, "old", ("CURRENT",))]
        if self.pending_uploaded:
            versions.append(OciCertificateVersion(4, "new", ("PENDING", "LATEST")))
        return tuple(versions)

    def upload_pending_version(self, certificate_id: str, **_: object) -> None:
        self.pending_uploaded = True

    def promote_current(self, certificate_id: str, version_number: int, **_: object) -> None:
        self.current = version_number


class _Retrieval:
    def __init__(self, current: str, new: str, management: _Management) -> None:
        self._current = current
        self._new = new
        self._management = management

    def get_public_bundle(
        self,
        certificate_id: str,
        *,
        opc_request_id: str,
        version_number: int | None = None,
    ) -> OciPublicBundle:
        requested = self._management.current if version_number is None else version_number
        pem = self._new if requested == 4 else self._current
        return OciPublicBundle(pem, "chain", requested, str(requested), ("CURRENT",))


def test_reconciler_uploads_then_verifies_then_promotes_once(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    old_material, _ = material_with_root()
    new_material, root = material_with_root()
    chain = OciCertificateChain(root, new_material.intermediates, new_material.chain_pem)
    management = _Management()
    retrieval = _Retrieval(
        old_material.leaf_pem.decode("ascii"), new_material.leaf_pem.decode("ascii"), management
    )
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        result = PublicationReconciler(management, retrieval, store).publish(
            config,
            config.certificates[0],
            new_material,
            chain,
            certificate_sha256(new_material.leaf),
            now=datetime.now(UTC),
        )
    finally:
        store.close()
    assert result.changed is True
    assert result.current_version_number == 4
    assert management.pending_uploaded is True


def test_reconciler_retries_promotion_after_oci_incorrect_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config("config/config.example.yaml")
    old_material, _ = material_with_root()
    new_material, root = material_with_root()
    chain = OciCertificateChain(root, new_material.intermediates, new_material.chain_pem)

    class SettlingManagement(_Management):
        def __init__(self) -> None:
            super().__init__()
            self.promotions = 0

        def promote_current(self, certificate_id: str, version_number: int, **_: object) -> None:
            self.promotions += 1
            if self.promotions == 1:
                raise ServiceError(409, "IncorrectState", {}, "still updating")
            self.current = version_number

    monkeypatch.setattr(reconciler.time, "sleep", lambda _: None)
    management = SettlingManagement()
    retrieval = _Retrieval(
        old_material.leaf_pem.decode("ascii"),
        new_material.leaf_pem.decode("ascii"),
        management,
    )
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        result = PublicationReconciler(management, retrieval, store).publish(
            config,
            config.certificates[0],
            new_material,
            chain,
            certificate_sha256(new_material.leaf),
            now=datetime.now(UTC),
        )
    finally:
        store.close()

    assert result.current_version_number == 4
    assert management.promotions == 2


def test_reconciler_records_the_renewal_timestamp_for_renew_operations(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    old_material, _ = material_with_root()
    new_material, root = material_with_root()
    chain = OciCertificateChain(root, new_material.intermediates, new_material.chain_pem)
    management = _Management()
    retrieval = _Retrieval(
        old_material.leaf_pem.decode("ascii"), new_material.leaf_pem.decode("ascii"), management
    )
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        PublicationReconciler(management, retrieval, store).publish(
            config,
            config.certificates[0],
            new_material,
            chain,
            certificate_sha256(new_material.leaf),
            now=datetime.now(UTC),
            operation_type=OperationType.RENEW,
        )
        state = store.certificate_state("main-site")
    finally:
        store.close()

    assert state is not None
    assert state.last_successful_renewal_at is not None
