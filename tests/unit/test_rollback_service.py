from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from oci_acme_publisher.config import load_config
from oci_acme_publisher.fingerprint import certificate_sha256
from oci_acme_publisher.oci_certificates import (
    OciCertificate,
    OciCertificateVersion,
    OciPublicBundle,
)
from oci_acme_publisher.rollback_service import RollbackError, RollbackService
from oci_acme_publisher.state_store import StateStore

from .test_certificate_validator import material_with_root


class _Management:
    def __init__(self) -> None:
        self.current = 5

    def get_certificate(self, certificate_id: str, *, opc_request_id: str) -> OciCertificate:
        return OciCertificate(certificate_id, "etag", self.current)

    def list_versions(
        self, certificate_id: str, *, opc_request_id: str
    ) -> tuple[OciCertificateVersion, ...]:
        return (OciCertificateVersion(4, "previous", ("PREVIOUS",)),)

    def upload_pending_version(self, certificate_id: str, **keywords: object) -> None:
        raise AssertionError("rollback must not upload")

    def promote_current(self, certificate_id: str, version_number: int, **keywords: object) -> None:
        self.current = version_number


class _Retrieval:
    def __init__(self, pem: str, management: _Management) -> None:
        self._pem = pem
        self._management = management

    def get_public_bundle(
        self,
        certificate_id: str,
        *,
        opc_request_id: str,
        version_number: int | None = None,
    ) -> OciPublicBundle:
        number = self._management.current if version_number is None else version_number
        return OciPublicBundle(self._pem, "chain", number, str(number), ("PREVIOUS",))


def test_rollback_promotes_and_confirms_previous_version(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    material, _ = material_with_root()
    management = _Management()
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        result = RollbackService(
            management, _Retrieval(material.leaf_pem.decode("ascii"), management), store
        ).rollback(config, config.certificates[0], now=datetime.now(UTC))
    finally:
        store.close()
    assert result.version_number == 4
    assert result.fingerprint == certificate_sha256(material.leaf)
    state = StateStore.open_read_only(tmp_path / "state.sqlite3")
    try:
        recorded = state.certificate_state(config.certificates[0].id)
    finally:
        state.close()
    assert recorded is not None
    assert recorded.last_oci_current_version == 4
    assert recorded.last_oci_current_fingerprint == result.fingerprint


def test_rollback_rejects_zero_multiple_or_scheduled_previous_versions(tmp_path: Path) -> None:
    store = StateStore.open(tmp_path / "state.sqlite3")

    class Management:
        def __init__(self, versions: tuple[OciCertificateVersion, ...]) -> None:
            self._versions = versions

        def list_versions(self, *_: object, **__: object) -> tuple[OciCertificateVersion, ...]:
            return self._versions

    try:
        for versions in (
            (),
            (
                OciCertificateVersion(1, "one", ("PREVIOUS",)),
                OciCertificateVersion(2, "two", ("PREVIOUS",)),
            ),
            (
                OciCertificateVersion(
                    1, "scheduled", ("PREVIOUS",), time_of_deletion=datetime.now(UTC)
                ),
            ),
        ):
            service = RollbackService(Management(versions), object(), store)  # type: ignore[arg-type]
            with pytest.raises(RollbackError, match="exactly one"):
                service._previous_version("ocid1.certificate.example", "request")
    finally:
        store.close()


def test_rollback_wraps_invalid_public_bundle_validation(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        with pytest.raises(RollbackError, match="local validation"):
            RollbackService._validate_bundle(
                "not pem", config.certificates[0], config, datetime.now(UTC)
            )
    finally:
        store.close()


def test_rollback_runs_successful_endpoint_audit(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    material, _ = material_with_root()
    management = _Management()
    store = StateStore.open(tmp_path / "state.sqlite3")
    audited: list[str] = []

    class Audit:
        async def audit(self, fingerprint: str) -> object:
            audited.append(fingerprint)
            return type("Result", (), {"successful": True})()

    try:
        result = RollbackService(
            management, _Retrieval(material.leaf_pem.decode("ascii"), management), store
        ).rollback(config, config.certificates[0], now=datetime.now(UTC), audit=Audit())  # type: ignore[arg-type]
    finally:
        store.close()
    assert audited == [result.fingerprint]


def test_rollback_converts_audit_failure_to_safe_rollback_error(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    material, _ = material_with_root()
    management = _Management()
    store = StateStore.open(tmp_path / "state.sqlite3")

    class Audit:
        async def audit(self, _: str) -> object:
            return type("Result", (), {"successful": False})()

    try:
        with pytest.raises(RollbackError, match="endpoint audit"):
            RollbackService(
                management, _Retrieval(material.leaf_pem.decode("ascii"), management), store
            ).rollback(config, config.certificates[0], now=datetime.now(UTC), audit=Audit())  # type: ignore[arg-type]
    finally:
        store.close()
