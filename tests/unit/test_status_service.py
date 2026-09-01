from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from oci_acme_publisher import status_service
from oci_acme_publisher.config import load_config
from oci_acme_publisher.state_store import OperationState, OperationType, StateStore
from oci_acme_publisher.status_service import status


def test_status_without_state_database_does_not_create_one(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    global_config = config.global_.model_copy(update={"state_dir": str(tmp_path)})
    config = config.model_copy(update={"global_": global_config})
    result = status(config)
    assert result[0]["state"] == "NO_LOCAL_STATE"
    assert not (tmp_path / "state.sqlite3").exists()


def test_status_reads_existing_state_without_mutating_it(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    global_config = config.global_.model_copy(update={"state_dir": str(tmp_path)})
    config = config.model_copy(update={"global_": global_config})
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        store.record_publication_success(
            "main-site",
            local_fingerprint="local",
            current_fingerprint="current",
            current_version=4,
        )
    finally:
        store.close()

    result = status(config)

    assert result[0]["state"] == "AVAILABLE"
    assert result[0]["last_oci_current_version"] == 4
    assert result[0]["oci_versions_observed"] == 0
    assert result[0]["pending_publication"] is False
    assert result[0]["drift"] == "LOCAL_OCI_FINGERPRINT_MISMATCH"


def test_status_exposes_bootstrap_ocid_persisted_outside_yaml(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    global_config = config.global_.model_copy(update={"state_dir": str(tmp_path)})
    certificate = config.certificates[0].model_copy(
        update={"oci": config.certificates[0].oci.model_copy(update={"certificate_ocid": None})}
    )
    config = config.model_copy(update={"global_": global_config, "certificates": (certificate,)})
    store = StateStore.open(tmp_path / "state.sqlite3")
    try:
        operation = store.start_operation("main-site", OperationType.BOOTSTRAP)
        store.transition(
            operation.operation_id,
            OperationState.COMPLETED,
            oci_certificate_ocid="ocid1.certificate.oc1..persisted",
        )
    finally:
        store.close()

    assert status(config)[0]["oci_certificate_ocid"] == "ocid1.certificate.oc1..persisted"


def test_status_exposes_disabled_documented_country_policy(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    global_config = config.global_.model_copy(update={"state_dir": str(tmp_path)})
    compatibility = config.compatibility.model_copy(
        update={"enforce_documented_subject_country": False}
    )
    config = config.model_copy(update={"global_": global_config, "compatibility": compatibility})

    result = status(config)

    assert result[0]["compatibility_warnings"] == ("DOCUMENTED_SUBJECT_COUNTRY_NOT_ENFORCED",)


def test_status_exposes_recorded_live_compatibility_gate(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    global_config = config.global_.model_copy(update={"state_dir": str(tmp_path)})
    compatibility = config.compatibility.model_copy(update={"live_verified": True})
    config = config.model_copy(update={"global_": global_config, "compatibility": compatibility})

    result = status(config)

    assert result[0]["compatibility"] == "LIVE_VERIFIED"


def test_status_reports_public_local_expiry_without_loading_private_key(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    global_config = config.global_.model_copy(update={"state_dir": str(tmp_path / "state")})
    acme = config.acme.model_copy(update={"certificates_dir": str(tmp_path / "certificates")})
    config = config.model_copy(update={"global_": global_config, "acme": acme})
    leaf_path = tmp_path / "certificates" / "main-site" / "current" / "cert.pem"
    leaf_path.parent.mkdir(parents=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]))
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2026, 2, 1, tzinfo=UTC))
        .sign(key, hashes.SHA256())
    )
    leaf_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    result = status(config)

    assert result[0]["local_not_after"] == "2026-02-01T00:00:00Z"


def test_status_reports_unavailable_existing_state_database(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config("config/config.example.yaml")
    global_config = config.global_.model_copy(update={"state_dir": str(tmp_path)})
    config = config.model_copy(update={"global_": global_config})
    (tmp_path / "state.sqlite3").touch()
    monkeypatch.setattr(
        status_service.StateStore,
        "open_read_only",
        lambda _: (_ for _ in ()).throw(sqlite3.DatabaseError("broken")),
    )

    result = status_service.status(config)

    assert result[0]["state"] == "STATE_UNAVAILABLE"
