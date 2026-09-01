"""Read-only status reporting from the local durable state store."""

from __future__ import annotations

import sqlite3
from dataclasses import asdict
from datetime import UTC
from pathlib import Path

from cryptography import x509

from .config import AppConfig
from .state_store import OperationState, StateStore


def _compatibility_warnings(config: AppConfig) -> tuple[str, ...]:
    """Expose documented-policy exceptions in every safe status response."""
    if config.compatibility.enforce_documented_subject_country:
        return ()
    return ("DOCUMENTED_SUBJECT_COUNTRY_NOT_ENFORCED",)


def _local_not_after(config: AppConfig, certificate_id: str) -> str | None:
    """Read only the public leaf's expiry; missing lineage remains an unknown fact."""
    leaf_path = Path(config.acme.certificates_dir) / certificate_id / "current" / "cert.pem"
    try:
        certificate = x509.load_pem_x509_certificate(leaf_path.read_bytes())
    except (OSError, ValueError):
        return None
    return certificate.not_valid_after_utc.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _drift(local_fingerprint: str | None, remote_fingerprint: str | None) -> str:
    """Classify only evidence in the durable store; never infer remote OCI state."""
    if local_fingerprint is None or remote_fingerprint is None:
        return "UNKNOWN"
    if local_fingerprint == remote_fingerprint:
        return "NONE"
    return "LOCAL_OCI_FINGERPRINT_MISMATCH"


def _base_payload(config: AppConfig, certificate_id: str) -> dict[str, object]:
    return {
        "certificate_id": certificate_id,
        "compatibility": (
            "LIVE_VERIFIED" if config.compatibility.live_verified else "LIVE_NOT_VERIFIED"
        ),
        "compatibility_warnings": _compatibility_warnings(config),
        "local_not_after": _local_not_after(config, certificate_id),
    }


def status(config: AppConfig) -> tuple[dict[str, object], ...]:
    """Return one safe status item per configured certificate without creating state."""
    database = Path(config.global_.state_dir) / "state.sqlite3"
    try:
        database_exists = database.exists()
    except OSError:
        database_exists = False
    if not database_exists:
        return tuple(
            _base_payload(config, certificate.id)
            | {
                "oci_certificate_ocid": certificate.oci.certificate_ocid,
                "state": "NO_LOCAL_STATE",
                "drift": "UNKNOWN",
                "oci_versions_observed": 0,
                "pending_publication": False,
            }
            for certificate in config.certificates
        )
    try:
        store = StateStore.open_read_only(database)
    except sqlite3.Error:
        return tuple(
            _base_payload(config, certificate.id)
            | {
                "oci_certificate_ocid": certificate.oci.certificate_ocid,
                "state": "STATE_UNAVAILABLE",
                "drift": "UNKNOWN",
                "oci_versions_observed": 0,
                "pending_publication": False,
            }
            for certificate in config.certificates
        )
    try:
        results: list[dict[str, object]] = []
        for certificate in config.certificates:
            state = store.certificate_state(certificate.id)
            confirmed_ocid = (
                certificate.oci.certificate_ocid
                or store.confirmed_oci_certificate_ocid(certificate.id)
            )
            payload = _base_payload(config, certificate.id) | {
                "oci_certificate_ocid": confirmed_ocid,
                "oci_versions_observed": store.known_oci_versions(certificate.id),
                "pending_publication": any(
                    operation.state
                    in (
                        OperationState.OCI_PENDING_UPLOADED,
                        OperationState.OCI_PENDING_VERIFIED,
                    )
                    for operation in store.active_operations(certificate.id)
                ),
            }
            if state is None:
                payload["state"] = "NO_PUBLICATION_STATE"
                payload["drift"] = "UNKNOWN"
            else:
                payload["state"] = "AVAILABLE"
                payload.update(asdict(state))
                payload["drift"] = _drift(
                    state.last_local_fingerprint, state.last_oci_current_fingerprint
                )
            results.append(payload)
        return tuple(results)
    finally:
        store.close()
