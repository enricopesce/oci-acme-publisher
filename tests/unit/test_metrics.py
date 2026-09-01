from __future__ import annotations

import math
import stat
from datetime import UTC, datetime
from pathlib import Path

from oci_acme_publisher.config import AppConfig, load_config
from oci_acme_publisher.metrics import (
    Metric,
    certificate_days_remaining,
    collect_metrics,
    write_configured_metrics,
    write_metrics,
)
from oci_acme_publisher.state_store import OperationState, OperationType, StateStore


def test_metrics_textfile_is_atomic_content_and_non_public(tmp_path: Path) -> None:
    target = tmp_path / "metrics" / "oci_acme.prom"
    metrics = (
        Metric("oci_acme_certificate_days_remaining", 12, (("certificate_id", "main-site"),)),
    )
    write_metrics(
        target,
        metrics,
    )
    assert (
        target.read_text(encoding="utf-8")
        == 'oci_acme_certificate_days_remaining{certificate_id="main-site"} 12\n'
    )
    assert stat.S_IMODE(target.stat().st_mode) == 0o640


def _monitoring_config(tmp_path: Path) -> AppConfig:
    config = load_config("config/config.example.yaml")
    raw = config.model_dump(by_alias=True)
    raw["global"]["state_dir"] = str(tmp_path / "state")
    raw["acme"]["certificates_dir"] = str(tmp_path / "certificates")
    raw["monitoring"]["metrics_textfile"] = {
        "enabled": True,
        "path": str(tmp_path / "metrics" / "oci_acme.prom"),
    }
    return AppConfig.model_validate(raw)


def test_collect_metrics_exports_required_safe_operational_samples(tmp_path: Path) -> None:
    config = _monitoring_config(tmp_path)
    store = StateStore.open(tmp_path / "state" / "state.sqlite3")
    try:
        operation = store.start_operation("main-site", OperationType.RENEW)
        store.transition(operation.operation_id, OperationState.HTTP01_PREFLIGHT_FAILED)
        audit = store.start_operation("main-site", OperationType.AUDIT)
        store.transition(audit.operation_id, OperationState.AUDIT_FAILED)
        rollback = store.start_operation("main-site", OperationType.ROLLBACK)
        store.transition(rollback.operation_id, OperationState.COMPLETED, oci_version_number=3)
        failed_rollback = store.start_operation("main-site", OperationType.ROLLBACK)
        store.transition(failed_rollback.operation_id, OperationState.ROLLBACK_FAILED)
        store.record_renewal_success("main-site")
        store.record_audit_success("main-site")
        samples = collect_metrics(config, store, now=datetime(2026, 8, 7, tzinfo=UTC))
    finally:
        store.close()
    rendered = "".join(sample.render() for sample in samples)
    for name in (
        "oci_acme_certificate_days_remaining",
        "oci_acme_last_renewal_success_timestamp",
        "oci_acme_last_publication_success_timestamp",
        "oci_acme_last_audit_success_timestamp",
        "oci_acme_renewal_failures_total",
        "oci_acme_publication_failures_total",
        "oci_acme_audit_failures_total",
        "oci_acme_rollbacks_total",
        "oci_acme_http01_preflight_failures_total",
        "oci_acme_oci_versions",
        "oci_acme_operation_duration_seconds",
        "oci_acme_compatibility_gate",
    ):
        assert name in rendered
    assert 'oci_acme_renewal_failures_total{certificate_id="main-site"} 1' in rendered
    assert 'oci_acme_audit_failures_total{certificate_id="main-site"} 1' in rendered
    assert 'oci_acme_rollbacks_total{certificate_id="main-site"} 1' in rendered
    assert 'oci_acme_oci_versions{certificate_id="main-site"} 1' in rendered
    assert "oci_acme_compatibility_gate 0" in rendered


def test_collect_metrics_marks_operator_verified_compatibility_gate(tmp_path: Path) -> None:
    config = _monitoring_config(tmp_path)
    compatibility = config.compatibility.model_copy(update={"live_verified": True})
    config = config.model_copy(update={"compatibility": compatibility})
    store = StateStore.open(tmp_path / "state" / "state.sqlite3")
    try:
        rendered = "".join(sample.render() for sample in collect_metrics(config, store))
    finally:
        store.close()

    assert "oci_acme_compatibility_gate 1" in rendered


def test_write_configured_metrics_obeys_enabled_target(tmp_path: Path) -> None:
    config = _monitoring_config(tmp_path)
    write_configured_metrics(config)
    target = tmp_path / "metrics" / "oci_acme.prom"
    assert target.exists()
    assert stat.S_IMODE(target.stat().st_mode) == 0o640


def test_certificate_days_remaining_is_unknown_when_public_leaf_is_missing(tmp_path: Path) -> None:
    config = _monitoring_config(tmp_path)

    assert math.isnan(
        certificate_days_remaining(config, config.certificates[0], datetime(2026, 8, 7, tzinfo=UTC))
    )
