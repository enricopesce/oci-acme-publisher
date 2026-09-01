"""Atomic Prometheus textfile metrics without certificate contents or secrets."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509

from .config import AppConfig, CertificateConfig
from .state_store import StateStore


def _escape_label_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


@dataclass(frozen=True, slots=True)
class Metric:
    """One already-sanitized Prometheus sample."""

    name: str
    value: float | int
    labels: tuple[tuple[str, str], ...] = ()

    def render(self) -> str:
        """Render a conservative Prometheus sample line."""
        if not self.name.startswith("oci_acme_"):
            raise ValueError("metric name must use the oci_acme_ namespace")
        label_text = ""
        if self.labels:
            rendered = ",".join(
                f'{key}="{_escape_label_value(value)}"' for key, value in self.labels
            )
            label_text = f"{{{rendered}}}"
        return f"{self.name}{label_text} {self.value}\n"


def write_metrics(path: Path, metrics: tuple[Metric, ...]) -> None:
    """Write a complete textfile atomically with mode 0640."""
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o640)
    try:
        content = "".join(metric.render() for metric in metrics).encode("utf-8")
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    os.replace(temporary, path)


_PUBLICATION_OPERATIONS = frozenset(("BOOTSTRAP", "PUBLISH", "RECONCILE"))
_FAILURE_STATES = frozenset(
    (
        "CONFIG_FAILED",
        "HTTP01_PREFLIGHT_FAILED",
        "ACME_FAILED",
        "LOCAL_VALIDATION_FAILED",
        "OCI_UPLOAD_FAILED",
        "OCI_VERSION_FAILED",
        "OCI_PROMOTION_FAILED",
        "AUDIT_FAILED",
        "ROLLBACK_FAILED",
        "MANUAL_INTERVENTION_REQUIRED",
    )
)


def _timestamp(value: str | None) -> float:
    if value is None:
        return 0.0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def certificate_days_remaining(
    config: AppConfig, certificate: CertificateConfig, now: datetime
) -> float:
    """Read only the public leaf certificate; missing local lineage is unknown."""
    leaf = Path(config.acme.certificates_dir) / certificate.id / "current" / "cert.pem"
    try:
        parsed = x509.load_pem_x509_certificate(leaf.read_bytes())
        expires = parsed.not_valid_after_utc
    except (OSError, ValueError):
        return float("nan")
    return max(0.0, (expires - now).total_seconds() / 86400.0)


def collect_metrics(
    config: AppConfig, store: StateStore, *, now: datetime | None = None
) -> tuple[Metric, ...]:
    """Build every required metric from safe local state and public certificate metadata."""
    current = now or datetime.now(UTC)
    samples: list[Metric] = [
        Metric("oci_acme_compatibility_gate", int(config.compatibility.live_verified))
    ]
    for certificate in config.certificates:
        labels = (("certificate_id", certificate.id),)
        state = store.certificate_state(certificate.id)
        samples.extend(
            (
                Metric(
                    "oci_acme_certificate_days_remaining",
                    certificate_days_remaining(config, certificate, current),
                    labels,
                ),
                Metric(
                    "oci_acme_last_renewal_success_timestamp",
                    _timestamp(state.last_successful_renewal_at if state else None),
                    labels,
                ),
                Metric(
                    "oci_acme_last_publication_success_timestamp",
                    _timestamp(state.last_successful_publication_at if state else None),
                    labels,
                ),
                Metric(
                    "oci_acme_last_audit_success_timestamp",
                    _timestamp(state.last_successful_audit_at if state else None),
                    labels,
                ),
                Metric("oci_acme_oci_versions", store.known_oci_versions(certificate.id), labels),
            )
        )
        counts = store.operation_counts(certificate.id)
        failures = {
            "renewal": 0,
            "publication": 0,
            "audit": 0,
            "preflight": 0,
            "rollback": 0,
        }
        rollbacks = 0
        for operation_type, operation_state, count in counts:
            if operation_type == "ROLLBACK" and operation_state == "COMPLETED":
                rollbacks += count
            if operation_state not in _FAILURE_STATES:
                continue
            if operation_state == "HTTP01_PREFLIGHT_FAILED":
                failures["preflight"] += count
            if operation_type == "RENEW":
                failures["renewal"] += count
            elif operation_type in _PUBLICATION_OPERATIONS:
                failures["publication"] += count
            elif operation_type == "AUDIT":
                failures["audit"] += count
            elif operation_type == "ROLLBACK":
                failures["rollback"] += count
        samples.extend(
            (
                Metric("oci_acme_renewal_failures_total", failures["renewal"], labels),
                Metric("oci_acme_publication_failures_total", failures["publication"], labels),
                Metric("oci_acme_audit_failures_total", failures["audit"], labels),
                Metric("oci_acme_rollbacks_total", rollbacks, labels),
                Metric("oci_acme_http01_preflight_failures_total", failures["preflight"], labels),
            )
        )
        for operation_type, duration in store.average_completed_operation_durations(certificate.id):
            samples.append(
                Metric(
                    "oci_acme_operation_duration_seconds",
                    duration,
                    (*labels, ("operation", operation_type.lower())),
                )
            )
    return tuple(samples)


def collect_read_only_metrics(config: AppConfig) -> tuple[Metric, ...]:
    """Collect metrics without creating a state database when the service has not run yet."""
    database = Path(config.global_.state_dir) / "state.sqlite3"
    try:
        database_exists = database.exists()
    except OSError:
        database_exists = False
    if not database_exists:
        return (
            Metric("oci_acme_state_available", 0),
            Metric("oci_acme_compatibility_gate", int(config.compatibility.live_verified)),
        )
    try:
        store = StateStore.open_read_only(database)
    except Exception:
        return (
            Metric("oci_acme_state_available", 0),
            Metric("oci_acme_compatibility_gate", int(config.compatibility.live_verified)),
        )
    try:
        return (Metric("oci_acme_state_available", 1), *collect_metrics(config, store))
    finally:
        store.close()


def write_configured_metrics(config: AppConfig) -> None:
    """Best-effort operational snapshot; monitoring failure never changes certificate state."""
    target = config.monitoring.metrics_textfile
    if not target.enabled:
        return
    store = StateStore.open(Path(config.global_.state_dir) / "state.sqlite3")
    try:
        write_metrics(Path(target.path), collect_metrics(config, store))
    finally:
        store.close()
