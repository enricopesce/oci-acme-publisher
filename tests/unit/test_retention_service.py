from __future__ import annotations

from datetime import UTC, datetime, timedelta

from oci_acme_publisher.config import load_config
from oci_acme_publisher.oci_certificates import OciCertificateVersion
from oci_acme_publisher.retention_service import plan_retention


def test_retention_only_schedules_old_unprotected_deprecated_versions() -> None:
    configuration = load_config("config/config.example.yaml").certificates[0].retention
    now = datetime(2026, 8, 6, tzinfo=UTC)
    versions = (
        OciCertificateVersion(1, "old", ("DEPRECATED",), now - timedelta(days=90)),
        OciCertificateVersion(2, "newer", ("DEPRECATED",), now - timedelta(days=60)),
        OciCertificateVersion(3, "current", ("CURRENT",), now - timedelta(days=120)),
        OciCertificateVersion(4, "referenced", ("DEPRECATED",), now - timedelta(days=120)),
    )
    plan = plan_retention(configuration, versions, referenced_versions=frozenset({4}), now=now)
    assert plan.version_numbers == ()


def test_retention_schedules_excess_old_versions() -> None:
    configuration = load_config("config/config.example.yaml").certificates[0].retention
    now = datetime(2026, 8, 6, tzinfo=UTC)
    versions = tuple(
        OciCertificateVersion(
            number,
            str(number),
            ("DEPRECATED",),
            now - timedelta(days=40 + number),
        )
        for number in range(1, 5)
    )
    plan = plan_retention(configuration, versions, referenced_versions=frozenset(), now=now)
    assert plan.version_numbers == (3, 4)
    assert plan.deletion_time == now + timedelta(days=configuration.deletion_delay_days)
