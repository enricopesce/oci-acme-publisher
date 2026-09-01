"""Safe OCI certificate-version retention planning."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .config import RetentionConfig
from .oci_certificates import OciCertificateVersion

_PROTECTED_STAGES = frozenset({"CURRENT", "PENDING", "PREVIOUS", "LATEST", "PENDING_ACTIVATION"})


@dataclass(frozen=True, slots=True)
class RetentionPlan:
    """Versions that may safely have deletion scheduled at the given time."""

    version_numbers: tuple[int, ...]
    deletion_time: datetime


def plan_retention(
    configuration: RetentionConfig,
    versions: tuple[OciCertificateVersion, ...],
    *,
    referenced_versions: frozenset[int],
    now: datetime,
) -> RetentionPlan:
    """Select only old unreferenced DEPRECATED versions beyond rollback retention."""
    deletion_time = now.astimezone(UTC) + timedelta(days=configuration.deletion_delay_days)
    if not configuration.enabled:
        return RetentionPlan((), deletion_time)
    eligible = sorted(
        (
            version
            for version in versions
            if "DEPRECATED" in version.stages
            and not _PROTECTED_STAGES.intersection(version.stages)
            and version.version_number not in referenced_versions
            and version.time_of_deletion is None
            and version.time_created is not None
            and version.time_created.astimezone(UTC)
            <= now.astimezone(UTC) - timedelta(days=configuration.minimum_age_days)
        ),
        key=lambda version: (version.time_created, version.version_number),
        reverse=True,
    )
    retained = eligible[: configuration.keep_deprecated_versions]
    retained_numbers = {version.version_number for version in retained}
    scheduled = tuple(
        version.version_number
        for version in eligible
        if version.version_number not in retained_numbers
    )
    return RetentionPlan(scheduled, deletion_time)
