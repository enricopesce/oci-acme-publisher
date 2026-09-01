"""Compatibility Gate 0 checks, with an offline profile validation path."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from .certificate_store import LineageMaterial, certificate_store
from .certificate_validator import validate_certificate_material
from .chain_builder import build_oci_chain
from .config import AppConfig, CertificateConfig
from .fingerprint import certificate_sha256
from .models import Environment
from .publication_service import PublicationService


class CompatibilityProbeError(RuntimeError):
    """The certificate profile cannot satisfy the documented OCI compatibility checks."""


class LiveProbePrerequisiteError(CompatibilityProbeError):
    """A live probe was requested without the dedicated OCI test environment."""


@dataclass(frozen=True, slots=True)
class CompatibilityProbeResult:
    """Safe profile facts from a completed offline validation."""

    certificate_id: str
    leaf_fingerprint: str
    root_fingerprint: str
    chain_bytes: int
    documented_subject_country_enforced: bool


@dataclass(frozen=True, slots=True)
class LiveCompatibilityProbeResult:
    """Evidence produced by the mutating, staging-only portion of Gate 0."""

    certificate_id: str
    oci_certificate_ocid: str
    initial_version_number: int
    promoted_version_number: int
    rollback_version_number: int
    leaf_fingerprint: str
    root_fingerprint: str
    chain_bytes: int
    documented_subject_country_enforced: bool


def probe_material(
    config: AppConfig,
    certificate: CertificateConfig,
    material: LineageMaterial,
) -> CompatibilityProbeResult:
    """Validate all local profile constraints that do not require OCI mutation."""
    try:
        leaf_fingerprint = validate_certificate_material(
            material,
            certificate,
            config.compatibility,
            config.global_,
            now=datetime.now(UTC),
        )
        chain = build_oci_chain(material, certificate, config.compatibility)
    except ValueError as error:
        raise CompatibilityProbeError(
            "local certificate profile is incompatible with OCI policy"
        ) from error
    return CompatibilityProbeResult(
        certificate.id,
        leaf_fingerprint,
        certificate_sha256(chain.root),
        len(chain.cert_chain_pem),
        config.compatibility.enforce_documented_subject_country,
    )


def offline_probe(
    config: AppConfig,
    certificate: CertificateConfig,
    *,
    expected_owner_uid: int,
) -> CompatibilityProbeResult:
    """Load the real lineage and run all offline Gate 0 validations."""
    material = certificate_store(config.acme, expected_owner_uid).load(certificate)
    return probe_material(config, certificate, material)


def require_live_test_environment(config: AppConfig, certificate: CertificateConfig) -> None:
    """Enforce the narrow boundary for the mutating Gate 0 test."""
    if config.global_.environment is not Environment.STAGING:
        raise LiveProbePrerequisiteError("live compatibility probe requires environment: staging")
    if not certificate.audit.endpoints:
        raise LiveProbePrerequisiteError(
            "live compatibility probe requires a manually associated TLS audit endpoint"
        )
    if certificate.oci.certificate_ocid is None:
        raise LiveProbePrerequisiteError(
            "live compatibility probe requires an existing test certificate OCID; "
            "run bootstrap, associate that OCID manually, then rerun the probe"
        )


def live_probe(
    config: AppConfig,
    certificate: CertificateConfig,
    *,
    expected_owner_uid: int,
    service: PublicationService | None = None,
) -> LiveCompatibilityProbeResult:
    """Run Gate 0 after bootstrap and manual test-listener association."""
    require_live_test_environment(config, certificate)
    publisher = service or PublicationService()
    baseline = publisher.publish(config, certificate.id)
    offline = offline_probe(config, certificate, expected_owner_uid=expected_owner_uid)
    published = publisher.renew(config, certificate.id, force_acme_renewal=True)
    if not publisher.audit(config, certificate.id):
        raise CompatibilityProbeError(
            "manual TLS consumer did not present promoted CURRENT version"
        )
    rollback = publisher.rollback(config, certificate.id)
    if not publisher.audit(config, certificate.id):
        raise CompatibilityProbeError(
            "manual TLS consumer did not present rolled-back CURRENT version"
        )
    oci_certificate_ocid = certificate.oci.certificate_ocid
    if oci_certificate_ocid is None:
        raise CompatibilityProbeError(
            "live compatibility probe did not obtain an OCI certificate OCID"
        )
    return LiveCompatibilityProbeResult(
        certificate_id=certificate.id,
        oci_certificate_ocid=oci_certificate_ocid,
        initial_version_number=baseline.current_version_number,
        promoted_version_number=published.current_version_number,
        rollback_version_number=rollback.version_number,
        leaf_fingerprint=offline.leaf_fingerprint,
        root_fingerprint=offline.root_fingerprint,
        chain_bytes=offline.chain_bytes,
        documented_subject_country_enforced=offline.documented_subject_country_enforced,
    )
