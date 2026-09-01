"""Tests for retained staging Gate 0 evidence and production enforcement."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from oci_acme_publisher.compatibility_probe import LiveCompatibilityProbeResult
from oci_acme_publisher.config import load_config
from oci_acme_publisher.errors import ConfigurationError
from oci_acme_publisher.publication_service import PublicationService
from oci_acme_publisher.staging_evidence import require_qualified_profile, write_evidence


@pytest.fixture
def config() -> object:
    return load_config("config/config.example.yaml")


def _result() -> LiveCompatibilityProbeResult:
    return LiveCompatibilityProbeResult(
        certificate_id="main-site",
        oci_certificate_ocid="ocid1.certificate.oc1..test",
        initial_version_number=1,
        promoted_version_number=2,
        rollback_version_number=1,
        leaf_fingerprint="a" * 64,
        root_fingerprint="b" * 64,
        chain_bytes=100,
        documented_subject_country_enforced=True,
    )


def test_retained_evidence_qualifies_the_matching_profile(tmp_path: Path, config: object) -> None:
    certificate = config.certificates[0]  # type: ignore[attr-defined]
    evidence = tmp_path / "gate0.json"
    write_evidence(str(evidence), certificate, _result())
    compatibility = config.compatibility.model_copy(  # type: ignore[attr-defined]
        update={"live_verified": True, "live_evidence_paths": (str(evidence),)}
    )
    qualified = config.model_copy(update={"compatibility": compatibility})  # type: ignore[attr-defined]
    require_qualified_profile(qualified, certificate)


def test_evidence_refuses_overwrite_and_writable_records(tmp_path: Path, config: object) -> None:
    certificate = config.certificates[0]  # type: ignore[attr-defined]
    evidence = tmp_path / "gate0.json"
    write_evidence(str(evidence), certificate, _result())
    with pytest.raises(ConfigurationError):
        write_evidence(str(evidence), certificate, _result())
    os.chmod(evidence, 0o660)
    compatibility = config.compatibility.model_copy(  # type: ignore[attr-defined]
        update={"live_verified": True, "live_evidence_paths": (str(evidence),)}
    )
    qualified = config.model_copy(update={"compatibility": compatibility})  # type: ignore[attr-defined]
    with pytest.raises(ConfigurationError):
        require_qualified_profile(qualified, certificate)


def test_evidence_must_match_the_production_certificate_shape(
    tmp_path: Path, config: object
) -> None:
    certificate = config.certificates[0]  # type: ignore[attr-defined]
    evidence = tmp_path / "gate0.json"
    write_evidence(str(evidence), certificate, _result())
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    payload["qualified_profile"]["identifier_count"] = 1
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    os.chmod(evidence, 0o640)
    compatibility = config.compatibility.model_copy(  # type: ignore[attr-defined]
        update={"live_verified": True, "live_evidence_paths": (str(evidence),)}
    )
    qualified = config.model_copy(update={"compatibility": compatibility})  # type: ignore[attr-defined]
    with pytest.raises(ConfigurationError):
        require_qualified_profile(qualified, certificate)


def test_evidence_is_reusable_for_an_equivalent_domain_and_production_chain(
    tmp_path: Path, config: object
) -> None:
    staging_certificate = config.certificates[0]  # type: ignore[attr-defined]
    evidence = tmp_path / "gate0.json"
    write_evidence(str(evidence), staging_certificate, _result())

    production_certificate = staging_certificate.model_copy(
        update={
            "common_name": "production.example",
            "domains": ("production.example", "www.production.example"),
            "chain": staging_certificate.chain.model_copy(
                update={
                    "allowed_issuer_common_names": ("Production Issuer",),
                    "allowed_root_sha256": ("c" * 64,),
                }
            ),
        }
    )
    compatibility = config.compatibility.model_copy(  # type: ignore[attr-defined]
        update={"live_verified": True, "live_evidence_paths": (str(evidence),)}
    )
    qualified = config.model_copy(update={"compatibility": compatibility})  # type: ignore[attr-defined]
    require_qualified_profile(qualified, production_certificate)


def test_production_publication_is_blocked_without_qualified_evidence(config: object) -> None:
    certificate = config.certificates[0]  # type: ignore[attr-defined]
    with pytest.raises(ConfigurationError):
        PublicationService()._require_production_qualification(config, certificate)  # type: ignore[arg-type]


def test_recovered_standard_evidence_qualifies_all_production_certificate_sets() -> None:
    config = load_config("config/production")
    evidence = str(Path("config/evidence/gate0-standard.json").resolve())
    compatibility = config.compatibility.model_copy(
        update={"live_verified": True, "live_evidence_paths": (evidence,)}
    )
    qualified = config.model_copy(update={"compatibility": compatibility})

    for certificate in qualified.certificates:
        require_qualified_profile(qualified, certificate)
