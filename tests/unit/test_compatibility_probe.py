from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from oci_acme_publisher import compatibility_probe
from oci_acme_publisher.compatibility_probe import (
    CompatibilityProbeError,
    LiveProbePrerequisiteError,
    live_probe,
    offline_probe,
    probe_material,
    require_live_test_environment,
)
from oci_acme_publisher.config import load_config
from oci_acme_publisher.fingerprint import certificate_sha256
from oci_acme_publisher.models import Environment

from .test_certificate_validator import material_with_root


def test_offline_probe_reports_validated_profile_with_pinned_root(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    material, root = material_with_root()
    root_path = tmp_path / "root.pem"
    root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    chain = config.certificates[0].chain.model_copy(
        update={
            "root_pem_path": str(root_path),
            "allowed_root_sha256": (certificate_sha256(root),),
            "allowed_issuer_common_names": ("issuer.example",),
        }
    )
    certificate = config.certificates[0].model_copy(update={"chain": chain})
    result = probe_material(config, certificate, material)
    assert result.leaf_fingerprint == certificate_sha256(material.leaf)
    assert result.root_fingerprint == certificate_sha256(root)


def test_probe_wraps_incompatible_local_material() -> None:
    config = load_config("config/config.example.yaml")
    material, _ = material_with_root(san=("example.com",))
    with pytest.raises(CompatibilityProbeError, match="incompatible"):
        probe_material(config, config.certificates[0], material)


def test_offline_probe_uses_the_confined_certificate_store(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config("config/config.example.yaml")
    material, _ = material_with_root(san=("example.com",))

    class Loader:
        def load(self, _: object) -> object:
            return material

    monkeypatch.setattr(compatibility_probe, "certificate_store", lambda *_: Loader())
    with pytest.raises(CompatibilityProbeError):
        offline_probe(config, config.certificates[0], expected_owner_uid=0)


def test_live_probe_refuses_non_staging_environment() -> None:
    config = load_config("config/config.example.yaml")
    with pytest.raises(LiveProbePrerequisiteError, match="environment: staging"):
        require_live_test_environment(config, config.certificates[0])


def test_live_probe_requires_bootstrapped_test_ocid() -> None:
    config = load_config("config/config.example.yaml")
    staging_global = config.global_.model_copy(update={"environment": Environment.STAGING})
    staging_acme = config.acme.model_copy(
        update={"directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"}
    )
    certificate = config.certificates[0].model_copy(
        update={
            "oci": config.certificates[0].oci.model_copy(update={"certificate_ocid": None}),
        }
    )
    staging = config.model_copy(
        update={"global_": staging_global, "acme": staging_acme, "certificates": (certificate,)}
    )
    with pytest.raises(LiveProbePrerequisiteError, match="run bootstrap"):
        require_live_test_environment(staging, certificate)


def test_live_probe_uses_second_version_and_rolls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config("config/config.example.yaml")
    staging_global = config.global_.model_copy(update={"environment": Environment.STAGING})
    staging_acme = config.acme.model_copy(
        update={"directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"}
    )
    certificate = config.certificates[0].model_copy(
        update={
            "oci": config.certificates[0].oci.model_copy(
                update={"certificate_ocid": "ocid1.certificate.oc1..test"}
            ),
        }
    )
    staging = config.model_copy(
        update={"global_": staging_global, "acme": staging_acme, "certificates": (certificate,)}
    )
    material, root = material_with_root(san=("example.com",))
    offline = compatibility_probe.CompatibilityProbeResult(
        certificate_id=certificate.id,
        leaf_fingerprint=certificate_sha256(material.leaf),
        root_fingerprint=certificate_sha256(root),
        chain_bytes=100,
        documented_subject_country_enforced=True,
    )

    class Service:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def publish(self, *_: object) -> object:
            self.calls.append("publish")
            return type("Result", (), {"current_version_number": 1})()

        def renew(self, *_: object, **__: object) -> object:
            self.calls.append("renew")
            return type("Result", (), {"current_version_number": 2})()

        def audit(self, *_: object) -> bool:
            self.calls.append("audit")
            return True

        def rollback(self, *_: object) -> object:
            self.calls.append("rollback")
            return type("Result", (), {"version_number": 1})()

    monkeypatch.setattr(compatibility_probe, "offline_probe", lambda *_, **__: offline)
    service = Service()
    result = live_probe(staging, certificate, expected_owner_uid=0, service=service)  # type: ignore[arg-type]
    assert result.promoted_version_number == 2
    assert result.rollback_version_number == 1
    assert service.calls == ["publish", "renew", "audit", "rollback", "audit"]
