from __future__ import annotations

from pathlib import Path

import pytest

from oci_acme_publisher.config import (
    MAX_CONFIG_BYTES,
    AppConfig,
    load_config,
    normalize_domain,
)
from oci_acme_publisher.errors import ConfigurationError


def test_normalize_domain_converts_idna() -> None:
    assert normalize_domain("BÜCHER.example.") == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "value", ["*.example.com", "192.0.2.1", "bad_name.example", "-bad.example"]
)
def test_normalize_domain_rejects_unsafe_names(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_domain(value)


def test_loader_rejects_duplicate_key(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("schema_version: 4\nschema_version: 4\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="invalid YAML"):
        load_config(str(config))


def test_example_configuration_is_valid() -> None:
    configuration = load_config("config/config.example.yaml")
    assert configuration.certificates[0].common_name == "example.com"


def test_rejects_observe_audit_without_an_endpoint(tmp_path: Path) -> None:
    source = Path("config/config.example.yaml").read_text(encoding="utf-8")
    config = tmp_path / "config.yaml"
    config.write_text(
        source.replace(
            "      endpoints:\n        - hostname: example.com\n          port: 443\n",
            "      endpoints: []\n",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="certificates.0"):
        load_config(str(config))


def test_loader_rejects_missing_oversized_and_non_mapping_files(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="unable to read"):
        load_config(str(tmp_path / "missing.yaml"))

    oversized = tmp_path / "large.yaml"
    oversized.write_bytes(b"#" * (MAX_CONFIG_BYTES + 1))
    with pytest.raises(ConfigurationError, match="exceeds maximum"):
        load_config(str(oversized))

    scalar = tmp_path / "scalar.yaml"
    scalar.write_text("just-a-string\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="root must be a mapping"):
        load_config(str(scalar))


def test_cross_field_invariants_reject_unsafe_environment_and_duplicate_domain() -> None:
    config = load_config("config/config.example.yaml")
    raw = config.model_dump(by_alias=True)
    raw["acme"]["directory_url"] = "https://acme-staging-v02.api.letsencrypt.org/directory"
    with pytest.raises(ValueError, match="production environment"):
        AppConfig.model_validate(raw)

    raw = config.model_dump(by_alias=True)
    duplicate = dict(raw["certificates"][0])
    duplicate["id"] = "second-site"
    duplicate["webroot_id"] = "second-site"
    raw["certificates"] = (*raw["certificates"], duplicate)
    with pytest.raises(ValueError, match="domain configured"):
        AppConfig.model_validate(raw)


def test_cross_field_invariants_reject_webroot_inside_certificate_store() -> None:
    config = load_config("config/config.example.yaml")
    raw = config.model_dump(by_alias=True)
    raw["http01"]["webroot_base"] = f"{raw['acme']['certificates_dir']}/webroot"
    with pytest.raises(ValueError, match="must not be inside"):
        AppConfig.model_validate(raw)


def test_monitoring_rejects_reversed_thresholds() -> None:
    raw = load_config("config/config.example.yaml").model_dump(by_alias=True)
    raw["monitoring"]["warning_days"] = 6
    raw["monitoring"]["critical_days"] = 7
    with pytest.raises(ValueError, match="critical_days"):
        AppConfig.model_validate(raw)


def test_oci_optimistic_concurrency_cannot_be_disabled() -> None:
    raw = load_config("config/config.example.yaml").model_dump(by_alias=True)
    raw["oci"]["use_etag"] = False

    with pytest.raises(ValueError, match="use_etag"):
        AppConfig.model_validate(raw)


def test_directory_configuration_composes_one_file_per_certificate() -> None:
    configuration = load_config("config/production")
    assert [certificate.common_name for certificate in configuration.certificates] == [
        "oci.enricopesce.it",
        "paperino.enricopesce.it",
        "pippo.enricopesce.it",
        "pluto.enricopesce.it",
    ]
