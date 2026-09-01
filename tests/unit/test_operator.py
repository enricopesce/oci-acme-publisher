from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from oci_acme_publisher import operator
from oci_acme_publisher.errors import ConfigurationError


def test_initialize_creates_native_schema_and_refuses_unsafe_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ConfigurationError, match="absolute"):
        operator.initialize_configuration("relative")

    regular_file = tmp_path / "file"
    regular_file.write_text("x", encoding="ascii")
    with pytest.raises(ConfigurationError, match="not a directory"):
        operator.initialize_configuration(str(regular_file))

    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    (nonempty / "keep").write_text("x", encoding="ascii")
    with pytest.raises(ConfigurationError, match="not empty"):
        operator.initialize_configuration(str(nonempty))

    destination = tmp_path / "config"
    expected = operator.initialize_configuration(str(destination), dry_run=True)
    assert expected[0].endswith("settings.yaml")
    monkeypatch.setattr(operator.os, "geteuid", lambda: 1000)
    created = operator.initialize_configuration(str(destination))
    assert created == expected
    settings = yaml.safe_load((destination / "settings.yaml").read_text(encoding="utf-8"))
    assert settings["schema_version"] == 4
    assert "account_key_path" in settings["acme"]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"config_directory": "relative"}, "absolute"),
        ({"certificate_id": "Bad_ID"}, "certificate id"),
        ({"domains": ()}, "at least one"),
        ({"domains": ("*.example.com",)}, "domains are invalid"),
        ({"domains": ("example.com", "example.com")}, "domains must be unique"),
        ({"region": "bad region"}, "region"),
        ({"compartment_ocid": "bad"}, "compartment OCID"),
        ({"certificate_ocid": "bad"}, "certificate OCID"),
    ],
)
def test_add_certificate_rejects_invalid_operator_input(
    tmp_path: Path, overrides: dict[str, object], message: str
) -> None:
    arguments: dict[str, object] = {
        "config_directory": str(tmp_path),
        "certificate_id": "example-com",
        "domains": ("example.com",),
        "region": "eu-frankfurt-1",
        "compartment_ocid": "ocid1.compartment.oc1..example",
        "certificate_ocid": None,
        "dry_run": True,
    }
    arguments.update(overrides)
    with pytest.raises(ConfigurationError, match=message):
        operator.add_certificate(**arguments)  # type: ignore[arg-type]


def test_add_certificate_writes_one_native_certificate_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "config"
    monkeypatch.setattr(operator.os, "geteuid", lambda: 1000)
    operator.initialize_configuration(str(destination))
    sample = destination / "certificates" / "example-com.yaml"
    sample.unlink()

    path = operator.add_certificate(
        str(destination),
        certificate_id="public-sites",
        domains=("BÜCHER.example", "www.example.com"),
        region="eu-frankfurt-1",
        compartment_ocid="ocid1.compartment.oc1..example",
        certificate_ocid="ocid1.certificate.oc1.eu-frankfurt-1.example",
    )
    document = yaml.safe_load(Path(path).read_text(encoding="utf-8"))["certificate"]
    assert document["id"] == "public-sites"
    assert document["domains"][0] == "xn--bcher-kva.example"

    with pytest.raises(ConfigurationError, match="already exists"):
        operator.add_certificate(
            str(destination),
            certificate_id="public-sites",
            domains=("example.com",),
            region="eu-frankfurt-1",
            compartment_ocid="ocid1.compartment.oc1..example",
            certificate_ocid=None,
        )


def test_effective_configuration_redacts_acme_contact() -> None:
    effective = operator.effective_configuration("config/config.example.yaml")
    assert effective["acme"]["email"] == "[REDACTED]"
