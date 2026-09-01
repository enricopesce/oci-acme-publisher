from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization

from oci_acme_publisher.chain_builder import (
    ChainBuildError,
    _algorithm_family,
    _load_pinned_root,
    _validate_ca,
    build_oci_chain,
)
from oci_acme_publisher.config import load_config
from oci_acme_publisher.fingerprint import certificate_sha256

from .test_certificate_validator import material_with_root


def test_builds_chain_ending_in_pinned_root(tmp_path: Path) -> None:
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
    result = build_oci_chain(material, certificate, config.compatibility)
    assert result.cert_chain_pem.endswith(root.public_bytes(serialization.Encoding.PEM))
    assert material.leaf_pem not in result.cert_chain_pem


def test_chain_rejects_unpinned_root_and_disallowed_issuer(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    material, root = material_with_root()
    root_path = tmp_path / "root.pem"
    root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    base_chain = config.certificates[0].chain.model_copy(update={"root_pem_path": str(root_path)})
    unpinned = config.certificates[0].model_copy(
        update={"chain": base_chain.model_copy(update={"allowed_root_sha256": ("0" * 64,)})}
    )
    with pytest.raises(ChainBuildError, match="fingerprint"):
        build_oci_chain(material, unpinned, config.compatibility)

    disallowed = config.certificates[0].model_copy(
        update={
            "chain": base_chain.model_copy(
                update={
                    "allowed_root_sha256": (certificate_sha256(root),),
                    "allowed_issuer_common_names": ("other.example",),
                }
            )
        }
    )
    with pytest.raises(ChainBuildError, match="issuer Common Name"):
        build_oci_chain(material, disallowed, config.compatibility)


def test_chain_rejects_a_root_only_acme_chain(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    material, root = material_with_root()
    root_path = tmp_path / "root.pem"
    root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    chain = config.certificates[0].chain.model_copy(
        update={
            "root_pem_path": str(root_path),
            "allowed_root_sha256": (certificate_sha256(root),),
        }
    )
    certificate = config.certificates[0].model_copy(update={"chain": chain})
    root_only = material.__class__(
        material.leaf,
        (root,),
        material.private_key,
        material.leaf_pem,
        root.public_bytes(serialization.Encoding.PEM),
        material.private_key_pem,
    )
    with pytest.raises(ChainBuildError, match="chain is empty"):
        build_oci_chain(root_only, certificate, config.compatibility)


def test_chain_helpers_reject_missing_root_unsupported_key_and_non_ca() -> None:
    config = load_config("config/config.example.yaml")
    missing_root = config.certificates[0].model_copy(
        update={
            "chain": config.certificates[0].chain.model_copy(
                update={"root_pem_path": "/definitely/missing/root.pem"}
            )
        }
    )
    with pytest.raises(ChainBuildError, match="cannot be loaded"):
        _load_pinned_root(missing_root)

    with pytest.raises(ChainBuildError, match="unsupported key"):
        _algorithm_family(SimpleNamespace(public_key=lambda: object()))

    material, _ = material_with_root()
    with pytest.raises(ChainBuildError, match="not a CA"):
        _validate_ca(material.leaf)


def test_chain_rejects_unconfigured_root_left_inside_acme_chain(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    material, _ = material_with_root()
    unrelated_material, unrelated_root = material_with_root()
    del unrelated_material
    root_path = tmp_path / "unrelated-root.pem"
    root_path.write_bytes(unrelated_root.public_bytes(serialization.Encoding.PEM))
    chain = config.certificates[0].chain.model_copy(
        update={
            "root_pem_path": str(root_path),
            "allowed_root_sha256": (certificate_sha256(unrelated_root),),
            "allowed_issuer_common_names": ("issuer.example",),
        }
    )
    certificate = config.certificates[0].model_copy(update={"chain": chain})
    with pytest.raises(ChainBuildError, match="must not contain"):
        build_oci_chain(material, certificate, config.compatibility)
