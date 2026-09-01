from __future__ import annotations

import os
from pathlib import Path

import pytest

from oci_acme_publisher.certificate_store import (
    CertificateStoreError,
    NativeCertificateStore,
    certificate_directory,
    certificate_store,
)
from oci_acme_publisher.config import load_config

from .test_certificate_validator import material_with_root


def test_store_commits_and_loads_one_atomic_generation(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    certificate = config.certificates[0]
    material, _ = material_with_root()
    store = NativeCertificateStore(tmp_path, os.getuid())

    loaded = store.commit(
        certificate,
        leaf_pem=material.leaf_pem,
        chain_pem=material.chain_pem,
        private_key_pem=material.private_key_pem,
        generation_name="generation-1",
    )

    assert loaded.leaf.serial_number == material.leaf.serial_number
    assert len(loaded.intermediates) == 2
    assert (tmp_path / "main-site" / "current").is_symlink()


def test_store_rejects_current_pointer_outside_generation_archive(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    lineage = tmp_path / "main-site"
    lineage.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (lineage / "current").symlink_to(outside)

    with pytest.raises(CertificateStoreError, match="escapes"):
        NativeCertificateStore(tmp_path, os.getuid()).load(config.certificates[0])


def test_store_rejects_private_key_with_group_read_access(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    certificate = config.certificates[0]
    material, _ = material_with_root()
    store = NativeCertificateStore(tmp_path, os.getuid())
    store.commit(
        certificate,
        leaf_pem=material.leaf_pem,
        chain_pem=material.chain_pem,
        private_key_pem=material.private_key_pem,
        generation_name="generation-1",
    )
    private_key = tmp_path / "main-site" / "generations" / "generation-1" / "privkey.pem"
    private_key.chmod(0o640)

    with pytest.raises(CertificateStoreError, match="private key is readable"):
        store.load(certificate)

    with pytest.raises(CertificateStoreError, match="ownership"):
        NativeCertificateStore(tmp_path, os.getuid() + 1).load(certificate)


def test_store_refuses_duplicate_generation(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    certificate = config.certificates[0]
    material, _ = material_with_root()
    store = NativeCertificateStore(tmp_path, os.getuid())
    arguments = {
        "leaf_pem": material.leaf_pem,
        "chain_pem": material.chain_pem,
        "private_key_pem": material.private_key_pem,
        "generation_name": "generation-1",
    }
    store.commit(certificate, **arguments)
    with pytest.raises(CertificateStoreError, match="already exists"):
        store.commit(certificate, **arguments)


def test_store_helpers_use_configured_certificate_identity(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    acme = config.acme.model_copy(update={"certificates_dir": str(tmp_path)})
    assert certificate_directory(acme, config.certificates[0]) == tmp_path / "main-site"
    assert certificate_store(acme, 123).expected_owner_uid == 123


def test_store_rejects_missing_or_dangling_current_generation(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    certificate = config.certificates[0]
    store = NativeCertificateStore(tmp_path, os.getuid())
    assert not store.exists(certificate)
    with pytest.raises(CertificateStoreError, match="unavailable"):
        store.load(certificate)

    lineage = tmp_path / certificate.id
    lineage.mkdir()
    (lineage / "current").symlink_to("generations/missing")
    with pytest.raises(CertificateStoreError, match="unavailable"):
        store.load(certificate)


def test_store_rejects_missing_unsafe_and_oversized_generation_files(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    certificate = config.certificates[0]
    material, _ = material_with_root()
    store = NativeCertificateStore(tmp_path, os.getuid())
    store.commit(
        certificate,
        leaf_pem=material.leaf_pem,
        chain_pem=material.chain_pem,
        private_key_pem=material.private_key_pem,
        generation_name="generation-1",
    )
    generation = tmp_path / certificate.id / "generations" / "generation-1"

    (generation / "cert.pem").unlink()
    with pytest.raises(CertificateStoreError, match="unavailable"):
        store.load(certificate)
    (generation / "cert.pem").write_bytes(material.leaf_pem)
    (generation / "cert.pem").chmod(0o660)
    with pytest.raises(CertificateStoreError, match="permissions"):
        store.load(certificate)
    (generation / "cert.pem").chmod(0o640)
    (generation / "chain.pem").write_bytes(b"x" * 51_201)
    with pytest.raises(CertificateStoreError, match="size limit"):
        store.load(certificate)


def test_store_rejects_empty_chain_and_invalid_pem(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    certificate = config.certificates[0]
    material, _ = material_with_root()
    store = NativeCertificateStore(tmp_path, os.getuid())
    store.commit(
        certificate,
        leaf_pem=material.leaf_pem,
        chain_pem=material.chain_pem,
        private_key_pem=material.private_key_pem,
        generation_name="generation-1",
    )
    generation = tmp_path / certificate.id / "generations" / "generation-1"
    (generation / "chain.pem").write_bytes(b"")
    with pytest.raises(CertificateStoreError, match="parsing failed"):
        store.load(certificate)

    (generation / "chain.pem").write_bytes(material.chain_pem)
    (generation / "cert.pem").write_bytes(b"not-pem")
    with pytest.raises(CertificateStoreError, match="parsing failed"):
        store.load(certificate)


def test_store_cleans_incomplete_generation_after_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = load_config("config/config.example.yaml")
    certificate = config.certificates[0]
    material, _ = material_with_root()
    store = NativeCertificateStore(tmp_path, os.getuid())
    original = store._write_new
    calls = 0

    def fail_second_write(path: Path, content: bytes, mode: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            (path.parent / "unexpected").write_text("keep", encoding="ascii")
            raise OSError("injected")
        original(path, content, mode)

    monkeypatch.setattr(NativeCertificateStore, "_write_new", staticmethod(fail_second_write))
    with pytest.raises(OSError, match="injected"):
        store.commit(
            certificate,
            leaf_pem=material.leaf_pem,
            chain_pem=material.chain_pem,
            private_key_pem=material.private_key_pem,
            generation_name="incomplete",
        )
    incomplete = tmp_path / certificate.id / "generations" / "incomplete"
    assert incomplete.exists()
    (incomplete / "unexpected").unlink()
    incomplete.rmdir()
