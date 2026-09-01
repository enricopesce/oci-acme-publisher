"""Atomic, generation-based storage for native ACME certificate material."""

from __future__ import annotations

import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from .config import AcmeConfig, CertificateConfig

_MAX_CERTIFICATE_PEM_BYTES = 10_240
_MAX_PRIVATE_KEY_PEM_BYTES = 5_120
_MAX_CHAIN_PEM_BYTES = 51_200


class CertificateStoreError(ValueError):
    """Stored certificate material failed the local filesystem policy."""


@dataclass(frozen=True, slots=True)
class LineageMaterial:
    """Parsed certificate material kept out of application state and logs."""

    leaf: x509.Certificate
    intermediates: tuple[x509.Certificate, ...]
    private_key: PrivateKeyTypes
    leaf_pem: bytes
    chain_pem: bytes
    private_key_pem: bytes


def certificate_directory(acme: AcmeConfig, certificate: CertificateConfig) -> Path:
    return Path(acme.certificates_dir) / certificate.id


@dataclass(frozen=True, slots=True)
class NativeCertificateStore:
    """Commit complete generations and expose one atomic ``current`` pointer."""

    root: Path
    expected_owner_uid: int

    def exists(self, certificate: CertificateConfig) -> bool:
        return (self.root / certificate.id / "current").is_symlink()

    def load(self, certificate: CertificateConfig) -> LineageMaterial:
        lineage = self.root / certificate.id
        current = lineage / "current"
        if not current.is_symlink():
            raise CertificateStoreError("native ACME certificate generation is unavailable")
        generation = Path(os.path.realpath(current))
        archive = (lineage / "generations").resolve()
        try:
            generation.relative_to(archive)
        except ValueError as error:
            raise CertificateStoreError(
                "current certificate generation escapes its archive"
            ) from error
        if not generation.is_dir():
            raise CertificateStoreError("current certificate generation is unavailable")
        leaf_pem = self._read(generation / "cert.pem", _MAX_CERTIFICATE_PEM_BYTES, False)
        chain_pem = self._read(generation / "chain.pem", _MAX_CHAIN_PEM_BYTES, False)
        private_key_pem = self._read(generation / "privkey.pem", _MAX_PRIVATE_KEY_PEM_BYTES, True)
        try:
            intermediates = tuple(x509.load_pem_x509_certificates(chain_pem))
            return LineageMaterial(
                leaf=x509.load_pem_x509_certificate(leaf_pem),
                intermediates=intermediates,
                private_key=serialization.load_pem_private_key(private_key_pem, password=None),
                leaf_pem=leaf_pem,
                chain_pem=chain_pem,
                private_key_pem=private_key_pem,
            )
        except (TypeError, ValueError) as error:
            raise CertificateStoreError("native ACME certificate parsing failed") from error

    def commit(
        self,
        certificate: CertificateConfig,
        *,
        leaf_pem: bytes,
        chain_pem: bytes,
        private_key_pem: bytes,
        generation_name: str,
    ) -> LineageMaterial:
        lineage = self.root / certificate.id
        generations = lineage / "generations"
        self._ensure_directory(lineage)
        self._ensure_directory(generations)
        generation = generations / generation_name
        if generation.exists():
            raise CertificateStoreError("certificate generation already exists")
        generation.mkdir(mode=0o700)
        self._set_owner_if_root(generation)
        try:
            self._write_new(generation / "cert.pem", leaf_pem, 0o640)
            self._write_new(generation / "chain.pem", chain_pem, 0o640)
            self._write_new(generation / "privkey.pem", private_key_pem, 0o600)
            temporary = lineage / f".current-{secrets.token_hex(12)}"
            temporary.symlink_to(generation.relative_to(lineage))
            os.replace(temporary, lineage / "current")
            if os.geteuid() == 0:
                os.chown(
                    lineage / "current",
                    self.expected_owner_uid,
                    -1,
                    follow_symlinks=False,
                )
        except BaseException:
            for name in ("cert.pem", "chain.pem", "privkey.pem"):
                (generation / name).unlink(missing_ok=True)
            try:
                generation.rmdir()
            except OSError:
                pass
            raise
        return self.load(certificate)

    def _read(self, path: Path, maximum_bytes: int, private: bool) -> bytes:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as error:
            raise CertificateStoreError("certificate generation file is unavailable") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != self.expected_owner_uid:
                raise CertificateStoreError("certificate generation file ownership is invalid")
            if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise CertificateStoreError("certificate generation file permissions are unsafe")
            if private and metadata.st_mode & (stat.S_IRGRP | stat.S_IROTH):
                raise CertificateStoreError("private key is readable outside publisher account")
            content = os.read(descriptor, maximum_bytes + 1)
            if len(content) > maximum_bytes:
                raise CertificateStoreError("certificate generation file exceeds size limit")
            return content
        finally:
            os.close(descriptor)

    def _ensure_directory(self, path: Path) -> None:
        path.mkdir(mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
        self._set_owner_if_root(path)

    def _set_owner_if_root(self, path: Path) -> None:
        if os.geteuid() == 0:
            os.chown(path, self.expected_owner_uid, -1)

    def _write_new(self, path: Path, content: bytes, mode: int) -> None:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, mode)
        try:
            if os.geteuid() == 0:
                os.fchown(descriptor, self.expected_owner_uid, -1)
            offset = 0
            while offset < len(content):
                offset += os.write(descriptor, content[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def certificate_store(acme: AcmeConfig, expected_owner_uid: int) -> NativeCertificateStore:
    return NativeCertificateStore(Path(acme.certificates_dir), expected_owner_uid)
