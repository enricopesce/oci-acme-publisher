"""Read-only operational preflight for roots, OCI identity and HTTP-01 routing."""

from __future__ import annotations

import asyncio
import subprocess
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .config import (
    AppConfig,
    CertificateConfig,
    Http01Config,
    OciConfig,
)
from .http01_preflight import Http01Preflight, PreflightError
from .oci_clients import OciCertificatesAdapters, OciExecutor, create_certificates_adapters

AdaptersFactory = Callable[[str, OciConfig], OciCertificatesAdapters]
ClockChecker = Callable[[int], None]
ResponderChecker = Callable[[Http01Config], None]


class OperationalPreflight:
    """Verify every external prerequisite without changing OCI or ACME state."""

    def __init__(
        self,
        adapters_factory: AdaptersFactory = create_certificates_adapters,
        clock_checker: ClockChecker | None = None,
        responder_checker: ResponderChecker | None = None,
    ) -> None:
        self._adapters_factory = adapters_factory
        self._clock_checker = clock_checker or self._verify_clock
        self._responder_checker = responder_checker or self._verify_responder

    def run(self, config: AppConfig, certificates: Sequence[CertificateConfig]) -> None:
        """Validate local root pins, OCI read access, then every HTTP-01 route."""
        self._clock_checker(config.global_.clock_skew_tolerance_seconds)
        self._responder_checker(config.http01)
        for certificate in certificates:
            self._verify_webroot(config.http01, certificate)
            self._verify_root_pin(certificate)
        for certificate in certificates:
            self._verify_oci_read(config, certificate)
        for certificate in certificates:
            asyncio.run(Http01Preflight(config.http01).run(certificate))

    @staticmethod
    def _verify_root_pin(certificate: CertificateConfig) -> None:
        try:
            root = x509.load_pem_x509_certificate(
                Path(certificate.chain.root_pem_path).read_bytes()
            )
        except (OSError, ValueError) as error:
            raise PreflightError("configured chain root is unreadable or invalid") from error
        fingerprint = root.fingerprint(hashes.SHA256()).hex()
        if fingerprint not in certificate.chain.allowed_root_sha256:
            raise PreflightError("configured chain root is not allowlisted")

    def _verify_oci_read(self, config: AppConfig, certificate: CertificateConfig) -> None:
        adapters = self._adapters_factory(certificate.oci.region, config.oci)
        certificate_ocid = certificate.oci.certificate_ocid
        if certificate_ocid is None:
            return
        executor = OciExecutor()
        try:
            asyncio.run(
                executor.run(
                    adapters.management.get_certificate,
                    certificate_ocid,
                    opc_request_id=str(uuid.uuid4()),
                )
            )
        finally:
            executor.close()

    @staticmethod
    def _verify_clock(_: int) -> None:
        """Require the OS time service to report a synchronized clock."""
        try:
            result = subprocess.run(
                ["/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--value"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise PreflightError("system clock synchronization cannot be verified") from error
        if result.returncode != 0 or result.stdout.strip().lower() != "yes":
            raise PreflightError("system clock is not synchronized")

    @staticmethod
    def _verify_webroot(http01: Http01Config, certificate: CertificateConfig) -> None:
        webroot = Path(http01.webroot_base) / certificate.webroot_id
        if not webroot.is_dir():
            raise PreflightError("configured HTTP-01 webroot is unavailable")

    @staticmethod
    def _verify_responder(http01: Http01Config) -> None:
        """Check the local readiness endpoint before publishing a synthetic token."""
        asyncio.run(OperationalPreflight._request_readiness(http01))

    @staticmethod
    async def _request_readiness(http01: Http01Config) -> None:
        responder = http01.responder
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(responder.bind_address, responder.bind_port), timeout=5
            )
            try:
                request = (
                    f"GET {responder.readiness_path} HTTP/1.1\r\n"
                    "Host: localhost\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
                writer.write(request)
                await writer.drain()
                response = await asyncio.wait_for(reader.read(4096), timeout=5)
            finally:
                writer.close()
                await writer.wait_closed()
        except (OSError, TimeoutError) as error:
            raise PreflightError("local HTTP-01 responder is unavailable") from error
        if not response.startswith(b"HTTP/1.1 200 "):
            raise PreflightError("local HTTP-01 responder is not ready")
