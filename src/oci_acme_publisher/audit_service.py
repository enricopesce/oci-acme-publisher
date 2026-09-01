"""TLS endpoint audit with direct DNS address checks and system trust validation."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from cryptography import x509

from .config import AuditConfig, AuditEndpoint
from .fingerprint import certificate_sha256
from .models import AuditMode

Resolver = Callable[[str], Awaitable[tuple[str, ...]]]
Probe = Callable[[str, str, int, float], Awaitable[str]]


class AuditError(RuntimeError):
    """An enforce-mode audit failed to converge to the expected certificate."""


async def resolve_endpoint_addresses(hostname: str) -> tuple[str, ...]:
    """Resolve all A and AAAA addresses for an audit endpoint."""
    loop = asyncio.get_running_loop()
    results = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    addresses = tuple(sorted({result[4][0] for result in results}))
    if not addresses:
        raise AuditError("endpoint DNS returned no addresses")
    return addresses


def fixed_address_resolver(addresses: tuple[str, ...]) -> Resolver:
    """Return a resolver pinned to validated public addresses for split-DNS hosts."""
    if not addresses:
        raise ValueError("fixed audit resolver requires at least one address")

    async def resolve(_: str) -> tuple[str, ...]:
        return addresses

    return resolve


def _validate_addresses(addresses: tuple[str, ...], reject_non_global: bool) -> None:
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as error:
            raise AuditError("endpoint DNS returned an invalid address") from error
        if reject_non_global and not parsed.is_global:
            raise AuditError("endpoint DNS returned a non-global address")


async def probe_tls_fingerprint(
    address: str, hostname: str, port: int, timeout_seconds: float
) -> str:
    """Connect directly with SNI and system trust, then fingerprint the peer leaf."""
    return await _probe_tls_fingerprint(
        address, hostname, port, timeout_seconds, ssl.create_default_context()
    )


def pinned_root_probe(root_pem_path: str) -> Probe:
    """Build a TLS probe that trusts only the configured, pinned test root."""
    context = ssl.create_default_context(cafile=root_pem_path)

    async def probe(address: str, hostname: str, port: int, timeout_seconds: float) -> str:
        return await _probe_tls_fingerprint(address, hostname, port, timeout_seconds, context)

    return probe


async def _probe_tls_fingerprint(
    address: str,
    hostname: str,
    port: int,
    timeout_seconds: float,
    context: ssl.SSLContext,
) -> str:
    """Connect directly with an explicitly selected TLS trust context."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port, ssl=context, server_hostname=hostname),
            timeout=timeout_seconds,
        )
    except (OSError, TimeoutError, ssl.SSLError) as error:
        raise AuditError("TLS endpoint connection or validation failed") from error
    del reader
    try:
        tls_object = writer.get_extra_info("ssl_object")
        if not isinstance(tls_object, ssl.SSLObject):
            raise AuditError("TLS endpoint did not provide an SSL object")
        peer = tls_object.getpeercert(binary_form=True)
        if not peer:
            raise AuditError("TLS endpoint did not provide a leaf certificate")
        return certificate_sha256(x509.load_der_x509_certificate(peer))
    except ValueError as error:
        raise AuditError("TLS endpoint leaf certificate is malformed") from error
    finally:
        writer.close()
        await writer.wait_closed()


@dataclass(frozen=True, slots=True)
class AuditResult:
    """Convergence result that can be persisted and notified without PEM content."""

    successful: bool
    attempts: int
    failed_endpoints: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuditService:
    """Retry audit during propagation; observe mode never raises for mismatch."""

    configuration: AuditConfig
    resolver: Resolver = resolve_endpoint_addresses
    probe: Probe = probe_tls_fingerprint

    async def audit(self, expected_fingerprint: str) -> AuditResult:
        """Check each configured endpoint until all required addresses converge or timeout."""
        if self.configuration.mode is AuditMode.DISABLED:
            return AuditResult(True, 0, ())
        deadline = time.monotonic() + self.configuration.propagation_timeout_seconds
        attempts = 0
        latest_failures: tuple[str, ...] = ()
        while True:
            attempts += 1
            latest_failures = await self._once(expected_fingerprint)
            if not latest_failures:
                return AuditResult(True, attempts, ())
            if time.monotonic() >= deadline:
                result = AuditResult(False, attempts, latest_failures)
                if self.configuration.mode is AuditMode.ENFORCE:
                    raise AuditError("TLS audit did not converge before propagation timeout")
                return result
            await asyncio.sleep(self.configuration.retry_interval_seconds)

    async def _once(self, expected_fingerprint: str) -> tuple[str, ...]:
        failures: list[str] = []
        for endpoint in self.configuration.endpoints:
            if not await self._endpoint_matches(endpoint, expected_fingerprint):
                failures.append(f"{endpoint.hostname}:{endpoint.port}")
        return tuple(failures)

    async def _endpoint_matches(self, endpoint: AuditEndpoint, expected_fingerprint: str) -> bool:
        try:
            addresses = await self.resolver(endpoint.hostname)
            _validate_addresses(addresses, self.configuration.reject_non_global_addresses)
            results = await asyncio.gather(
                *(
                    self.probe(
                        address,
                        endpoint.hostname,
                        endpoint.port,
                        float(self.configuration.retry_interval_seconds),
                    )
                    for address in addresses
                ),
                return_exceptions=True,
            )
        except AuditError:
            return False
        matches = [result == expected_fingerprint for result in results if isinstance(result, str)]
        if self.configuration.require_all_addresses:
            return len(matches) == len(addresses) and all(matches)
        return any(matches)
