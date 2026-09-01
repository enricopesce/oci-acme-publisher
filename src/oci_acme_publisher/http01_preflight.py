"""Direct HTTP-01 preflight checks for every configured DNS address."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import secrets
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from .config import CertificateConfig, Http01Config
from .http01_paths import publisher_uid

Resolver = Callable[[str], Awaitable[tuple[str, ...]]]


class PreflightError(RuntimeError):
    """The local HTTP-01 route cannot be safely confirmed."""


async def resolve_all_addresses(hostname: str) -> tuple[str, ...]:
    """Resolve both A and AAAA records without trusting an HTTP proxy."""
    loop = asyncio.get_running_loop()
    records = await loop.getaddrinfo(hostname, 80, type=socket.SOCK_STREAM)
    addresses = tuple(sorted({record[4][0] for record in records}))
    if not addresses:
        raise PreflightError("DNS did not return an address")
    return addresses


def _validate_addresses(addresses: tuple[str, ...], reject_non_global: bool) -> None:
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as error:
            raise PreflightError("DNS returned an invalid IP address") from error
        if reject_non_global and not parsed.is_global:
            raise PreflightError("DNS returned a non-global address")


def _write_challenge(path: Path, content: bytes) -> None:
    """Atomically create the exact temporary challenge with non-public permissions."""
    path.parent.mkdir(mode=0o2750, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(12)}")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o640)
    try:
        os.write(descriptor, content)
        # Administrative preflight is commonly invoked as root, while the
        # responder deliberately accepts only files owned by the publisher.
        # The timer already runs as that account, so retain its normal ownership.
        if os.geteuid() == 0:
            os.fchown(descriptor, publisher_uid(), -1)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def _remove_challenge(path: Path) -> None:
    """Remove the synthetic token; an already-removed file is harmless."""
    try:
        path.unlink()
    except FileNotFoundError:
        return None


async def _request_address(
    address: str,
    hostname: str,
    token: str,
    expected: bytes,
    connect_timeout_seconds: int,
    response_timeout_seconds: int,
    port: int,
) -> None:
    """Make one HTTP/1.1 request directly to a resolved address without redirects."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=connect_timeout_seconds
        )
    except (OSError, TimeoutError) as error:
        raise PreflightError("unable to connect to resolved address") from error
    request = (
        f"GET /.well-known/acme-challenge/{token} HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    try:
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=response_timeout_seconds)
        header_bytes = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"), response_timeout_seconds
        )
        header_lines = header_bytes.decode("iso-8859-1").split("\r\n")
        if not header_lines or header_lines[0] != "HTTP/1.1 200 OK":
            raise PreflightError("HTTP-01 preflight response was not 200")
        headers: dict[str, str] = {}
        for line in header_lines[1:]:
            if not line:
                continue
            name, separator, value = line.partition(":")
            if not separator:
                raise PreflightError("HTTP-01 preflight response has malformed header")
            lower_name = name.lower()
            if lower_name in headers:
                raise PreflightError("HTTP-01 preflight response repeats a header")
            headers[lower_name] = value.strip()
        if "transfer-encoding" in headers:
            raise PreflightError("HTTP-01 preflight response must not be chunked")
        if headers.get("content-length") != str(len(expected)):
            raise PreflightError("HTTP-01 preflight response has unexpected content length")
        body = await asyncio.wait_for(reader.readexactly(len(expected)), response_timeout_seconds)
        if body != expected:
            raise PreflightError("HTTP-01 preflight response body does not match")
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, UnicodeDecodeError) as error:
        raise PreflightError("HTTP-01 preflight response is malformed") from error
    finally:
        writer.close()
        await writer.wait_closed()


@dataclass(frozen=True, slots=True)
class Http01Preflight:
    """Synthetic file and direct checks; this is not a CA multi-perspective proof."""

    http01: Http01Config
    resolver: Resolver = resolve_all_addresses
    port: int = 80

    async def run(self, certificate: CertificateConfig) -> None:
        """Verify all configured domains and addresses, always removing the synthetic file."""
        policy = self.http01.self_check
        if not policy.enabled:
            return
        token = secrets.token_urlsafe(32)
        content = secrets.token_urlsafe(48).encode("ascii")
        challenge = (
            Path(self.http01.webroot_base)
            / certificate.webroot_id
            / ".well-known"
            / "acme-challenge"
            / token
        )
        await asyncio.to_thread(_write_challenge, challenge, content)
        try:
            semaphore = asyncio.Semaphore(self.http01.responder.max_concurrent_requests)
            await asyncio.wait_for(
                asyncio.gather(
                    *(
                        self._check_domain(certificate, domain, token, content, semaphore)
                        for domain in certificate.domains
                    )
                ),
                timeout=policy.total_timeout_seconds,
            )
        except TimeoutError as error:
            raise PreflightError("HTTP-01 preflight exceeded its total timeout") from error
        finally:
            await asyncio.to_thread(_remove_challenge, challenge)

    async def _check_domain(
        self,
        certificate: CertificateConfig,
        domain: str,
        token: str,
        content: bytes,
        semaphore: asyncio.Semaphore,
    ) -> None:
        addresses = await self.resolver(domain)
        _validate_addresses(addresses, self.http01.self_check.reject_non_global_addresses)
        results = await asyncio.gather(
            *(
                self._check_address(address, domain, token, content, semaphore)
                for address in addresses
            ),
            return_exceptions=True,
        )
        errors = [result for result in results if isinstance(result, BaseException)]
        if errors and self.http01.self_check.require_all_addresses:
            raise PreflightError("one or more HTTP-01 addresses failed preflight") from errors[0]

    async def _check_address(
        self,
        address: str,
        domain: str,
        token: str,
        content: bytes,
        semaphore: asyncio.Semaphore,
    ) -> None:
        async with semaphore:
            await _request_address(
                address,
                domain,
                token,
                content,
                self.http01.self_check.connect_timeout_seconds,
                self.http01.self_check.response_timeout_seconds,
                self.port,
            )
