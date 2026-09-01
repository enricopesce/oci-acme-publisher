from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from oci_acme_publisher import http01_preflight
from oci_acme_publisher.config import load_config
from oci_acme_publisher.http01_preflight import (
    Http01Preflight,
    PreflightError,
    _request_address,
    _validate_addresses,
    _write_challenge,
)


async def _http01_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    request = await reader.readuntil(b"\r\n\r\n")
    token = request.split(b" ")[1].rsplit(b"/", maxsplit=1)[1]
    writer.write(
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(token)).encode("ascii")
        + b"\r\nConnection: close\r\n\r\n"
        + token
    )
    await writer.drain()
    writer.close()


async def test_preflight_removes_synthetic_file_after_response_mismatch(tmp_path: Path) -> None:
    server = await asyncio.start_server(_http01_server, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1] if server.sockets else 0
    config = load_config("config/config.example.yaml")
    self_check = config.http01.self_check.model_copy(update={"reject_non_global_addresses": False})
    http01 = config.http01.model_copy(
        update={"webroot_base": str(tmp_path), "self_check": self_check}
    )

    async def resolver(_: str) -> tuple[str, ...]:
        return ("127.0.0.1",)

    try:
        with pytest.raises(PreflightError, match="one or more"):
            await Http01Preflight(http01, resolver=resolver, port=port).run(config.certificates[0])
    finally:
        server.close()
        await server.wait_closed()
    challenge_directory = tmp_path / "main-site" / ".well-known" / "acme-challenge"
    assert list(challenge_directory.iterdir()) == []


async def test_preflight_disabled_performs_no_filesystem_or_dns_io(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    policy = config.http01.self_check.model_copy(update={"enabled": False})
    http01 = config.http01.model_copy(update={"webroot_base": str(tmp_path), "self_check": policy})

    async def resolver(_: str) -> tuple[str, ...]:
        raise AssertionError("disabled preflight must not resolve")

    await Http01Preflight(http01, resolver=resolver).run(config.certificates[0])
    assert list(tmp_path.iterdir()) == []


async def test_preflight_checks_every_address_and_removes_successful_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config("config/config.example.yaml")
    policy = config.http01.self_check.model_copy(update={"reject_non_global_addresses": False})
    http01 = config.http01.model_copy(update={"webroot_base": str(tmp_path), "self_check": policy})
    requests: list[tuple[str, str]] = []

    async def resolver(_: str) -> tuple[str, ...]:
        return ("127.0.0.1", "127.0.0.2")

    async def request(address: str, hostname: str, *_: object) -> None:
        requests.append((address, hostname))

    monkeypatch.setattr(http01_preflight, "_request_address", request)
    await Http01Preflight(http01, resolver=resolver).run(config.certificates[0])

    assert set(requests) == {
        ("127.0.0.1", "example.com"),
        ("127.0.0.2", "example.com"),
        ("127.0.0.1", "www.example.com"),
        ("127.0.0.2", "www.example.com"),
    }
    challenge_directory = tmp_path / "main-site" / ".well-known" / "acme-challenge"
    assert list(challenge_directory.iterdir()) == []


async def test_preflight_can_tolerate_partial_address_failure_when_configured(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config("config/config.example.yaml")
    policy = config.http01.self_check.model_copy(
        update={"reject_non_global_addresses": False, "require_all_addresses": False}
    )
    http01 = config.http01.model_copy(update={"webroot_base": str(tmp_path), "self_check": policy})

    async def resolver(_: str) -> tuple[str, ...]:
        return ("127.0.0.1", "127.0.0.2")

    async def request(address: str, *_: object) -> None:
        if address.endswith(".2"):
            raise PreflightError("simulated route mismatch")

    monkeypatch.setattr(http01_preflight, "_request_address", request)
    await Http01Preflight(http01, resolver=resolver).run(config.certificates[0])


async def test_preflight_uses_domain_dns_addresses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config("config/config.example.yaml")
    http01 = config.http01.model_copy(update={"webroot_base": str(tmp_path)})
    requests: list[tuple[str, str]] = []

    async def resolver(_: str) -> tuple[str, ...]:
        return ("129.152.26.163", "129.152.26.164")

    async def request(address: str, hostname: str, *_: object) -> None:
        requests.append((address, hostname))

    monkeypatch.setattr(http01_preflight, "_request_address", request)
    await Http01Preflight(http01, resolver=resolver).run(config.certificates[0])
    assert set(requests) == {
        ("129.152.26.163", "example.com"),
        ("129.152.26.164", "example.com"),
        ("129.152.26.163", "www.example.com"),
        ("129.152.26.164", "www.example.com"),
    }


@pytest.mark.parametrize("addresses", (("not-ip",), ("127.0.0.1",)))
def test_preflight_address_validation_rejects_invalid_and_non_global_addresses(
    addresses: tuple[str, ...],
) -> None:
    with pytest.raises(PreflightError):
        _validate_addresses(addresses, reject_non_global=True)


def test_synthetic_challenge_write_is_atomic_and_private(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "token"
    _write_challenge(path, b"expected")
    assert path.read_bytes() == b"expected"
    assert path.stat().st_mode & 0o027 == 0


def test_root_synthetic_challenge_is_assigned_to_publisher(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ownership: list[tuple[int, int, int]] = []
    monkeypatch.setattr(http01_preflight.os, "geteuid", lambda: 0)
    monkeypatch.setattr(http01_preflight, "publisher_uid", lambda: 987)
    monkeypatch.setattr(
        http01_preflight.os,
        "fchown",
        lambda descriptor, uid, gid: ownership.append((descriptor, uid, gid)),
    )

    _write_challenge(tmp_path / "token", b"expected")

    assert ownership and ownership[0][1:] == (987, -1)


async def test_direct_http_preflight_request_requires_exact_non_chunked_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b"expected-content"
    written: list[bytes] = []

    class Reader:
        async def readuntil(self, _: bytes) -> bytes:
            return b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n"

        async def readexactly(self, size: int) -> bytes:
            assert size == len(expected)
            return expected

    class Writer:
        def write(self, content: bytes) -> None:
            written.append(content)

        async def drain(self) -> None:
            return None

        def close(self) -> None:
            return None

        async def wait_closed(self) -> None:
            return None

    async def connect(*_: object, **__: object) -> tuple[Reader, Writer]:
        return Reader(), Writer()

    monkeypatch.setattr(http01_preflight.asyncio, "open_connection", connect)
    await _request_address("203.0.113.1", "example.com", "T" * 20, expected, 1, 1, 80)
    assert b"Host: example.com" in written[0]


@pytest.mark.parametrize(
    "headers",
    (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n",
        b"HTTP/1.1 302 Found\r\nContent-Length: 1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n",
    ),
)
async def test_direct_http_preflight_rejects_unsafe_headers(
    monkeypatch: pytest.MonkeyPatch, headers: bytes
) -> None:
    class Reader:
        async def readuntil(self, _: bytes) -> bytes:
            return headers

        async def readexactly(self, _: int) -> bytes:
            return b"x"

    class Writer:
        def write(self, _: bytes) -> None:
            return None

        async def drain(self) -> None:
            return None

        def close(self) -> None:
            return None

        async def wait_closed(self) -> None:
            return None

    async def connect(*_: object, **__: object) -> tuple[Reader, Writer]:
        return Reader(), Writer()

    monkeypatch.setattr(http01_preflight.asyncio, "open_connection", connect)
    with pytest.raises(PreflightError):
        await _request_address("203.0.113.1", "example.com", "T" * 20, b"x", 1, 1, 80)
