from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from oci_acme_publisher.config import load_config
from oci_acme_publisher.http01_paths import ChallengeFileError, ChallengeFileReader
from oci_acme_publisher.http01_responder import (
    STATE_KEY,
    TOKEN_PATTERN,
    ResponderState,
    _challenge,
    _error_middleware,
    _single_host,
    config_host_webroots,
    create_app,
    normalize_host_header,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [("EXAMPLE.com:8080", "example.com"), ("xn--bcher-kva.example", "xn--bcher-kva.example")],
)
def test_host_normalization(value: str, expected: str) -> None:
    assert normalize_host_header(value) == expected


@pytest.mark.parametrize(
    "value", ["example.com/path", "user@example.com", "example.com:0", "[::1]"]
)
def test_host_normalization_rejects_ambiguous_values(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_host_header(value)


def test_token_pattern_rejects_traversal() -> None:
    assert TOKEN_PATTERN.fullmatch("../" + "a" * 20) is None
    assert TOKEN_PATTERN.fullmatch("a" * 19) is None


def test_config_host_webroots_maps_all_configured_domains() -> None:
    config = load_config("config/config.example.yaml")
    assert config_host_webroots(config) == {
        "example.com": "main-site",
        "www.example.com": "main-site",
    }


def test_single_host_rejects_missing_duplicate_and_non_ascii_headers() -> None:
    class Request:
        def __init__(self, headers: tuple[tuple[bytes, bytes], ...]) -> None:
            self.raw_headers = headers

    assert _single_host(Request(((b"Host", b"example.com"),))) == "example.com"
    for headers in ((), ((b"Host", b"a.example"), (b"Host", b"b.example")), ((b"Host", b"\xff"),)):
        with pytest.raises(ValueError):
            _single_host(Request(headers))


def test_responder_state_reports_unavailable_challenge_directory(tmp_path: Path) -> None:
    class Reader:
        def _open_challenge_directory(self, _: str) -> int:
            raise ChallengeFileError("unavailable")

    state = ResponderState(
        host_webroots={},
        reader=Reader(),  # type: ignore[arg-type]
        health_path="/healthz",
        readiness_path="/readyz",
        required_webroots=("main-site",),
        request_semaphore=asyncio.Semaphore(1),
    )
    assert state.ready() is False


async def test_responder_serves_only_allowlisted_challenge(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    config = config.model_copy(
        update={"http01": config.http01.model_copy(update={"webroot_base": str(tmp_path)})}
    )
    token = "A" * 20
    challenge_dir = tmp_path / "main-site" / ".well-known" / "acme-challenge"
    challenge_dir.mkdir(parents=True)
    challenge = challenge_dir / token
    challenge.write_bytes(b"challenge-content")
    challenge.chmod(0o640)
    application = create_app(config, expected_owner_uid=os.getuid())
    client = TestClient(TestServer(application))
    await client.start_server()
    try:
        response = await client.get(
            f"/.well-known/acme-challenge/{token}", headers={"Host": "example.com"}
        )
        assert response.status == 200
        assert await response.read() == b"challenge-content"
        assert response.headers["Cache-Control"] == "no-store, no-cache, must-revalidate"
        unknown = await client.get(
            f"/.well-known/acme-challenge/{token}", headers={"Host": "unknown.example"}
        )
        assert unknown.status == 404
        rejected = await client.get("/anything", headers={"Host": "example.com"})
        assert rejected.status == 404
    finally:
        await client.close()


async def test_responder_rejects_symlink(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    config = config.model_copy(
        update={"http01": config.http01.model_copy(update={"webroot_base": str(tmp_path)})}
    )
    token = "B" * 20
    challenge_dir = tmp_path / "main-site" / ".well-known" / "acme-challenge"
    challenge_dir.mkdir(parents=True)
    target = tmp_path / "target"
    target.write_bytes(b"content")
    (challenge_dir / token).symlink_to(target)
    application = create_app(config, expected_owner_uid=os.getuid())
    client = TestClient(TestServer(application))
    await client.start_server()
    try:
        response = await client.get(
            f"/.well-known/acme-challenge/{token}", headers={"Host": "example.com"}
        )
        assert response.status == 404
    finally:
        await client.close()


async def test_responder_exposes_health_and_fails_readiness_without_webroot(tmp_path: Path) -> None:
    config = load_config("config/config.example.yaml")
    config = config.model_copy(
        update={"http01": config.http01.model_copy(update={"webroot_base": str(tmp_path)})}
    )
    application = create_app(config, expected_owner_uid=os.getuid())
    client = TestClient(TestServer(application))
    await client.start_server()
    try:
        health = await client.get("/healthz")
        readiness = await client.get("/readyz")
        assert health.status == 200
        assert await health.text() == "ok\n"
        assert readiness.status == 503
    finally:
        await client.close()


async def test_challenge_and_error_middleware_fail_closed() -> None:
    token = "C" * 20

    class Reader:
        def read(self, *_: str) -> bytes:
            raise ChallengeFileError("missing")

    state = ResponderState(
        host_webroots={"example.com": "main-site"},
        reader=Reader(),  # type: ignore[arg-type]
        health_path="/healthz",
        readiness_path="/readyz",
        required_webroots=(),
        request_semaphore=asyncio.Semaphore(1),
    )

    class Request:
        def __init__(self) -> None:
            self.app = {STATE_KEY: state}
            self.match_info = {"token": token}
            self.raw_headers = ((b"Host", b"example.com"),)

    with pytest.raises(web.HTTPNotFound):
        await _challenge(Request())  # type: ignore[arg-type]

    async def broken(_: object) -> object:
        raise OSError("disk failure")

    response = await _error_middleware(Request(), broken)  # type: ignore[arg-type]
    assert response.status == 500

    async def timeout(_: object) -> object:
        raise TimeoutError

    response = await _error_middleware(Request(), timeout)  # type: ignore[arg-type]
    assert response.status == 408


def test_challenge_reader_rejects_unsafe_file_metadata(tmp_path: Path) -> None:
    challenge_directory = tmp_path / "main-site" / ".well-known" / "acme-challenge"
    challenge_directory.mkdir(parents=True)
    token = "D" * 20
    challenge = challenge_directory / token
    challenge.write_bytes(b"content")
    reader = ChallengeFileReader(tmp_path, max_file_bytes=16, expected_owner_uid=os.getuid() + 1)
    with pytest.raises(ChallengeFileError, match="ownership"):
        reader.read("main-site", token)

    challenge.chmod(0o660)
    reader = ChallengeFileReader(tmp_path, max_file_bytes=16, expected_owner_uid=os.getuid())
    with pytest.raises(ChallengeFileError, match="permissions"):
        reader.read("main-site", token)

    challenge.chmod(0o640)
    reader = ChallengeFileReader(tmp_path, max_file_bytes=3, expected_owner_uid=os.getuid())
    with pytest.raises(ChallengeFileError, match="maximum size"):
        reader.read("main-site", token)


def test_challenge_reader_rejects_missing_directory_and_non_regular_file(tmp_path: Path) -> None:
    reader = ChallengeFileReader(tmp_path, max_file_bytes=16, expected_owner_uid=os.getuid())
    with pytest.raises(ChallengeFileError, match="directory"):
        reader.read("main-site", "D" * 20)

    challenge_directory = tmp_path / "main-site" / ".well-known" / "acme-challenge"
    challenge_directory.mkdir(parents=True)
    token = "E" * 20
    (challenge_directory / token).mkdir()
    with pytest.raises(ChallengeFileError, match="not regular"):
        reader.read("main-site", token)
