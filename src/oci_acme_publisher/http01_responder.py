"""Minimal persistent HTTP-01 responder with no OCI or ACME capabilities."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from aiohttp import web

from .config import AppConfig, load_config, normalize_domain
from .http01_paths import ChallengeFileError, ChallengeFileReader, publisher_uid

TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,256}$")
CHALLENGE_PREFIX = "/.well-known/acme-challenge/"
_SECURITY_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}


class HostHeaderError(ValueError):
    """The request Host header cannot be matched safely."""


def normalize_host_header(value: str) -> str:
    """Normalize an allowlisted DNS Host header and remove an optional port."""
    if not value or any(char.isspace() for char in value) or "%" in value:
        raise HostHeaderError("invalid Host header")
    if any(character in value for character in ("/", "\\", "@", "[", "]")):
        raise HostHeaderError("invalid Host header")
    host = value
    if ":" in value:
        host, separator, port = value.rpartition(":")
        if not separator or not host or not port.isascii() or not port.isdecimal():
            raise HostHeaderError("invalid Host header")
        if not 1 <= int(port) <= 65535:
            raise HostHeaderError("invalid Host header")
    try:
        return normalize_domain(host)
    except ValueError as error:
        raise HostHeaderError("invalid Host header") from error


def config_host_webroots(config: AppConfig) -> Mapping[str, str]:
    """Build the immutable hostname-to-webroot map at responder startup."""
    return {
        domain: certificate.webroot_id
        for certificate in config.certificates
        for domain in certificate.domains
    }


@dataclass(frozen=True, slots=True)
class ResponderState:
    """All responder dependencies, deliberately without publisher credentials."""

    host_webroots: Mapping[str, str]
    reader: ChallengeFileReader
    health_path: str
    readiness_path: str
    required_webroots: tuple[str, ...]
    request_semaphore: asyncio.Semaphore

    def ready(self) -> bool:
        """Confirm all challenge directories can be safely opened."""
        for webroot_id in self.required_webroots:
            try:
                file_descriptor = self.reader._open_challenge_directory(webroot_id)
            except ChallengeFileError:
                return False
            os.close(file_descriptor)
        return True


STATE_KEY: web.AppKey[ResponderState] = web.AppKey("state", ResponderState)


@web.middleware
async def _error_middleware(
    request: web.Request,
    handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
) -> web.StreamResponse:
    try:
        return await handler(request)
    except TimeoutError:
        return web.Response(status=408)
    except web.HTTPException:
        raise
    except (OSError, RuntimeError, ValueError):
        return web.Response(status=500)


async def _health(_: web.Request) -> web.Response:
    return web.Response(text="ok\n", content_type="text/plain")


async def _readiness(request: web.Request) -> web.Response:
    state = request.app[STATE_KEY]
    is_ready = state.ready()
    return web.Response(
        status=200 if is_ready else 503, text="ready\n" if is_ready else "not ready\n"
    )


def _single_host(request: web.Request) -> str:
    hosts = [value for key, value in request.raw_headers if key.lower() == b"host"]
    if len(hosts) != 1:
        raise HostHeaderError("Host must appear exactly once")
    return normalize_host_header(hosts[0].decode("ascii"))


async def _challenge(request: web.Request) -> web.StreamResponse:
    state = request.app[STATE_KEY]
    token = request.match_info["token"]
    if TOKEN_PATTERN.fullmatch(token) is None:
        raise web.HTTPNotFound()
    try:
        host = _single_host(request)
        webroot_id = state.host_webroots[host]
    except (HostHeaderError, KeyError, UnicodeDecodeError):
        raise web.HTTPNotFound() from None
    async with state.request_semaphore:
        try:
            content = await asyncio.wait_for(
                asyncio.to_thread(state.reader.read, webroot_id, token),
                timeout=5,
            )
        except (ChallengeFileError, TimeoutError):
            raise web.HTTPNotFound() from None
    return web.Response(content_type="text/plain", body=content, headers=_SECURITY_HEADERS)


def create_app(config: AppConfig, *, expected_owner_uid: int | None = None) -> web.Application:
    """Create the constrained aiohttp application; no network calls occur here."""
    responder = config.http01.responder
    owner_uid = publisher_uid() if expected_owner_uid is None else expected_owner_uid
    state = ResponderState(
        host_webroots=config_host_webroots(config),
        reader=ChallengeFileReader(
            webroot_base=Path(config.http01.webroot_base),
            max_file_bytes=responder.max_challenge_file_bytes,
            expected_owner_uid=owner_uid,
        ),
        health_path=responder.health_path,
        readiness_path=responder.readiness_path,
        required_webroots=tuple(certificate.webroot_id for certificate in config.certificates),
        request_semaphore=asyncio.Semaphore(responder.max_concurrent_requests),
    )
    application = web.Application(
        middlewares=[_error_middleware],
        client_max_size=responder.max_request_body_bytes,
        handler_args={"keepalive_timeout": responder.keepalive_timeout_seconds},
    )
    application[STATE_KEY] = state
    application.router.add_get(responder.health_path, _health, allow_head=False)
    application.router.add_get(responder.readiness_path, _readiness, allow_head=False)
    application.router.add_get(f"{CHALLENGE_PREFIX}{{token}}", _challenge)
    return application


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="oci-acme-http01")
    subcommands = parser.add_subparsers(dest="command", required=True)
    serve = subcommands.add_parser("serve")
    serve.add_argument("--config", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the persistent responder from a validated configuration file."""
    args = _parser().parse_args(argv)
    config = load_config(args.config)
    app = create_app(config)
    responder = config.http01.responder
    web.run_app(
        app,
        host=responder.bind_address,
        port=responder.bind_port,
        backlog=responder.backlog,
        print=None,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
