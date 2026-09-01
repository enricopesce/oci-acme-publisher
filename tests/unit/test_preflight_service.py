from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes, serialization

from oci_acme_publisher import preflight_service
from oci_acme_publisher.config import AppConfig, load_config
from oci_acme_publisher.http01_preflight import PreflightError
from oci_acme_publisher.preflight_service import OperationalPreflight

from .test_certificate_validator import material_with_root


def _config_with_pinned_root(tmp_path: Path) -> AppConfig:
    base = load_config("config/config.example.yaml")
    _, root = material_with_root()
    root_path = tmp_path / "root.pem"
    root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
    chain = base.certificates[0].chain.model_copy(
        update={
            "root_pem_path": str(root_path),
            "allowed_root_sha256": (root.fingerprint(hashes.SHA256()).hex(),),
        }
    )
    certificate = base.certificates[0].model_copy(update={"chain": chain})
    (tmp_path / certificate.webroot_id).mkdir()
    http01 = base.http01.model_copy(update={"webroot_base": str(tmp_path)})
    return base.model_copy(update={"certificates": (certificate,), "http01": http01})


def test_operational_preflight_checks_root_oci_read_and_http01(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _config_with_pinned_root(tmp_path)
    read_ids: list[str] = []
    http_ids: list[str] = []

    class Http:
        def __init__(self, _: object) -> None:
            pass

        async def run(self, certificate: object, **_: object) -> None:
            http_ids.append(certificate.id)  # type: ignore[attr-defined]

    management = SimpleNamespace(
        get_certificate=lambda certificate_id, **_: read_ids.append(certificate_id)
    )
    monkeypatch.setattr(preflight_service, "Http01Preflight", Http)
    service = OperationalPreflight(
        adapters_factory=lambda *_: SimpleNamespace(management=management, retrieval=object()),
        clock_checker=lambda _: None,
        responder_checker=lambda _: None,
    )

    service.run(config, config.certificates)

    assert read_ids == [config.certificates[0].oci.certificate_ocid]
    assert http_ids == ["main-site"]


def test_operational_preflight_rejects_unallowlisted_root(tmp_path: Path) -> None:
    config = _config_with_pinned_root(tmp_path)
    chain = config.certificates[0].chain.model_copy(update={"allowed_root_sha256": ("0" * 64,)})
    certificate = config.certificates[0].model_copy(update={"chain": chain})
    config = config.model_copy(update={"certificates": (certificate,)})

    with pytest.raises(PreflightError, match="not allowlisted"):
        OperationalPreflight(clock_checker=lambda _: None, responder_checker=lambda _: None).run(
            config, config.certificates
        )


def test_operational_preflight_rejects_missing_webroot(tmp_path: Path) -> None:
    config = _config_with_pinned_root(tmp_path)
    (tmp_path / config.certificates[0].webroot_id).rmdir()

    with pytest.raises(PreflightError, match="webroot"):
        OperationalPreflight(clock_checker=lambda _: None, responder_checker=lambda _: None).run(
            config, config.certificates
        )


def test_clock_preflight_requires_ntp_synchronization(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        preflight_service.subprocess,
        "run",
        lambda *_, **__: SimpleNamespace(returncode=0, stdout="yes\n"),
    )

    OperationalPreflight._verify_clock(300)


def test_clock_preflight_rejects_unsynchronized_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        preflight_service.subprocess,
        "run",
        lambda *_, **__: SimpleNamespace(returncode=0, stdout="no\n"),
    )

    with pytest.raises(PreflightError, match="not synchronized"):
        OperationalPreflight._verify_clock(300)


def test_clock_preflight_rejects_unavailable_time_service(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        preflight_service.subprocess,
        "run",
        lambda *_, **__: (_ for _ in ()).throw(OSError("not found")),
    )

    with pytest.raises(PreflightError, match="cannot be verified"):
        OperationalPreflight._verify_clock(300)


def test_responder_preflight_checks_local_readiness(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _config_with_pinned_root(tmp_path)

    class Reader:
        async def read(self, _: int) -> bytes:
            return b"HTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n"

    class Writer:
        request: bytes = b""

        def write(self, _: bytes) -> None:
            self.request = _

        async def drain(self) -> None:
            pass

        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    writer = Writer()

    async def connect(_: str, __: int) -> tuple[Reader, Writer]:
        return Reader(), writer

    monkeypatch.setattr(preflight_service.asyncio, "open_connection", connect)

    OperationalPreflight._verify_responder(config.http01)

    assert writer.request == b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"


def test_responder_preflight_rejects_non_ready_response(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _config_with_pinned_root(tmp_path)

    class Reader:
        async def read(self, _: int) -> bytes:
            return b"HTTP/1.1 503 Service Unavailable\\r\\n\\r\\n"

    class Writer:
        def write(self, _: bytes) -> None:
            pass

        async def drain(self) -> None:
            pass

        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    async def connect(_: str, __: int) -> tuple[Reader, Writer]:
        return Reader(), Writer()

    monkeypatch.setattr(preflight_service.asyncio, "open_connection", connect)

    with pytest.raises(PreflightError, match="not ready"):
        OperationalPreflight._verify_responder(config.http01)
