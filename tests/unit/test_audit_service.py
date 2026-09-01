from __future__ import annotations

import pytest

from oci_acme_publisher import audit_service
from oci_acme_publisher.audit_service import (
    AuditError,
    AuditService,
    _validate_addresses,
    fixed_address_resolver,
    pinned_root_probe,
    probe_tls_fingerprint,
)
from oci_acme_publisher.config import load_config
from oci_acme_publisher.models import AuditMode


async def test_observe_audit_reports_mismatch_without_raising() -> None:
    config = load_config("config/config.example.yaml")
    audit = config.certificates[0].audit.model_copy(
        update={"propagation_timeout_seconds": 0, "reject_non_global_addresses": False}
    )

    async def resolver(_: str) -> tuple[str, ...]:
        return ("127.0.0.1",)

    async def probe(_: str, __: str, ___: int, ____: float) -> str:
        return "b" * 64

    result = await AuditService(audit, resolver=resolver, probe=probe).audit("a" * 64)
    assert result.successful is False
    assert result.failed_endpoints == ("example.com:443",)


async def test_enforce_audit_raises_on_mismatch() -> None:
    config = load_config("config/config.example.yaml")
    audit = config.certificates[0].audit.model_copy(
        update={
            "mode": AuditMode.ENFORCE,
            "propagation_timeout_seconds": 0,
            "reject_non_global_addresses": False,
        }
    )

    async def resolver(_: str) -> tuple[str, ...]:
        return ("127.0.0.1",)

    async def probe(_: str, __: str, ___: int, ____: float) -> str:
        return "b" * 64

    try:
        await AuditService(audit, resolver=resolver, probe=probe).audit("a" * 64)
    except AuditError:
        return
    raise AssertionError("enforce audit must raise")


async def test_disabled_audit_does_not_resolve_or_connect() -> None:
    config = load_config("config/config.example.yaml")
    audit = config.certificates[0].audit.model_copy(update={"mode": AuditMode.DISABLED})

    async def resolver(_: str) -> tuple[str, ...]:
        raise AssertionError("disabled audit must not resolve DNS")

    result = await AuditService(audit, resolver=resolver).audit("a" * 64)
    assert result.successful is True
    assert result.attempts == 0


async def test_fixed_address_resolver_ignores_hostname() -> None:
    resolver = fixed_address_resolver(("203.0.113.10", "2001:db8::1"))

    assert await resolver("split-dns.example") == ("203.0.113.10", "2001:db8::1")


def test_fixed_address_resolver_rejects_empty_address_list() -> None:
    with pytest.raises(ValueError, match="at least one"):
        fixed_address_resolver(())


async def test_audit_accepts_any_matching_address_when_configured() -> None:
    config = load_config("config/config.example.yaml")
    audit = config.certificates[0].audit.model_copy(
        update={"require_all_addresses": False, "reject_non_global_addresses": False}
    )

    async def resolver(_: str) -> tuple[str, ...]:
        return ("127.0.0.1", "127.0.0.2")

    async def probe(address: str, _: str, __: int, ___: float) -> str:
        return "a" * 64 if address.endswith(".1") else "b" * 64

    result = await AuditService(audit, resolver=resolver, probe=probe).audit("a" * 64)
    assert result.successful is True
    assert result.attempts == 1


async def test_audit_treats_invalid_resolver_output_as_mismatch() -> None:
    config = load_config("config/config.example.yaml")
    audit = config.certificates[0].audit.model_copy(
        update={"propagation_timeout_seconds": 0, "reject_non_global_addresses": False}
    )

    async def resolver(_: str) -> tuple[str, ...]:
        return ("not-an-address",)

    result = await AuditService(audit, resolver=resolver).audit("a" * 64)
    assert result.failed_endpoints == ("example.com:443",)


@pytest.mark.parametrize("addresses", (("not-an-address",), ("127.0.0.1",)))
def test_address_validation_rejects_invalid_and_non_global_addresses(
    addresses: tuple[str, ...],
) -> None:
    with pytest.raises(AuditError):
        _validate_addresses(addresses, reject_non_global=True)


async def test_tls_probe_fingerprints_peer_certificate_and_closes_writer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[bool] = []

    class TlsObject:
        def getpeercert(self, *, binary_form: bool) -> bytes:
            assert binary_form is True
            return b"der-certificate"

    class Writer:
        def get_extra_info(self, _: str) -> object:
            return TlsObject()

        def close(self) -> None:
            closed.append(True)

        async def wait_closed(self) -> None:
            return None

    async def connect(*_: object, **__: object) -> tuple[object, Writer]:
        return object(), Writer()

    monkeypatch.setattr(audit_service.ssl, "SSLObject", TlsObject)
    monkeypatch.setattr(audit_service.asyncio, "open_connection", connect)
    monkeypatch.setattr(audit_service.x509, "load_der_x509_certificate", lambda _: object())
    monkeypatch.setattr(audit_service, "certificate_sha256", lambda _: "fingerprint")

    assert await probe_tls_fingerprint("203.0.113.10", "example.com", 443, 1) == "fingerprint"
    assert closed == [True]


async def test_pinned_root_probe_uses_the_test_root_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = object()
    calls: list[object] = []

    monkeypatch.setattr(audit_service.ssl, "create_default_context", lambda **kwargs: context)

    async def probe(*args: object) -> str:
        calls.extend(args)
        return "fingerprint"

    monkeypatch.setattr(audit_service, "_probe_tls_fingerprint", probe)
    result = await pinned_root_probe("/pinned/root.pem")("203.0.113.10", "example.com", 443, 1)
    assert result == "fingerprint"
    assert calls[-1] is context


async def test_tls_probe_rejects_missing_ssl_object_and_malformed_certificate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Writer:
        def __init__(self, ssl_object: object) -> None:
            self._ssl_object = ssl_object

        def get_extra_info(self, _: str) -> object:
            return self._ssl_object

        def close(self) -> None:
            return None

        async def wait_closed(self) -> None:
            return None

    async def missing_ssl(*_: object, **__: object) -> tuple[object, Writer]:
        return object(), Writer(None)

    monkeypatch.setattr(audit_service.asyncio, "open_connection", missing_ssl)
    with pytest.raises(AuditError, match="SSL object"):
        await probe_tls_fingerprint("203.0.113.10", "example.com", 443, 1)

    class TlsObject:
        def getpeercert(self, *, binary_form: bool) -> bytes:
            return b"bad-der"

    async def malformed(*_: object, **__: object) -> tuple[object, Writer]:
        return object(), Writer(TlsObject())

    monkeypatch.setattr(audit_service.ssl, "SSLObject", TlsObject)
    monkeypatch.setattr(audit_service.asyncio, "open_connection", malformed)
    monkeypatch.setattr(
        audit_service.x509,
        "load_der_x509_certificate",
        lambda _: (_ for _ in ()).throw(ValueError("invalid")),
    )
    with pytest.raises(AuditError, match="malformed"):
        await probe_tls_fingerprint("203.0.113.10", "example.com", 443, 1)
