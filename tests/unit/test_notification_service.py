from __future__ import annotations

from pathlib import Path

import pytest

from oci_acme_publisher import notification_service
from oci_acme_publisher.config import NotificationsConfig
from oci_acme_publisher.notification_service import (
    NotificationError,
    NotificationService,
    credential_path,
    webhook_url,
)


def test_notification_url_requires_https_and_allowlisted_host() -> None:
    configuration = NotificationsConfig(
        enabled=True,
        provider="webhook",
        credential_ref="systemd-credential:notifier",
        allowed_hosts=("hooks.example.invalid",),
    )
    assert (
        webhook_url(configuration, "https://hooks.example.invalid/path")
        == "https://hooks.example.invalid/path"
    )
    with pytest.raises(NotificationError):
        webhook_url(configuration, "http://hooks.example.invalid/path")
    with pytest.raises(NotificationError):
        webhook_url(configuration, "https://untrusted.example.invalid/path")


@pytest.mark.parametrize(
    "reference",
    ("plain-secret", "systemd-credential:", "systemd-credential:../secret"),
)
def test_credential_path_accepts_only_a_safe_systemd_credential(reference: str) -> None:
    with pytest.raises(NotificationError):
        credential_path(reference)


@pytest.mark.asyncio
async def test_disabled_notifier_performs_no_io() -> None:
    assert await NotificationService(NotificationsConfig()).notify("ignored", {}) is False


@pytest.mark.asyncio
async def test_notifier_skips_delivery_during_a_durable_cooldown() -> None:
    configuration = NotificationsConfig(
        enabled=True,
        provider="webhook",
        credential_ref="systemd-credential:notifier",
        allowed_hosts=("hooks.example.invalid",),
    )

    class Deduplicator:
        def should_send_alert(self, *_: object, **__: object) -> bool:
            return False

        def record_alert_sent(self, *_: object) -> None:
            raise AssertionError("cooldown must not record a delivery")

    assert (
        await NotificationService(configuration).notify(
            "AUDIT_FAILED",
            {"certificate_id": "main-site", "status": "AUDIT_FAILED"},
            deduplicator=Deduplicator(),
        )
        is False
    )


@pytest.mark.asyncio
async def test_notifier_sends_only_to_allowlisted_https_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = tmp_path / "webhook"
    secret.write_text("https://hooks.example.invalid/endpoint\n", encoding="utf-8")
    configuration = NotificationsConfig(
        enabled=True,
        provider="webhook",
        credential_ref="systemd-credential:notifier",
        allowed_hosts=("hooks.example.invalid",),
    )
    requests: list[tuple[str, dict[str, object], bool]] = []
    records: list[tuple[str, str]] = []

    class Deduplicator:
        def should_send_alert(self, *_: object, **__: object) -> bool:
            return True

        def record_alert_sent(self, key: str, status: str) -> None:
            records.append((key, status))

    class Response:
        status = 204

        async def __aenter__(self) -> Response:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

    class Session:
        def __init__(self, **_: object) -> None:
            pass

        async def __aenter__(self) -> Session:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        def post(self, url: str, *, json: dict[str, object], allow_redirects: bool) -> Response:
            requests.append((url, json, allow_redirects))
            return Response()

    monkeypatch.setattr(notification_service, "credential_path", lambda _: secret)
    monkeypatch.setattr(notification_service.aiohttp, "ClientSession", Session)

    assert (
        await NotificationService(configuration).notify(
            "EVENT", {"certificate_id": "main-site"}, deduplicator=Deduplicator()
        )
        is True
    )

    assert requests == [
        (
            "https://hooks.example.invalid/endpoint",
            {"event": "EVENT", "fields": {"certificate_id": "main-site"}},
            False,
        )
    ]
    assert records == [("EVENT:main-site", "EVENT")]


@pytest.mark.asyncio
async def test_notifier_rejects_unreadable_credential_and_non_success_response(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    configuration = NotificationsConfig(
        enabled=True,
        provider="slack",
        credential_ref="systemd-credential:notifier",
        allowed_hosts=("hooks.example.invalid",),
    )
    monkeypatch.setattr(notification_service, "credential_path", lambda _: tmp_path / "missing")
    with pytest.raises(NotificationError, match="cannot be read"):
        await NotificationService(configuration).notify("EVENT", {})

    secret = tmp_path / "webhook"
    secret.write_text("https://hooks.example.invalid/endpoint", encoding="utf-8")

    class Response:
        status = 503

        async def __aenter__(self) -> Response:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

    class Session:
        def __init__(self, **_: object) -> None:
            pass

        async def __aenter__(self) -> Session:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        def post(self, *_: object, **__: object) -> Response:
            return Response()

    monkeypatch.setattr(notification_service, "credential_path", lambda _: secret)
    monkeypatch.setattr(notification_service.aiohttp, "ClientSession", Session)
    with pytest.raises(NotificationError, match="non-success"):
        await NotificationService(configuration).notify("EVENT", {})
