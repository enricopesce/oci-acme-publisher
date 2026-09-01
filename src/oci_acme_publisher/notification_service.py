"""Bounded HTTPS notification delivery using systemd credentials only."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

import aiohttp

from .config import NotificationsConfig


class NotificationError(RuntimeError):
    """Notification transport or credential validation failed."""


class AlertDeduplicator(Protocol):
    """Minimal durable cooldown boundary; it never accepts notification secrets."""

    def should_send_alert(
        self, dedup_key: str, status: str, *, minimum_repeat_interval_minutes: int
    ) -> bool: ...

    def record_alert_sent(self, dedup_key: str, status: str) -> None: ...


def credential_path(reference: str) -> Path:
    """Resolve only a named systemd credential in the standard credential directory."""
    prefix = "systemd-credential:"
    if not reference.startswith(prefix):
        raise NotificationError("notification credential reference is invalid")
    name = reference.removeprefix(prefix)
    if not name or "/" in name or ".." in name:
        raise NotificationError("notification credential name is invalid")
    return Path("/run/credentials/oci-acme-renew.service") / name


def webhook_url(configuration: NotificationsConfig, secret: str) -> str:
    """Validate a credential-provided webhook URL against HTTPS and an explicit allowlist."""
    parsed = urlparse(secret)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise NotificationError("notification webhook must be a credential-provided HTTPS URL")
    if parsed.hostname not in configuration.allowed_hosts:
        raise NotificationError("notification webhook host is not allowlisted")
    return secret


class NotificationService:
    """Send a small redacted event without making notification failure a renewal failure."""

    def __init__(self, configuration: NotificationsConfig) -> None:
        self._configuration = configuration

    async def notify(
        self,
        event: str,
        fields: dict[str, str],
        *,
        deduplicator: AlertDeduplicator | None = None,
    ) -> bool:
        """Deliver one redacted event with bounded retry and optional durable cooldown."""
        if not self._configuration.enabled:
            return False
        certificate_id = fields.get("certificate_id", "")
        status = fields.get("status", event)
        dedup_key = f"{event}:{certificate_id}"
        if deduplicator is not None and not deduplicator.should_send_alert(
            dedup_key,
            status,
            minimum_repeat_interval_minutes=self._configuration.minimum_repeat_interval_minutes,
        ):
            return False
        reference = self._configuration.credential_ref
        if reference is None:
            raise NotificationError("enabled notifier has no credential reference")
        try:
            secret = credential_path(reference).read_text(encoding="utf-8").strip()
        except OSError as error:
            raise NotificationError("notification credential cannot be read") from error
        url = webhook_url(self._configuration, secret)
        payload: dict[str, object]
        if self._configuration.provider == "slack":
            payload = {"text": event, "attachments": [{"fields": fields}]}
        else:
            payload = {"event": event, "fields": fields}
        timeout = aiohttp.ClientTimeout(
            connect=self._configuration.connect_timeout_seconds,
            total=self._configuration.total_timeout_seconds,
        )
        for attempt in range(2):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(url, json=payload, allow_redirects=False) as response:
                        if 200 <= response.status < 300:
                            if deduplicator is not None:
                                deduplicator.record_alert_sent(dedup_key, status)
                            return True
                        if response.status < 500 and response.status != 429:
                            raise NotificationError(
                                "notification endpoint returned non-success status"
                            )
            except aiohttp.ClientError as error:
                if attempt == 1:
                    raise NotificationError("notification delivery failed") from error
            if attempt == 0:
                await asyncio.sleep(0.25)
        raise NotificationError("notification endpoint returned non-success status")
