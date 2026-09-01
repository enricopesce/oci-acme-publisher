"""UTC clock helpers for durable state."""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now_rfc3339() -> str:
    """Return an RFC 3339 timestamp with UTC offset and second precision."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
