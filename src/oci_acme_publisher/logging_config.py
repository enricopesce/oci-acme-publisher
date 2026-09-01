"""Structured stdout logging with central redaction."""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Final, TextIO

from .redaction import redact_value

_RESERVED_FIELDS: Final = frozenset(
    {
        "timestamp",
        "level",
        "event",
        "message",
        "exc_info",
        "stack_info",
    }
)


class JsonFormatter(logging.Formatter):
    """Render logger records as one redacted JSON object per stdout line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "event": getattr(record, "event", record.name),
        }
        fields = getattr(record, "event_fields", {})
        if isinstance(fields, Mapping):
            for key, value in fields.items():
                if isinstance(key, str) and key not in _RESERVED_FIELDS:
                    payload[key] = redact_value(value)
        if record.exc_info:
            exception_type = record.exc_info[0]
            if exception_type is not None:
                payload["error_class"] = exception_type.__name__
        return json.dumps(payload, sort_keys=True, default=str)


def configure_json_logging(level: str, *, stream: TextIO = sys.stdout) -> None:
    """Configure exactly one JSON handler for journald collection."""
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


def log_event(logger: logging.Logger, level: int, event: str, **fields: object) -> None:
    """Emit a named structured event without treating interpolated input as a format string."""
    logger.log(level, event, extra={"event": event, "event_fields": fields})
