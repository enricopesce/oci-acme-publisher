"""Centralized conservative redaction for process and SDK diagnostics."""

from __future__ import annotations

import re
from collections.abc import Mapping

_PEM_BLOCK = re.compile(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.DOTALL)
_AUTHORIZATION = re.compile(r"(?im)^(authorization\s*[:=]\s*)\S+.*$")
_URL_CREDENTIAL = re.compile(r"https://[^\s/@:]+:[^\s/@]+@")
_HTTPS_URL = re.compile(r"https://[^\s]+")
_BEARER_TOKEN = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/-]+=*")


def redact(value: str) -> str:
    """Remove the high-risk material that must never reach journal output."""
    without_pem = _PEM_BLOCK.sub("[REDACTED_PEM]", value)
    without_auth = _AUTHORIZATION.sub(r"\1[REDACTED]", without_pem)
    without_credentials = _URL_CREDENTIAL.sub("https://[REDACTED]@", without_auth)
    without_bearer = _BEARER_TOKEN.sub("Bearer [REDACTED]", without_credentials)
    return _HTTPS_URL.sub("[REDACTED_HTTPS_URL]", without_bearer)


def redact_value(value: object) -> object:
    """Recursively redact JSON-compatible event fields without stringifying objects."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, bool | int | float) or value is None:
        return value
    if isinstance(value, Mapping):
        return {redact(str(key)): redact_value(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [redact_value(item) for item in value]
    return "[REDACTED_UNSUPPORTED_VALUE]"
