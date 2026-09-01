"""Immutable domain models shared by configuration and runtime services."""

from __future__ import annotations

from enum import StrEnum


class Environment(StrEnum):
    """ACME deployment environment."""

    PRODUCTION = "production"
    STAGING = "staging"


class KeyType(StrEnum):
    """Initially supported private key families."""

    RSA = "rsa"
    ECDSA = "ecdsa"


class AuditMode(StrEnum):
    """Endpoint audit behavior."""

    DISABLED = "disabled"
    OBSERVE = "observe"
    ENFORCE = "enforce"
