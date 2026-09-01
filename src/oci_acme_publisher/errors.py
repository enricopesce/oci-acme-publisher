"""Typed application errors with safe public messages."""

from __future__ import annotations

from dataclasses import dataclass

from .exit_codes import ExitCode


@dataclass(slots=True)
class PublisherError(Exception):
    """Base error which deliberately separates safe and diagnostic text."""

    code: ExitCode
    public_message: str

    def __str__(self) -> str:
        return self.public_message


class ConfigurationError(PublisherError):
    """Raised when configuration is invalid or unsafe."""

    def __init__(self, public_message: str) -> None:
        super().__init__(ExitCode.CONFIGURATION_INVALID, public_message)
