"""Bounded, redacted operational diagnostics for operators and support cases."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .config import AppConfig
from .errors import ConfigurationError
from .operator import diagnose_configuration
from .status_service import status

_SERVICE_NAMES = ("oci-acme-http01.service", "oci-acme-renew.service", "oci-acme-renew.timer")
_SERVICE_PROPERTIES = ("Id", "ActiveState", "SubState", "UnitFileState", "Result")


def service_status(
    runner: object = subprocess.run,
) -> tuple[dict[str, str], ...]:
    """Return selected systemd state only; never collect journal entries."""
    results: list[dict[str, str]] = []
    for unit in _SERVICE_NAMES:
        command = ["systemctl", "show", unit, "--no-page"]
        command.extend(f"--property={property_name}" for property_name in _SERVICE_PROPERTIES)
        try:
            completed = runner(  # type: ignore[operator]
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            results.append({"unit": unit, "state": "UNAVAILABLE"})
            continue
        if completed.returncode != 0:
            results.append({"unit": unit, "state": "UNAVAILABLE"})
            continue
        fields = {
            key: value
            for key, _, value in (line.partition("=") for line in completed.stdout.splitlines())
            if key
        }
        results.append(
            {
                "unit": unit,
                "active_state": fields.get("ActiveState", "unknown"),
                "sub_state": fields.get("SubState", "unknown"),
                "unit_file_state": fields.get("UnitFileState", "unknown"),
                "result": fields.get("Result", "unknown"),
            }
        )
    return tuple(results)


def support_bundle(config_path: str, config: AppConfig) -> dict[str, object]:
    """Build an intentionally non-sensitive support document in memory."""
    return {
        "schema_version": 1,
        "result": "SUPPORT_BUNDLE_CREATED",
        "created_at": datetime.now(UTC).isoformat(),
        "application_version": __version__,
        "diagnostics": diagnose_configuration(config_path),
        "certificate_status": status(config),
        "services": service_status(),
        "exclusions": [
            "configuration values",
            "systemd credentials",
            "journal entries",
            "private keys",
            "PEM certificate contents",
            "ACME account key material",
        ],
    }


def write_support_bundle(path: str, bundle: dict[str, object]) -> None:
    """Write a new support bundle atomically without replacing an existing record."""
    output = Path(path)
    if not output.is_absolute():
        raise ConfigurationError("support bundle output path must be an absolute path")
    if output.exists() or output.is_symlink():
        raise ConfigurationError("support bundle already exists; refusing to overwrite it")
    if not output.parent.is_dir():
        raise ConfigurationError("support bundle directory does not exist")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    with os.fdopen(descriptor, "w", encoding="utf-8") as bundle_file:
        json.dump(bundle, bundle_file, indent=2, sort_keys=True)
        bundle_file.write("\n")
