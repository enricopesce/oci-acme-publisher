"""Retained proof that a staging OCI compatibility gate qualified a certificate profile."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from .config import AppConfig, CertificateConfig
from .errors import ConfigurationError

_MAX_EVIDENCE_BYTES = 1_048_576
_RESULT = "STAGING_COMPATIBILITY_PASSED"


class LiveProbeEvidence(Protocol):
    """The non-secret result fields retained from the live compatibility probe."""

    @property
    def oci_certificate_ocid(self) -> str: ...

    @property
    def initial_version_number(self) -> int: ...

    @property
    def promoted_version_number(self) -> int: ...

    @property
    def rollback_version_number(self) -> int: ...

    @property
    def leaf_fingerprint(self) -> str: ...

    @property
    def root_fingerprint(self) -> str: ...

    @property
    def chain_bytes(self) -> int: ...

    @property
    def documented_subject_country_enforced(self) -> bool: ...


def certificate_profile(certificate: CertificateConfig) -> dict[str, object]:
    """Return CA-independent properties exercised by the live compatibility gate.

    A staging CA necessarily uses different issuers and trust anchors from its
    production service.  Those values therefore cannot be part of a reusable
    staging qualification.  Production issuer and root policy remains enforced
    independently when every issued chain is validated before OCI publication.
    """
    return {
        "identifier_count": len(certificate.domains),
        "common_name_is_first_identifier": certificate.domains[0] == certificate.common_name,
        "contains_wildcard": any(domain.startswith("*.") for domain in certificate.domains),
        "key": certificate.key.model_dump(mode="json"),
    }


def write_evidence(
    path: str,
    certificate: CertificateConfig,
    result: LiveProbeEvidence,
) -> None:
    """Persist one immutable, non-secret staging evidence record without overwrite."""
    output = Path(path)
    if not output.is_absolute():
        raise ConfigurationError("staging evidence path must be an absolute path")
    if output.exists() or output.is_symlink():
        raise ConfigurationError("staging evidence already exists; refusing to overwrite it")
    if not output.parent.is_dir():
        raise ConfigurationError("staging evidence directory does not exist")
    payload = {
        "schema_version": 2,
        "result": _RESULT,
        "recorded_at": datetime.now(UTC).isoformat(),
        "certificate_id": certificate.id,
        "qualified_profile": certificate_profile(certificate),
        "live_probe": {
            "oci_certificate_ocid": result.oci_certificate_ocid,
            "initial_version_number": result.initial_version_number,
            "promoted_version_number": result.promoted_version_number,
            "rollback_version_number": result.rollback_version_number,
            "leaf_fingerprint": result.leaf_fingerprint,
            "root_fingerprint": result.root_fingerprint,
            "chain_bytes": result.chain_bytes,
            "documented_subject_country_enforced": result.documented_subject_country_enforced,
        },
    }
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    with os.fdopen(descriptor, "w", encoding="utf-8") as evidence_file:
        json.dump(payload, evidence_file, indent=2, sort_keys=True)
        evidence_file.write("\n")


def require_qualified_profile(config: AppConfig, certificate: CertificateConfig) -> None:
    """Require a protected Gate 0 record matching the exact production certificate profile."""
    if not config.compatibility.live_verified:
        raise ConfigurationError("production operation requires compatibility.live_verified")
    expected = certificate_profile(certificate)
    for evidence_path in config.compatibility.live_evidence_paths:
        payload = _read_evidence(evidence_path)
        if (
            payload.get("schema_version") == 2
            and payload.get("result") == _RESULT
            and payload.get("qualified_profile") == expected
        ):
            return
    raise ConfigurationError("no retained staging evidence qualifies this certificate profile")


def _read_evidence(path: str) -> dict[str, Any]:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ConfigurationError("staging evidence is not a regular file")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ConfigurationError("staging evidence must not be group or world writable")
        if metadata.st_size > _MAX_EVIDENCE_BYTES:
            raise ConfigurationError("staging evidence exceeds maximum size")
        raw = candidate.read_bytes()
    except OSError as error:
        raise ConfigurationError("unable to read staging evidence") from error
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ConfigurationError("staging evidence is invalid JSON") from error
    if not isinstance(value, dict):
        raise ConfigurationError("staging evidence root must be an object")
    return value
