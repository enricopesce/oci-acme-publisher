"""Certificate fingerprint helpers."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes


def certificate_sha256(certificate: x509.Certificate) -> str:
    """Return the lower-case SHA-256 fingerprint of an X.509 certificate."""
    return certificate.fingerprint(hashes.SHA256()).hex()
