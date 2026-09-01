"""Build OCI import chains using only locally pinned roots."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from .certificate_store import LineageMaterial
from .certificate_validator import CertificateValidationError, verify_certificate_signature
from .config import CertificateConfig, CompatibilityConfig
from .fingerprint import certificate_sha256


class ChainBuildError(CertificateValidationError):
    """The local chain cannot satisfy the pinned OCI import profile."""


@dataclass(frozen=True, slots=True)
class OciCertificateChain:
    """The OCI chain excludes the leaf and ends at its verified pinned root."""

    root: x509.Certificate
    intermediates: tuple[x509.Certificate, ...]
    cert_chain_pem: bytes


def _subject_common_name(certificate: x509.Certificate) -> str:
    attributes = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(attributes) != 1 or not isinstance(attributes[0].value, str):
        raise ChainBuildError("certificate subject has no single textual Common Name")
    return attributes[0].value


def _load_pinned_root(configuration: CertificateConfig) -> x509.Certificate:
    root_path = Path(configuration.chain.root_pem_path)
    try:
        content = root_path.read_bytes()
        root = x509.load_pem_x509_certificate(content)
    except (OSError, ValueError) as error:
        raise ChainBuildError("configured root certificate cannot be loaded") from error
    if certificate_sha256(root) not in configuration.chain.allowed_root_sha256:
        raise ChainBuildError("configured root fingerprint is not allowlisted")
    return root


def _algorithm_family(certificate: x509.Certificate) -> str:
    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return "rsa"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ecdsa"
    raise ChainBuildError("chain contains an unsupported key algorithm")


def _validate_ca(certificate: x509.Certificate) -> None:
    try:
        basic_constraints = certificate.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound as error:
        raise ChainBuildError("issuer certificate lacks BasicConstraints") from error
    if not isinstance(basic_constraints, x509.BasicConstraints) or not basic_constraints.ca:
        raise ChainBuildError("issuer certificate is not a CA")


def build_oci_chain(
    material: LineageMaterial,
    certificate: CertificateConfig,
    compatibility: CompatibilityConfig,
) -> OciCertificateChain:
    """Verify order, signatures and root pin, then serialize the OCI bundle chain."""
    root = _load_pinned_root(certificate)
    root_fingerprint = certificate_sha256(root)
    intermediates = tuple(
        item for item in material.intermediates if certificate_sha256(item) != root_fingerprint
    )
    if not intermediates:
        raise ChainBuildError("ACME certificate chain is empty")
    if any(item.subject == root.subject for item in intermediates):
        raise ChainBuildError("ACME certificate chain must not contain the configured root")
    current = material.leaf
    for issuer in intermediates:
        if current.issuer != issuer.subject:
            raise ChainBuildError("ACME certificate chain issuer order is invalid")
        _validate_ca(issuer)
        verify_certificate_signature(current, issuer)
        current = issuer
    if current.issuer != root.subject:
        raise ChainBuildError("configured root does not issue the final intermediate")
    _validate_ca(root)
    verify_certificate_signature(current, root)
    if _subject_common_name(intermediates[0]) not in certificate.chain.allowed_issuer_common_names:
        raise ChainBuildError("intermediate issuer Common Name is not allowlisted")
    if compatibility.reject_mixed_algorithm_chain:
        families = {_algorithm_family(item) for item in (material.leaf, *intermediates, root)}
        if len(families) != 1:
            raise ChainBuildError("chain mixes RSA and ECDSA key families")
    chain_pem = b"".join(
        item.public_bytes(serialization.Encoding.PEM) for item in (*intermediates, root)
    )
    if len(chain_pem) + len(material.leaf_pem) > 51_200:
        raise ChainBuildError("OCI certificate bundle exceeds size limit")
    return OciCertificateChain(root=root, intermediates=intermediates, cert_chain_pem=chain_pem)
