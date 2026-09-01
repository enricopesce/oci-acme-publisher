"""Local, fail-closed validation of ACME certificate material."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from .certificate_store import LineageMaterial
from .config import CertificateConfig, CompatibilityConfig, GlobalConfig, normalize_domain
from .fingerprint import certificate_sha256
from .models import Environment, KeyType

_ISO_COUNTRIES = frozenset(
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BM BN BO BQ "
    "BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK "
    "DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR "
    "GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM "
    "KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MG MH MK ML MM MN MO MP MQ "
    "MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM "
    "PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV "
    "SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI "
    "VN VU WF WS XK YE YT ZA ZM ZW".split()
)


class CertificateValidationError(ValueError):
    """Certificate material does not meet the local or OCI profile policy."""


def verify_certificate_signature(child: x509.Certificate, issuer: x509.Certificate) -> None:
    public_key = issuer.public_key()
    signature_hash = child.signature_hash_algorithm
    if signature_hash is None:
        raise CertificateValidationError("certificate signature algorithm has no hash")
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                signature_hash,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(signature_hash),
            )
        else:
            raise CertificateValidationError("unsupported issuer public key algorithm")
    except CertificateValidationError:
        raise
    except (InvalidSignature, TypeError, ValueError) as error:
        raise CertificateValidationError("certificate signature verification failed") from error


def _dns_sans(certificate: x509.Certificate) -> tuple[str, ...]:
    try:
        extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound as error:
        raise CertificateValidationError("certificate does not contain SAN") from error
    san = cast(x509.SubjectAlternativeName, extension.value)
    names = san.get_values_for_type(x509.DNSName)
    try:
        return tuple(normalize_domain(name) for name in names)
    except ValueError as error:
        raise CertificateValidationError("certificate SAN is invalid") from error


def _common_name(certificate: x509.Certificate) -> str:
    attributes = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(attributes) != 1:
        raise CertificateValidationError("certificate must have exactly one Common Name")
    try:
        value = attributes[0].value
        if not isinstance(value, str):
            raise CertificateValidationError("certificate Common Name is not text")
        return normalize_domain(value)
    except ValueError as error:
        raise CertificateValidationError("certificate Common Name is invalid") from error


def _validate_key(certificate: x509.Certificate, expected: CertificateConfig) -> None:
    public_key = certificate.public_key()
    if expected.key.type is KeyType.RSA:
        if (
            not isinstance(public_key, rsa.RSAPublicKey)
            or public_key.key_size != expected.key.rsa_size
        ):
            raise CertificateValidationError("certificate RSA key does not match configuration")
        return
    curve = expected.key.ecdsa_curve
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or public_key.curve.name != curve:
        raise CertificateValidationError("certificate ECDSA key does not match configuration")


def _validate_extensions(certificate: x509.Certificate) -> None:
    try:
        if certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise CertificateValidationError("leaf certificate must not be a CA")
    except x509.ExtensionNotFound as error:
        raise CertificateValidationError("leaf certificate lacks BasicConstraints") from error
    try:
        eku = cast(
            x509.ExtendedKeyUsage,
            certificate.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value,
        )
    except x509.ExtensionNotFound:
        eku = None
    if eku is not None and ExtendedKeyUsageOID.SERVER_AUTH not in eku:
        raise CertificateValidationError("leaf certificate EKU excludes server authentication")
    try:
        key_usage = cast(
            x509.KeyUsage,
            certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value,
        )
    except x509.ExtensionNotFound:
        key_usage = None
    if key_usage is not None and not key_usage.digital_signature:
        raise CertificateValidationError("leaf certificate key usage excludes digital signature")


def _validate_country(certificate: x509.Certificate, compatibility: CompatibilityConfig) -> None:
    if not compatibility.enforce_documented_subject_country:
        return
    countries = certificate.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    if len(countries) != 1 or countries[0].value not in _ISO_COUNTRIES:
        raise CertificateValidationError("certificate country code is missing or not ISO 3166-1")


def _validate_validity(
    certificate: x509.Certificate, global_config: GlobalConfig, now: datetime
) -> None:
    current = now.astimezone(UTC)
    skew = global_config.clock_skew_tolerance_seconds
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    if current.timestamp() + skew < not_before.timestamp():
        raise CertificateValidationError("certificate is not yet valid")
    if current.timestamp() - skew > not_after.timestamp():
        raise CertificateValidationError("certificate is expired")


def validate_certificate_material(
    material: LineageMaterial,
    certificate: CertificateConfig,
    compatibility: CompatibilityConfig,
    global_config: GlobalConfig,
    *,
    now: datetime,
) -> str:
    """Validate local material and return its SHA-256 leaf fingerprint."""
    leaf = material.leaf
    if _common_name(leaf) != certificate.common_name:
        raise CertificateValidationError("certificate Common Name does not match configuration")
    if _dns_sans(leaf) != certificate.domains:
        raise CertificateValidationError("certificate SAN does not exactly match configuration")
    public_encoding = serialization.Encoding.DER
    public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    if leaf.public_key().public_bytes(
        public_encoding, public_format
    ) != material.private_key.public_key().public_bytes(public_encoding, public_format):
        raise CertificateValidationError("private key does not match certificate")
    _validate_validity(leaf, global_config, now)
    _validate_extensions(leaf)
    _validate_key(leaf, certificate)
    _validate_country(leaf, compatibility)
    if (
        global_config.environment is Environment.PRODUCTION
        and "Fake LE" in leaf.issuer.rfc4514_string()
    ):
        raise CertificateValidationError("staging certificate cannot be published in production")
    if len(material.leaf_pem) > 10_240 or len(material.private_key_pem) > 5_120:
        raise CertificateValidationError("certificate or private key exceeds OCI size limit")
    if len(material.leaf_pem) + len(material.chain_pem) > 51_200:
        raise CertificateValidationError("certificate bundle exceeds OCI size limit")
    if not material.intermediates:
        raise CertificateValidationError("certificate chain is empty")
    verify_certificate_signature(leaf, material.intermediates[0])
    return certificate_sha256(leaf)


def validate_public_certificate(
    certificate_pem: str,
    certificate: CertificateConfig,
    global_config: GlobalConfig,
    *,
    now: datetime,
) -> str:
    """Validate public OCI retrieval content against the expected local identity."""
    try:
        leaf = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as error:
        raise CertificateValidationError("OCI public bundle leaf PEM is invalid") from error
    if _common_name(leaf) != certificate.common_name:
        raise CertificateValidationError(
            "OCI public bundle Common Name does not match configuration"
        )
    if _dns_sans(leaf) != certificate.domains:
        raise CertificateValidationError(
            "OCI public bundle SAN does not exactly match configuration"
        )
    _validate_validity(leaf, global_config, now)
    return certificate_sha256(leaf)
