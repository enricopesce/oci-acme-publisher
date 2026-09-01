from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from oci_acme_publisher.certificate_store import LineageMaterial
from oci_acme_publisher.certificate_validator import (
    CertificateValidationError,
    _common_name,
    _dns_sans,
    _validate_country,
    _validate_extensions,
    _validate_key,
    _validate_validity,
    validate_certificate_material,
    validate_public_certificate,
    verify_certificate_signature,
)
from oci_acme_publisher.config import load_config


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _certificate(
    subject: x509.Name,
    issuer: x509.Name,
    subject_key: rsa.RSAPrivateKey,
    issuer_key: rsa.RSAPrivateKey,
    *,
    ca: bool,
    san: tuple[str, ...] = (),
    digital_signature: bool = True,
    server_auth: bool = True,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature,
                False,
                False,
                False,
                False,
                ca,
                False,
                False,
                False,
            ),
            critical=True,
        )
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain) for domain in san]), critical=False
        ).add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH]
                if server_auth
                else [ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def material_with_root(
    *, san: tuple[str, ...] = ("example.com", "www.example.com")
) -> tuple[LineageMaterial, x509.Certificate]:
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = _certificate(_name("root.example"), _name("root.example"), root_key, root_key, ca=True)
    issuer = _certificate(_name("issuer.example"), root.subject, issuer_key, root_key, ca=True)
    leaf = _certificate(
        _name("example.com"), issuer.subject, leaf_key, issuer_key, ca=False, san=san
    )
    leaf_pem = leaf.public_bytes(serialization.Encoding.PEM)
    chain_pem = issuer.public_bytes(serialization.Encoding.PEM) + root.public_bytes(
        serialization.Encoding.PEM
    )
    private_key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    material = LineageMaterial(
        leaf=leaf,
        intermediates=(issuer, root),
        private_key=leaf_key,
        leaf_pem=leaf_pem,
        chain_pem=chain_pem,
        private_key_pem=private_key_pem,
    )
    return material, root


def _material(*, san: tuple[str, ...] = ("example.com", "www.example.com")) -> LineageMaterial:
    return material_with_root(san=san)[0]


def test_validates_matching_leaf_key_cn_and_san() -> None:
    config = load_config("config/config.example.yaml")
    fingerprint = validate_certificate_material(
        _material(),
        config.certificates[0],
        config.compatibility,
        config.global_,
        now=datetime.now(UTC),
    )
    assert len(fingerprint) == 64


def test_rejects_san_mismatch() -> None:
    config = load_config("config/config.example.yaml")
    with pytest.raises(CertificateValidationError, match="SAN"):
        validate_certificate_material(
            _material(san=("example.com",)),
            config.certificates[0],
            config.compatibility,
            config.global_,
            now=datetime.now(UTC),
        )


def test_rejects_private_key_mismatch_and_empty_chain() -> None:
    config = load_config("config/config.example.yaml")
    material = _material()
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    mismatched = LineageMaterial(
        material.leaf,
        material.intermediates,
        wrong_key,
        material.leaf_pem,
        material.chain_pem,
        material.private_key_pem,
    )
    with pytest.raises(CertificateValidationError, match="private key"):
        validate_certificate_material(
            mismatched,
            config.certificates[0],
            config.compatibility,
            config.global_,
            now=datetime.now(UTC),
        )

    without_chain = LineageMaterial(
        material.leaf,
        (),
        material.private_key,
        material.leaf_pem,
        material.chain_pem,
        material.private_key_pem,
    )
    with pytest.raises(CertificateValidationError, match="chain is empty"):
        validate_certificate_material(
            without_chain,
            config.certificates[0],
            config.compatibility,
            config.global_,
            now=datetime.now(UTC),
        )


def test_rejects_oversized_local_material_after_profile_validation() -> None:
    config = load_config("config/config.example.yaml")
    material = _material()
    oversized = LineageMaterial(
        material.leaf,
        material.intermediates,
        material.private_key,
        b"x" * 10_241,
        material.chain_pem,
        material.private_key_pem,
    )
    with pytest.raises(CertificateValidationError, match="size limit"):
        validate_certificate_material(
            oversized,
            config.certificates[0],
            config.compatibility,
            config.global_,
            now=datetime.now(UTC),
        )


def test_signature_verification_rejects_an_unrelated_issuer() -> None:
    material, root = material_with_root()
    with pytest.raises(CertificateValidationError, match="signature verification"):
        verify_certificate_signature(material.leaf, root)


def test_public_certificate_validation_rejects_malformed_and_accepts_matching_leaf() -> None:
    config = load_config("config/config.example.yaml")
    with pytest.raises(CertificateValidationError, match="PEM is invalid"):
        validate_public_certificate(
            "not pem", config.certificates[0], config.global_, now=datetime.now(UTC)
        )

    material = _material()
    fingerprint = validate_public_certificate(
        material.leaf_pem.decode("ascii"),
        config.certificates[0],
        config.global_,
        now=datetime.now(UTC),
    )
    assert len(fingerprint) == 64


def test_extension_validation_rejects_ca_leaf() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_leaf = _certificate(_name("example.com"), _name("example.com"), key, key, ca=True)
    with pytest.raises(CertificateValidationError, match="must not be a CA"):
        _validate_extensions(ca_leaf)


def test_key_country_and_validity_constraints_fail_closed() -> None:
    config = load_config("config/config.example.yaml")
    material = _material()
    ecdsa_expected = config.certificates[0].model_copy(
        update={"key": config.certificates[0].key.model_copy(update={"type": "ecdsa"})}
    )
    with pytest.raises(CertificateValidationError, match="ECDSA key"):
        _validate_key(material.leaf, ecdsa_expected)

    countryless_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    countryless = _certificate(
        countryless_name,
        countryless_name,
        material.private_key,
        material.private_key,
        ca=False,
        san=("example.com",),
    )
    with pytest.raises(CertificateValidationError, match="country code"):
        _validate_country(countryless, config.compatibility)

    with pytest.raises(CertificateValidationError, match="expired"):
        _validate_validity(
            material.leaf,
            config.global_,
            datetime.now(UTC) + timedelta(days=366),
        )

    with pytest.raises(CertificateValidationError, match="not yet valid"):
        _validate_validity(
            material.leaf,
            config.global_,
            datetime.now(UTC) - timedelta(days=366),
        )


def test_san_and_leaf_extension_constraints_fail_closed() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    no_san = _certificate(_name("example.com"), _name("example.com"), key, key, ca=True)
    with pytest.raises(CertificateValidationError, match="does not contain SAN"):
        _dns_sans(no_san)

    client_only = _certificate(
        _name("example.com"),
        _name("example.com"),
        key,
        key,
        ca=False,
        san=("example.com",),
        server_auth=False,
    )
    with pytest.raises(CertificateValidationError, match="excludes server"):
        _validate_extensions(client_only)

    no_signature = _certificate(
        _name("example.com"),
        _name("example.com"),
        key,
        key,
        ca=False,
        san=("example.com",),
        digital_signature=False,
    )
    with pytest.raises(CertificateValidationError, match="digital signature"):
        _validate_extensions(no_signature)


def test_certificate_helpers_reject_missing_cn_basic_constraints_and_rsa_size() -> None:
    class Subject:
        def get_attributes_for_oid(self, _: object) -> list[object]:
            return []

    with pytest.raises(CertificateValidationError, match="exactly one Common Name"):
        _common_name(type("Certificate", (), {"subject": Subject()})())

    class Extensions:
        def get_extension_for_class(self, _: object) -> object:
            raise x509.ExtensionNotFound("missing", ExtensionOID.BASIC_CONSTRAINTS)

    with pytest.raises(CertificateValidationError, match="lacks BasicConstraints"):
        _validate_extensions(type("Certificate", (), {"extensions": Extensions()})())

    config = load_config("config/config.example.yaml")
    material = _material()
    rsa_4096 = config.certificates[0].model_copy(
        update={"key": config.certificates[0].key.model_copy(update={"rsa_size": 4096})}
    )
    with pytest.raises(CertificateValidationError, match="RSA key"):
        _validate_key(material.leaf, rsa_4096)
