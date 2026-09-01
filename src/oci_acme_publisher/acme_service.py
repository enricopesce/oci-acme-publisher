"""Native RFC 8555 issuance using the Python ACME protocol library."""

from __future__ import annotations

import os
import re
import secrets
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests
from acme import challenges, client, errors, messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from josepy.jwk import JWKRSA

from .certificate_store import LineageMaterial, NativeCertificateStore
from .certificate_validator import CertificateValidationError, validate_certificate_material
from .chain_builder import ChainBuildError, build_oci_chain
from .config import AppConfig, CertificateConfig
from .fingerprint import certificate_sha256
from .http01_preflight import _remove_challenge, _write_challenge
from .models import KeyType

_TOKEN = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
_ACCOUNT_KEY_BITS = 3072


class AcmeOperationError(RuntimeError):
    """Native ACME issuance did not complete safely."""


class NativeAcmeService:
    """Own account, order, HTTP-01 and local-generation lifecycle."""

    def __init__(self, store: NativeCertificateStore) -> None:
        self._store = store

    def issue(
        self,
        config: AppConfig,
        certificate: CertificateConfig,
        *,
        force: bool = False,
    ) -> LineageMaterial:
        current = self._load_optional(certificate)
        if current is not None and not force and not self._renewal_due(config, current):
            return current
        private_key = self._certificate_key(config, certificate, current)
        private_key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        csr_pem = self._csr(certificate, private_key)
        challenge_paths: list[Path] = []
        try:
            acme_client = self._client(config)
            order = acme_client.new_order(csr_pem, profile=config.acme.preferred_profile)
            expected = set(certificate.domains)
            observed = {
                authorization.body.identifier.value for authorization in order.authorizations
            }
            if observed != expected:
                raise AcmeOperationError("ACME order returned unexpected identifiers")
            for authorization in order.authorizations:
                challenge = self._http01(authorization)
                response, validation = challenge.response_and_validation(acme_client.net.key)
                token = challenge.chall.encode("token")
                if not isinstance(token, str) or _TOKEN.fullmatch(token) is None:
                    raise AcmeOperationError("ACME server returned an invalid HTTP-01 token")
                path = (
                    Path(config.http01.webroot_base)
                    / certificate.webroot_id
                    / ".well-known"
                    / "acme-challenge"
                    / token
                )
                _write_challenge(path, validation.encode("ascii"))
                challenge_paths.append(path)
                acme_client.answer_challenge(challenge, response)
            deadline = datetime.now() + timedelta(seconds=config.acme.operation_timeout_seconds)
            authorized = acme_client.poll_authorizations(order, deadline)
            finalized = acme_client.finalize_order(
                authorized, deadline, fetch_alternative_chains=True
            )
            material = self._select_chain(
                config, certificate, finalized, private_key, private_key_pem
            )
            generation = (
                datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
                + "-"
                + certificate_sha256(material.leaf)[:12]
                + "-"
                + secrets.token_hex(4)
            )
            return self._store.commit(
                certificate,
                leaf_pem=material.leaf_pem,
                chain_pem=material.chain_pem,
                private_key_pem=private_key_pem,
                generation_name=generation,
            )
        except AcmeOperationError:
            raise
        except (errors.Error, requests.RequestException, OSError, TypeError, ValueError) as error:
            raise AcmeOperationError("native ACME operation failed") from error
        finally:
            for path in challenge_paths:
                _remove_challenge(path)

    def _client(self, config: AppConfig) -> client.ClientV2:
        account_key = self._account_key(config)
        network = client.ClientNetwork(
            account_key,
            user_agent="oci-acme-publisher/2.0",
            timeout=min(config.acme.operation_timeout_seconds, 300),
        )
        directory = client.ClientV2.get_directory(config.acme.directory_url, network)
        acme_client = client.ClientV2(directory, net=network)
        registration = messages.NewRegistration.from_data(
            email=config.acme.email,
            terms_of_service_agreed=config.acme.agree_to_terms,
        )
        try:
            acme_client.new_account(registration)
        except errors.ConflictError as error:
            # RFC 8555 servers return the existing account URL when this key is
            # already registered.  Rehydrate the client session from that URL;
            # treating this response as a failure would make only the first
            # certificate set usable with a persistent account key.
            existing = messages.RegistrationResource(
                body=registration,
                uri=error.location,
            )
            acme_client.query_registration(existing)
        return acme_client

    def _account_key(self, config: AppConfig) -> JWKRSA:
        path = Path(config.acme.account_key_path)
        if not path.exists():
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            generated_key = rsa.generate_private_key(
                public_exponent=65537, key_size=_ACCOUNT_KEY_BITS
            )
            pem = generated_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600)
            try:
                offset = 0
                while offset < len(pem):
                    offset += os.write(descriptor, pem[offset:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as error:
            raise AcmeOperationError("ACME account key is unavailable") from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
                raise AcmeOperationError("ACME account key permissions are unsafe")
            raw = os.read(descriptor, 16_385)
            if len(raw) > 16_384:
                raise AcmeOperationError("ACME account key exceeds size limit")
            loaded_key = serialization.load_pem_private_key(raw, password=None)
        finally:
            os.close(descriptor)
        if not isinstance(loaded_key, rsa.RSAPrivateKey):
            raise AcmeOperationError("ACME account key must be RSA")
        return JWKRSA(key=loaded_key)

    def _load_optional(self, certificate: CertificateConfig) -> LineageMaterial | None:
        if not self._store.exists(certificate):
            return None
        return self._store.load(certificate)

    @staticmethod
    def _renewal_due(config: AppConfig, material: LineageMaterial) -> bool:
        threshold = datetime.now(UTC) + timedelta(days=config.acme.renew_before_days)
        return material.leaf.not_valid_after_utc <= threshold

    @staticmethod
    def _certificate_key(
        config: AppConfig,
        certificate: CertificateConfig,
        current: LineageMaterial | None,
    ) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
        if current is not None and not config.acme.rotate_private_key_on_renewal:
            key = current.private_key
            if isinstance(key, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
                return key
            raise AcmeOperationError("stored certificate private key type is unsupported")
        if certificate.key.type is KeyType.RSA:
            return rsa.generate_private_key(
                public_exponent=65537, key_size=int(certificate.key.rsa_size or 2048)
            )
        curve = ec.SECP384R1() if certificate.key.ecdsa_curve == "secp384r1" else ec.SECP256R1()
        return ec.generate_private_key(curve)

    @staticmethod
    def _csr(
        certificate: CertificateConfig,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    ) -> bytes:
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, certificate.common_name)])
        )
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain) for domain in certificate.domains]),
            critical=False,
        )
        return builder.sign(private_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    @staticmethod
    def _http01(authorization: messages.AuthorizationResource) -> messages.ChallengeBody:
        matches = tuple(
            challenge
            for challenge in authorization.body.challenges
            if isinstance(challenge.chall, challenges.HTTP01)
        )
        if len(matches) != 1:
            raise AcmeOperationError(
                "ACME authorization did not offer exactly one HTTP-01 challenge"
            )
        return matches[0]

    @staticmethod
    def _select_chain(
        config: AppConfig,
        certificate: CertificateConfig,
        order: messages.OrderResource,
        private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
        private_key_pem: bytes,
    ) -> LineageMaterial:
        candidates = (order.fullchain_pem, *(order.alternative_fullchains_pem or ()))
        last_error: Exception | None = None
        for candidate in candidates:
            if not candidate:
                continue
            try:
                parsed = x509.load_pem_x509_certificates(candidate.encode("ascii"))
                if len(parsed) < 2:
                    raise AcmeOperationError("ACME response did not contain an intermediate chain")
                leaf_pem = parsed[0].public_bytes(serialization.Encoding.PEM)
                chain_pem = b"".join(
                    item.public_bytes(serialization.Encoding.PEM) for item in parsed[1:]
                )
                material = LineageMaterial(
                    leaf=parsed[0],
                    intermediates=tuple(parsed[1:]),
                    private_key=private_key,
                    leaf_pem=leaf_pem,
                    chain_pem=chain_pem,
                    private_key_pem=private_key_pem,
                )
                validate_certificate_material(
                    material,
                    certificate,
                    config.compatibility,
                    config.global_,
                    now=datetime.now(UTC),
                )
                build_oci_chain(material, certificate, config.compatibility)
                return material
            except (CertificateValidationError, ChainBuildError, ValueError) as error:
                last_error = error
        raise AcmeOperationError(
            "ACME server returned no acceptable certificate chain"
        ) from last_error
