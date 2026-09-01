from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from acme import challenges, messages
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from oci_acme_publisher import acme_service
from oci_acme_publisher.acme_service import AcmeOperationError, NativeAcmeService
from oci_acme_publisher.config import AppConfig, load_config

from .test_certificate_validator import material_with_root


class _RecordingStore:
    def __init__(self) -> None:
        self.commit_arguments: dict[str, Any] | None = None

    def exists(self, _certificate: object) -> bool:
        return False

    def load(self, _certificate: object) -> object:
        raise AssertionError("load must not be called without a current generation")

    def commit(self, _certificate: object, **kwargs: Any) -> object:
        self.commit_arguments = kwargs
        material, _ = material_with_root()
        return material


def _local_config(tmp_path: Path) -> AppConfig:
    config = load_config("config/config.example.yaml")
    raw = config.model_dump(by_alias=True)
    raw["acme"]["account_key_path"] = str(tmp_path / "account.key")
    raw["acme"]["certificates_dir"] = str(tmp_path / "certificates")
    raw["http01"]["webroot_base"] = str(tmp_path / "webroots")
    return AppConfig.model_validate(raw)


def test_account_key_is_created_once_with_private_permissions(tmp_path: Path) -> None:
    config = _local_config(tmp_path)
    service = NativeAcmeService(_RecordingStore())  # type: ignore[arg-type]

    first = service._account_key(config)
    second = service._account_key(config)
    path = Path(config.acme.account_key_path)

    assert path.stat().st_mode & 0o777 == 0o600
    assert first.thumbprint() == second.thumbprint()


def test_account_key_rejects_group_read_access(tmp_path: Path) -> None:
    config = _local_config(tmp_path)
    service = NativeAcmeService(_RecordingStore())  # type: ignore[arg-type]
    service._account_key(config)
    Path(config.acme.account_key_path).chmod(0o640)

    with pytest.raises(AcmeOperationError, match="permissions"):
        service._account_key(config)


def test_account_key_rejects_non_rsa_and_oversized_material(tmp_path: Path) -> None:
    config = _local_config(tmp_path)
    service = NativeAcmeService(_RecordingStore())  # type: ignore[arg-type]
    path = Path(config.acme.account_key_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    ecdsa = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path.write_bytes(ecdsa)
    path.chmod(0o600)
    with pytest.raises(AcmeOperationError, match="must be RSA"):
        service._account_key(config)

    path.write_bytes(b"x" * 16_385)
    with pytest.raises(AcmeOperationError, match="size limit"):
        service._account_key(config)


def test_account_key_rejects_symlink(tmp_path: Path) -> None:
    config = _local_config(tmp_path)
    service = NativeAcmeService(_RecordingStore())  # type: ignore[arg-type]
    target = tmp_path / "target.key"
    target.write_text("not-secret", encoding="ascii")
    Path(config.acme.account_key_path).symlink_to(target)
    with pytest.raises(AcmeOperationError, match="unavailable"):
        service._account_key(config)


def test_csr_contains_exact_common_name_and_sans() -> None:
    config = load_config("config/config.example.yaml")
    certificate = config.certificates[0]
    material, _ = material_with_root()

    csr = x509.load_pem_x509_csr(NativeAcmeService._csr(certificate, material.private_key))

    assert csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == (
        "example.com"
    )
    sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert tuple(sans.get_values_for_type(x509.DNSName)) == certificate.domains


def test_certificate_key_rotation_reuse_and_ecdsa_curves(tmp_path: Path) -> None:
    config = _local_config(tmp_path)
    certificate = config.certificates[0]
    material, _ = material_with_root()
    reused_config = config.model_copy(
        update={"acme": config.acme.model_copy(update={"rotate_private_key_on_renewal": False})}
    )
    assert NativeAcmeService._certificate_key(reused_config, certificate, material) is (
        material.private_key
    )
    with pytest.raises(AcmeOperationError, match="unsupported"):
        NativeAcmeService._certificate_key(
            reused_config,
            certificate,
            replace(material, private_key=object()),  # type: ignore[arg-type]
        )
    assert isinstance(
        NativeAcmeService._certificate_key(config, certificate, None), rsa.RSAPrivateKey
    )

    for curve_name, curve_type in (("secp256r1", ec.SECP256R1), ("secp384r1", ec.SECP384R1)):
        ecdsa_certificate = certificate.model_copy(
            update={
                "key": certificate.key.model_copy(
                    update={"type": "ecdsa", "rsa_size": None, "ecdsa_curve": curve_name}
                )
            }
        )
        key = NativeAcmeService._certificate_key(config, ecdsa_certificate, None)
        assert isinstance(key.curve, curve_type)


def test_existing_fresh_generation_is_returned_without_network(tmp_path: Path) -> None:
    config = _local_config(tmp_path).model_copy(
        update={"acme": _local_config(tmp_path).acme.model_copy(update={"renew_before_days": 1})}
    )
    material, _ = material_with_root()

    class ExistingStore(_RecordingStore):
        def exists(self, _certificate: object) -> bool:
            return True

        def load(self, _certificate: object) -> object:
            return material

    service = NativeAcmeService(ExistingStore())  # type: ignore[arg-type]
    assert service.issue(config, config.certificates[0]) is material
    assert not service._renewal_due(config, material)


def test_native_client_registers_account(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = _local_config(tmp_path)
    network = SimpleNamespace()
    captured: dict[str, object] = {}

    monkeypatch.setattr(acme_service.client, "ClientNetwork", lambda *_args, **_kwargs: network)

    class FakeV2:
        @staticmethod
        def get_directory(url: str, supplied_network: object) -> str:
            assert url == config.acme.directory_url
            assert supplied_network is network
            return "directory"

        def __init__(self, directory: object, *, net: object) -> None:
            assert directory == "directory"
            assert net is network

        def new_account(self, registration: object) -> None:
            captured["registration"] = registration

    monkeypatch.setattr(acme_service.client, "ClientV2", FakeV2)
    result = NativeAcmeService(_RecordingStore())._client(config)  # type: ignore[arg-type]
    assert isinstance(result, FakeV2)
    assert captured["registration"] is not None


def test_native_client_reuses_existing_account(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _local_config(tmp_path)
    network = SimpleNamespace()
    captured: dict[str, object] = {}

    monkeypatch.setattr(acme_service.client, "ClientNetwork", lambda *_args, **_kwargs: network)

    class FakeV2:
        @staticmethod
        def get_directory(_url: str, _network: object) -> str:
            return "directory"

        def __init__(self, _directory: object, *, net: object) -> None:
            assert net is network

        def new_account(self, _registration: object) -> None:
            raise acme_service.errors.ConflictError("https://ca.example/account/1")

        def query_registration(self, registration: object) -> None:
            captured["registration"] = registration

    monkeypatch.setattr(acme_service.client, "ClientV2", FakeV2)
    NativeAcmeService(_RecordingStore())._client(config)  # type: ignore[arg-type]

    registration = captured["registration"]
    assert isinstance(registration, messages.RegistrationResource)
    assert registration.uri == "https://ca.example/account/1"


def test_http01_requires_exactly_one_matching_challenge() -> None:
    http = messages.ChallengeBody(chall=challenges.HTTP01(token=b"token"), uri="https://ca/ch")
    authorization = SimpleNamespace(body=SimpleNamespace(challenges=(http,)))
    assert NativeAcmeService._http01(authorization) is http  # type: ignore[arg-type]

    for offered in ((), (http, http)):
        invalid = SimpleNamespace(body=SimpleNamespace(challenges=offered))
        with pytest.raises(AcmeOperationError, match="exactly one"):
            NativeAcmeService._http01(invalid)  # type: ignore[arg-type]


def test_select_chain_uses_valid_alternative_and_rejects_invalid_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config("config/config.example.yaml")
    certificate = config.certificates[0]
    material, _ = material_with_root()
    fullchain = (material.leaf_pem + material.chain_pem).decode("ascii")
    monkeypatch.setattr(acme_service, "validate_certificate_material", lambda *_a, **_k: "x")
    monkeypatch.setattr(acme_service, "build_oci_chain", lambda *_a, **_k: ())

    selected = NativeAcmeService._select_chain(
        config,
        certificate,
        SimpleNamespace(fullchain_pem="", alternative_fullchains_pem=[fullchain]),
        material.private_key,
        material.private_key_pem,
    )
    assert selected.leaf.serial_number == material.leaf.serial_number

    with pytest.raises(AcmeOperationError, match="no acceptable"):
        NativeAcmeService._select_chain(
            config,
            certificate,
            SimpleNamespace(fullchain_pem="not-pem", alternative_fullchains_pem=None),
            material.private_key,
            material.private_key_pem,
        )

    with pytest.raises(AcmeOperationError, match="intermediate chain"):
        NativeAcmeService._select_chain(
            config,
            certificate,
            SimpleNamespace(
                fullchain_pem=material.leaf_pem.decode("ascii"), alternative_fullchains_pem=[]
            ),
            material.private_key,
            material.private_key_pem,
        )


def test_issue_rejects_identifier_mismatch_and_wraps_transport_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _local_config(tmp_path)
    service = NativeAcmeService(_RecordingStore())  # type: ignore[arg-type]
    wrong_order = SimpleNamespace(
        authorizations=[
            SimpleNamespace(body=SimpleNamespace(identifier=SimpleNamespace(value="x")))
        ]
    )
    monkeypatch.setattr(
        service,
        "_client",
        lambda _config: SimpleNamespace(new_order=lambda *_a, **_k: wrong_order),
    )
    with pytest.raises(AcmeOperationError, match="unexpected identifiers"):
        service.issue(config, config.certificates[0], force=True)

    monkeypatch.setattr(service, "_client", lambda _config: (_ for _ in ()).throw(OSError()))
    with pytest.raises(AcmeOperationError, match="native ACME operation failed"):
        service.issue(config, config.certificates[0], force=True)


def test_issue_rejects_invalid_http01_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = _local_config(tmp_path)
    material, _ = material_with_root()
    service = NativeAcmeService(_RecordingStore())  # type: ignore[arg-type]
    authorizations = [
        SimpleNamespace(body=SimpleNamespace(identifier=SimpleNamespace(value=domain)))
        for domain in config.certificates[0].domains
    ]
    order = SimpleNamespace(authorizations=authorizations)
    fake_client = SimpleNamespace(
        net=SimpleNamespace(key=object()),
        new_order=lambda *_a, **_k: order,
    )
    invalid_challenge = SimpleNamespace(
        chall=SimpleNamespace(encode=lambda _name: "../unsafe"),
        response_and_validation=lambda _key: (object(), "validation"),
    )
    monkeypatch.setattr(service, "_client", lambda _config: fake_client)
    monkeypatch.setattr(service, "_certificate_key", lambda *_args: material.private_key)
    monkeypatch.setattr(service, "_http01", lambda _authorization: invalid_challenge)
    with pytest.raises(AcmeOperationError, match="invalid HTTP-01 token"):
        service.issue(config, config.certificates[0], force=True)


def test_issue_completes_http01_and_removes_challenge_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _local_config(tmp_path)
    certificate = config.certificates[0]
    material, _ = material_with_root()
    store = _RecordingStore()
    service = NativeAcmeService(store)  # type: ignore[arg-type]
    challenge_directory = (
        Path(config.http01.webroot_base) / certificate.webroot_id / ".well-known" / "acme-challenge"
    )

    class FakeChallengeType:
        def __init__(self, token: str) -> None:
            self.token = token

        def encode(self, name: str) -> str:
            assert name == "token"
            return self.token

    class FakeChallenge:
        def __init__(self, token: str) -> None:
            self.chall = FakeChallengeType(token)

        def response_and_validation(self, _key: object) -> tuple[object, str]:
            return object(), f"{self.chall.token}.validation"

    authorization = SimpleNamespace(
        body=SimpleNamespace(identifier=SimpleNamespace(value="example.com"))
    )
    second_authorization = SimpleNamespace(
        body=SimpleNamespace(identifier=SimpleNamespace(value="www.example.com"))
    )
    order = SimpleNamespace(authorizations=[authorization, second_authorization])
    final_order = SimpleNamespace(
        fullchain_pem=(material.leaf_pem + material.chain_pem).decode("ascii"),
        alternative_fullchains_pem=[],
    )

    class FakeClient:
        net = SimpleNamespace(key=object())

        def new_order(self, _csr: bytes, *, profile: str | None) -> object:
            assert profile is None
            return order

        def answer_challenge(self, _challenge: object, _response: object) -> None:
            challenge = _challenge
            assert (challenge_directory / challenge.chall.token).read_text(
                encoding="ascii"
            ) == f"{challenge.chall.token}.validation"

        def poll_authorizations(self, supplied: object, _deadline: object) -> object:
            assert supplied is order
            return order

        def finalize_order(
            self, supplied: object, _deadline: object, *, fetch_alternative_chains: bool
        ) -> object:
            assert supplied is order
            assert fetch_alternative_chains
            return final_order

    monkeypatch.setattr(service, "_client", lambda _config: FakeClient())
    monkeypatch.setattr(service, "_certificate_key", lambda *_args: material.private_key)
    challenge_tokens = iter(("safe-token-1", "safe-token-2"))
    monkeypatch.setattr(
        service, "_http01", lambda _authorization: FakeChallenge(next(challenge_tokens))
    )
    monkeypatch.setattr(acme_service, "validate_certificate_material", lambda *_args, **_kw: "x")
    monkeypatch.setattr(acme_service, "build_oci_chain", lambda *_args, **_kw: ())

    service.issue(config, certificate, force=True)

    assert store.commit_arguments is not None
    assert store.commit_arguments["leaf_pem"] == material.leaf_pem
    assert store.commit_arguments["chain_pem"] == material.chain_pem
    assert not (challenge_directory / "safe-token-1").exists()
    assert not (challenge_directory / "safe-token-2").exists()
    assert os.path.basename(store.commit_arguments["generation_name"]).startswith("20")
