from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

import pytest
from oci.certificates_management import models as management_models
from oci.exceptions import ServiceError

from oci_acme_publisher.oci_certificates import (
    CertificatesManagementAdapter,
    CertificatesRetrievalAdapter,
    OciCertificateError,
    version_name,
)
from oci_acme_publisher.oci_retry import ReadRetryPolicy


@dataclass
class _Data:
    id: str | None = None
    current_version: object | None = None
    version_number: int | None = None
    version_name: str | None = None
    stages: list[str] | None = None
    certificate_pem: str | None = None
    cert_chain_pem: str | None = None
    time_created: object | None = None
    time_of_deletion: object | None = None


@dataclass
class _Response:
    data: object
    headers: dict[str, str]


@dataclass
class _Collection:
    items: list[_Data]


class _ManagementClient:
    def __init__(self) -> None:
        self.updated: list[tuple[object, ...]] = []
        self.created: list[tuple[object, ...]] = []
        self.scheduled: list[tuple[object, ...]] = []

    def get_certificate(self, certificate_id: str, **_: object) -> _Response:
        current = _Data(version_number=3)
        return _Response(_Data(id=certificate_id, current_version=current), {"etag": "etag-1"})

    def list_certificate_versions(self, _: str, **__: object) -> _Response:
        return _Response([_Data(version_number=3, version_name="current", stages=["CURRENT"])], {})

    def get_certificate_version(self, _: str, version_number: int, **__: object) -> _Response:
        return _Response(
            _Data(version_number=version_number, version_name="pending", stages=["PENDING"]),
            {"etag": "version-etag"},
        )

    def update_certificate(self, *arguments: object, **keywords: object) -> _Response:
        self.updated.append((*arguments, keywords))
        return _Response(_Data(), {})

    def create_certificate(self, *arguments: object, **keywords: object) -> _Response:
        self.created.append((*arguments, keywords))
        return _Response(_Data(id="ocid1.certificate.oc1.created"), {})

    def schedule_certificate_version_deletion(
        self, *arguments: object, **keywords: object
    ) -> _Response:
        self.scheduled.append((*arguments, keywords))
        return _Response(_Data(), {})


class _RetrievalClient:
    def get_certificate_bundle(self, _: str, **__: object) -> _Response:
        return _Response(
            _Data(
                certificate_pem="certificate",
                cert_chain_pem="chain",
                version_number=3,
                version_name="current",
                stages=["CURRENT"],
            ),
            {},
        )


def test_version_name_is_deterministic() -> None:
    assert (
        version_name(datetime(2026, 8, 6, tzinfo=UTC), "a" * 64)
        == "le-20260806T000000Z-aaaaaaaaaaaa"
    )


def test_management_adapter_keeps_pending_upload_and_promotion_separate() -> None:
    client = _ManagementClient()
    adapter = CertificatesManagementAdapter(client)
    certificate = adapter.get_certificate("ocid1.certificate.example", opc_request_id="request")
    assert certificate.current_version_number == 3
    adapter.upload_pending_version(
        certificate.certificate_id,
        etag=certificate.etag,
        version_name_value="le-20260806T000000Z-aaaaaaaaaaaa",
        certificate_pem=b"certificate",
        cert_chain_pem=b"chain",
        private_key_pem=b"key",
        opc_request_id="request",
    )
    adapter.promote_current(
        certificate.certificate_id, 4, etag=certificate.etag, opc_request_id="request"
    )
    update = cast(management_models.UpdateCertificateDetails, client.updated[0][1])
    pending = cast(
        management_models.UpdateCertificateByImportingConfigDetails, update.certificate_config
    )
    promotion = cast(management_models.UpdateCertificateDetails, client.updated[1][1])
    assert pending.stage == "PENDING"
    assert promotion.current_version_number == 4


def test_retrieval_adapter_requests_public_only_bundle() -> None:
    bundle = CertificatesRetrievalAdapter(_RetrievalClient()).get_public_bundle(
        "ocid1.certificate.example", opc_request_id="request"
    )
    assert bundle.stages == ("CURRENT",)


def test_management_adapter_lists_gets_creates_and_schedules_versions() -> None:
    client = _ManagementClient()
    adapter = CertificatesManagementAdapter(client)

    versions = adapter.list_versions("ocid1.certificate.example", opc_request_id="request")
    pending = adapter.get_version("ocid1.certificate.example", 4, opc_request_id="request")
    created = adapter.create_imported_certificate(
        compartment_id="ocid1.compartment.example",
        certificate_name="main-site",
        version_name_value="le-20260806T000000Z-aaaaaaaaaaaa",
        certificate_pem=b"certificate",
        cert_chain_pem=b"chain",
        private_key_pem=b"key",
        opc_request_id="request",
    )
    adapter.schedule_version_deletion(
        "ocid1.certificate.example",
        1,
        time_of_deletion=datetime(2026, 9, 6, tzinfo=UTC),
        etag="etag-1",
        opc_request_id="request",
    )

    assert versions[0].version_name == "current"
    assert pending.stages == ("PENDING",)
    assert pending.etag == "version-etag"
    assert created == "ocid1.certificate.oc1.created"
    assert len(client.created) == 1
    assert len(client.scheduled) == 1


def test_management_adapter_collects_all_version_pages() -> None:
    pages_seen: list[str | None] = []

    class Client:
        def list_certificate_versions(self, _: str, **keywords: object) -> _Response:
            page = keywords.get("page")
            pages_seen.append(page if isinstance(page, str) else None)
            if page is None:
                return _Response(
                    [_Data(version_number=1, version_name="first", stages=["DEPRECATED"])],
                    {"opc-next-page": "second-page"},
                )
            return _Response(
                [_Data(version_number=2, version_name="second", stages=["CURRENT"])], {}
            )

    versions = CertificatesManagementAdapter(Client()).list_versions(
        "ocid1.certificate.example", opc_request_id="request"
    )

    assert [version.version_number for version in versions] == [1, 2]
    assert pages_seen == [None, "second-page"]


def test_management_adapter_accepts_oci_version_collection_items() -> None:
    class Client:
        def list_certificate_versions(self, *_: object, **__: object) -> _Response:
            return _Response(
                _Collection([_Data(version_number=2, version_name="pending", stages=["PENDING"])]),
                {},
            )

    versions = CertificatesManagementAdapter(Client()).list_versions(
        "ocid1.certificate.example", opc_request_id="request"
    )

    assert versions[0].version_number == 2
    assert versions[0].stages == ("PENDING",)


def test_management_adapter_rejects_a_cyclic_version_page_token() -> None:
    class Client:
        def list_certificate_versions(self, *_: object, **__: object) -> _Response:
            return _Response([], {"opc-next-page": "same-page"})

    with pytest.raises(OciCertificateError, match="page token"):
        CertificatesManagementAdapter(Client()).list_versions(
            "ocid1.certificate.example", opc_request_id="request"
        )


def test_adapter_rejects_incomplete_or_mismatched_oci_responses() -> None:
    class BadManagement:
        def get_certificate(self, _: str, **__: object) -> _Response:
            return _Response(_Data(id="ocid1.certificate.other"), {})

        def list_certificate_versions(self, _: str, **__: object) -> _Response:
            return _Response([_Data(version_number=None, stages=[])], {})

    class BadRetrieval:
        def get_certificate_bundle(self, _: str, **__: object) -> _Response:
            return _Response(_Data(certificate_pem="certificate", cert_chain_pem=None), {})

    management = CertificatesManagementAdapter(BadManagement())
    with pytest.raises(OciCertificateError, match="mismatched"):
        management.get_certificate("ocid1.certificate.example", opc_request_id="request")
    with pytest.raises(OciCertificateError, match="version number"):
        management.list_versions("ocid1.certificate.example", opc_request_id="request")
    with pytest.raises(OciCertificateError, match="public bundle"):
        CertificatesRetrievalAdapter(BadRetrieval()).get_public_bundle(
            "ocid1.certificate.example", opc_request_id="request"
        )


@pytest.mark.parametrize("fingerprint", ("A" * 64, "short"))
def test_version_name_rejects_noncanonical_fingerprint(fingerprint: str) -> None:
    with pytest.raises(ValueError, match="lower-case hexadecimal"):
        version_name(datetime(2026, 8, 6, tzinfo=UTC), fingerprint)


@pytest.mark.parametrize(
    "version",
    (
        _Data(version_number=1, version_name=object(), stages=[]),
        _Data(version_number=1, version_name="valid", stages=[1]),
        _Data(version_number=1, version_name="valid", stages=[], time_created=object()),
        _Data(version_number=1, version_name="valid", stages=[], time_of_deletion=object()),
    ),
)
def test_management_adapter_rejects_invalid_version_metadata(version: _Data) -> None:
    class Client:
        def list_certificate_versions(self, *_: object, **__: object) -> _Response:
            return _Response([version], {})

    with pytest.raises(OciCertificateError):
        CertificatesManagementAdapter(Client()).list_versions(
            "ocid1.certificate.example", opc_request_id="r"
        )


def test_management_adapter_rejects_invalid_resource_metadata_and_create_response() -> None:
    class Client:
        def get_certificate(self, certificate_id: str, **_: object) -> _Response:
            return _Response(
                _Data(id=certificate_id, current_version=_Data(version_number="3")), {}
            )

        def create_certificate(self, *_: object, **__: object) -> _Response:
            return _Response(_Data(id=""), {})

    adapter = CertificatesManagementAdapter(Client())
    with pytest.raises(OciCertificateError, match="current version"):
        adapter.get_certificate("ocid1.certificate.example", opc_request_id="r")
    with pytest.raises(OciCertificateError, match="lacks certificate OCID"):
        adapter.create_imported_certificate(
            compartment_id="ocid1.compartment.example",
            certificate_name="name",
            version_name_value="le-20260806T000000Z-aaaaaaaaaaaa",
            certificate_pem=b"certificate",
            cert_chain_pem=b"chain",
            private_key_pem=b"key",
            opc_request_id="r",
        )


def test_retrieval_adapter_rejects_invalid_public_version_metadata() -> None:
    class Client:
        def get_certificate_bundle(self, *_: object, **__: object) -> _Response:
            return _Response(
                _Data(
                    certificate_pem="certificate",
                    cert_chain_pem="chain",
                    version_number=None,
                    version_name="current",
                    stages=[],
                ),
                {},
            )

    with pytest.raises(OciCertificateError, match="version metadata"):
        CertificatesRetrievalAdapter(Client()).get_public_bundle(
            "ocid1.certificate.example", opc_request_id="r"
        )


def test_adapter_translates_final_sdk_service_errors() -> None:
    class ManagementClient:
        def schedule_certificate_version_deletion(self, *_: object, **__: object) -> _Response:
            raise ServiceError(409, "Conflict", {}, "conflict")

    class RetrievalClient:
        def get_certificate_bundle(self, *_: object, **__: object) -> _Response:
            raise ServiceError(404, "NotAuthorizedOrNotFound", {}, "not ready")

    with pytest.raises(OciCertificateError, match="deletion scheduling"):
        CertificatesManagementAdapter(ManagementClient()).schedule_version_deletion(
            "ocid1.certificate.example",
            1,
            time_of_deletion=datetime(2026, 9, 6, tzinfo=UTC),
            etag="version-etag",
            opc_request_id="request",
        )
    with pytest.raises(OciCertificateError, match="public bundle retrieval"):
        CertificatesRetrievalAdapter(
            RetrievalClient(), read_retry_policy=ReadRetryPolicy(1)
        ).get_public_bundle("ocid1.certificate.example", opc_request_id="request")


def test_adapters_reject_invalid_etag_version_list_and_public_stages() -> None:
    class ManagementClient:
        def get_certificate(self, certificate_id: str, **_: object) -> _Response:
            return _Response(_Data(id=certificate_id), {"etag": 1})  # type: ignore[dict-item]

        def list_certificate_versions(self, *_: object, **__: object) -> _Response:
            return _Response(object(), {})

    class RetrievalClient:
        def get_certificate_bundle(self, *_: object, **__: object) -> _Response:
            return _Response(
                _Data(
                    certificate_pem="certificate",
                    cert_chain_pem="chain",
                    version_number=1,
                    version_name="version",
                    stages=None,
                ),
                {},
            )

    management = CertificatesManagementAdapter(ManagementClient())
    with pytest.raises(OciCertificateError, match="ETag"):
        management.get_certificate("ocid1.certificate.example", opc_request_id="r")
    with pytest.raises(OciCertificateError, match="version list"):
        management.list_versions("ocid1.certificate.example", opc_request_id="r")
    with pytest.raises(OciCertificateError, match="invalid stages"):
        CertificatesRetrievalAdapter(RetrievalClient()).get_public_bundle(
            "ocid1.certificate.example", opc_request_id="r"
        )
