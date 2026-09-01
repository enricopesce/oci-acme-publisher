"""Narrow OCI Certificates adapters; deliberately no Load Balancer dependency."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from oci.certificates_management import models as management_models
from oci.exceptions import ServiceError

from .oci_retry import ReadRetryPolicy, retry_read_sync


class OciCertificateError(RuntimeError):
    """An OCI Certificates response did not satisfy the adapter contract."""


@dataclass(frozen=True, slots=True)
class OciCertificate:
    """Safe management metadata required by reconciliation."""

    certificate_id: str
    etag: str | None
    current_version_number: int | None


@dataclass(frozen=True, slots=True)
class OciCertificateVersion:
    """A compact certificate-version record without private material."""

    version_number: int
    version_name: str | None
    stages: tuple[str, ...]
    time_created: datetime | None = None
    time_of_deletion: datetime | None = None
    etag: str | None = None


@dataclass(frozen=True, slots=True)
class OciPublicBundle:
    """Public-only certificate bundle returned by the retrieval API."""

    certificate_pem: str
    cert_chain_pem: str
    version_number: int
    version_name: str | None
    stages: tuple[str, ...]


def version_name(now: datetime, fingerprint: str) -> str:
    """Return the deterministic idempotency name mandated for imported versions."""
    if len(fingerprint) < 12 or any(
        character not in "0123456789abcdef" for character in fingerprint
    ):
        raise ValueError("fingerprint must be lower-case hexadecimal SHA-256")
    timestamp = now.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"le-{timestamp}-{fingerprint[:12]}"


def _version_from_data(data: Any, *, etag: str | None = None) -> OciCertificateVersion:
    number = getattr(data, "version_number", None)
    if not isinstance(number, int):
        raise OciCertificateError("OCI response has no certificate version number")
    version_name_value = getattr(data, "version_name", None)
    if version_name_value is not None and not isinstance(version_name_value, str):
        raise OciCertificateError("OCI response has invalid certificate version name")
    stages_value = getattr(data, "stages", ())
    if not isinstance(stages_value, list) or not all(
        isinstance(stage, str) for stage in stages_value
    ):
        raise OciCertificateError("OCI response has invalid certificate stages")
    created = getattr(data, "time_created", None)
    deletion = getattr(data, "time_of_deletion", None)
    if created is not None and not isinstance(created, datetime):
        raise OciCertificateError("OCI response has invalid version creation time")
    if deletion is not None and not isinstance(deletion, datetime):
        raise OciCertificateError("OCI response has invalid version deletion time")
    if etag is not None and not isinstance(etag, str):
        raise OciCertificateError("OCI returned an invalid version ETag")
    return OciCertificateVersion(
        number, version_name_value, tuple(stages_value), created, deletion, etag
    )


class CertificatesManagementAdapter:
    """Synchronous OCI management operations, to be run in the dedicated executor."""

    def __init__(
        self, client: Any, *, read_retry_policy: ReadRetryPolicy | None = None
    ) -> None:  # OCI SDK has no complete type stubs.
        self._client = client
        self._read_retry_policy = read_retry_policy or ReadRetryPolicy(max_attempts=5)

    def _read(self, operation: Any) -> Any:
        return retry_read_sync(operation, self._read_retry_policy)

    def get_certificate(self, certificate_id: str, *, opc_request_id: str) -> OciCertificate:
        """Get the resource and its optimistic-concurrency ETag."""
        response = self._read(
            lambda: self._client.get_certificate(certificate_id, opc_request_id=opc_request_id)
        )
        data = response.data
        resource_id = getattr(data, "id", None)
        if resource_id != certificate_id:
            raise OciCertificateError("OCI returned a mismatched certificate identifier")
        current = getattr(data, "current_version", None)
        current_number = getattr(current, "version_number", None) if current is not None else None
        if current_number is not None and not isinstance(current_number, int):
            raise OciCertificateError("OCI returned an invalid current version")
        etag = response.headers.get("etag")
        if etag is not None and not isinstance(etag, str):
            raise OciCertificateError("OCI returned an invalid ETag")
        return OciCertificate(certificate_id, etag, current_number)

    def list_versions(
        self, certificate_id: str, *, opc_request_id: str
    ) -> tuple[OciCertificateVersion, ...]:
        """Return every version page, rejecting malformed or cyclic OCI page tokens."""
        versions: list[OciCertificateVersion] = []
        page: str | None = None
        seen_pages: set[str] = set()
        while True:
            arguments: dict[str, str] = {"opc_request_id": opc_request_id}
            if page is not None:
                arguments["page"] = page
            request_arguments = dict(arguments)
            response = self._read(
                lambda request_arguments=request_arguments: self._client.list_certificate_versions(
                    certificate_id, **request_arguments
                )
            )
            collection = response.data
            items = getattr(collection, "items", collection)
            if not isinstance(items, list):
                raise OciCertificateError("OCI returned invalid certificate-version list")
            versions.extend(_version_from_data(item) for item in items)
            next_page = response.headers.get("opc-next-page")
            if next_page is None:
                return tuple(versions)
            if not isinstance(next_page, str) or not next_page or next_page in seen_pages:
                raise OciCertificateError("OCI returned an invalid certificate-version page token")
            seen_pages.add(next_page)
            page = next_page

    def get_version(
        self, certificate_id: str, version_number: int, *, opc_request_id: str
    ) -> OciCertificateVersion:
        """Get one version's stage/name metadata."""
        response = self._read(
            lambda: self._client.get_certificate_version(
                certificate_id, version_number, opc_request_id=opc_request_id
            )
        )
        return _version_from_data(response.data, etag=response.headers.get("etag"))

    def create_imported_certificate(
        self,
        *,
        compartment_id: str,
        certificate_name: str,
        version_name_value: str,
        certificate_pem: bytes,
        cert_chain_pem: bytes,
        private_key_pem: bytes,
        opc_request_id: str,
    ) -> str:
        """Bootstrap an imported certificate; OCI decides its initial stage."""
        config = management_models.CreateCertificateByImportingConfigDetails(
            version_name=version_name_value,
            certificate_pem=certificate_pem.decode("ascii"),
            cert_chain_pem=cert_chain_pem.decode("ascii"),
            private_key_pem=private_key_pem.decode("ascii"),
        )
        details = management_models.CreateCertificateDetails(
            name=certificate_name,
            compartment_id=compartment_id,
            certificate_config=config,
        )
        response = self._client.create_certificate(details, opc_request_id=opc_request_id)
        certificate_id = getattr(response.data, "id", None)
        if not isinstance(certificate_id, str) or not certificate_id:
            raise OciCertificateError("OCI create response lacks certificate OCID")
        return certificate_id

    def upload_pending_version(
        self,
        certificate_id: str,
        *,
        etag: str | None,
        version_name_value: str,
        certificate_pem: bytes,
        cert_chain_pem: bytes,
        private_key_pem: bytes,
        opc_request_id: str,
    ) -> None:
        """Import exactly one new version at PENDING; this never promotes it."""
        details = management_models.UpdateCertificateByImportingConfigDetails(
            version_name=version_name_value,
            stage="PENDING",
            certificate_pem=certificate_pem.decode("ascii"),
            cert_chain_pem=cert_chain_pem.decode("ascii"),
            private_key_pem=private_key_pem.decode("ascii"),
        )
        update = management_models.UpdateCertificateDetails(certificate_config=details)
        self._client.update_certificate(
            certificate_id,
            update,
            if_match=etag,
            opc_request_id=opc_request_id,
        )

    def promote_current(
        self,
        certificate_id: str,
        version_number: int,
        *,
        etag: str | None,
        opc_request_id: str,
    ) -> None:
        """Promote with a distinct request containing no other resource changes."""
        details = management_models.UpdateCertificateDetails(current_version_number=version_number)
        self._client.update_certificate(
            certificate_id,
            details,
            if_match=etag,
            opc_request_id=opc_request_id,
        )

    def schedule_version_deletion(
        self,
        certificate_id: str,
        version_number: int,
        *,
        time_of_deletion: datetime,
        etag: str | None,
        opc_request_id: str,
    ) -> None:
        """Schedule deletion rather than deleting immediately."""
        details = management_models.ScheduleCertificateVersionDeletionDetails(
            time_of_deletion=time_of_deletion
        )
        try:
            self._client.schedule_certificate_version_deletion(
                certificate_id,
                version_number,
                details,
                if_match=etag,
                opc_request_id=opc_request_id,
            )
        except ServiceError as error:
            raise OciCertificateError("OCI version deletion scheduling failed") from error


class CertificatesRetrievalAdapter:
    """Public-only OCI retrieval calls; this adapter never requests private keys."""

    def __init__(
        self, client: Any, *, read_retry_policy: ReadRetryPolicy | None = None
    ) -> None:  # OCI SDK has no complete type stubs.
        self._client = client
        self._read_retry_policy = read_retry_policy or ReadRetryPolicy(max_attempts=5)

    def get_public_bundle(
        self,
        certificate_id: str,
        *,
        opc_request_id: str,
        version_number: int | None = None,
    ) -> OciPublicBundle:
        """Retrieve the current or numbered public bundle only."""
        arguments: dict[str, object] = {
            "opc_request_id": opc_request_id,
            "certificate_bundle_type": "CERTIFICATE_CONTENT_PUBLIC_ONLY",
        }
        if version_number is not None:
            arguments["version_number"] = version_number
        try:
            response = retry_read_sync(
                lambda: self._client.get_certificate_bundle(certificate_id, **arguments),
                self._read_retry_policy,
            )
        except ServiceError as error:
            raise OciCertificateError("OCI public bundle retrieval failed") from error
        data = response.data
        certificate_pem = getattr(data, "certificate_pem", None)
        cert_chain_pem = getattr(data, "cert_chain_pem", None)
        retrieved_version = getattr(data, "version_number", None)
        retrieved_name = getattr(data, "version_name", None)
        stages = getattr(data, "stages", None)
        if not isinstance(certificate_pem, str) or not isinstance(cert_chain_pem, str):
            raise OciCertificateError("OCI retrieval response does not contain a public bundle")
        if not isinstance(retrieved_version, int) or not isinstance(
            retrieved_name, str | type(None)
        ):
            raise OciCertificateError("OCI retrieval response has invalid version metadata")
        if not isinstance(stages, list) or not all(isinstance(stage, str) for stage in stages):
            raise OciCertificateError("OCI retrieval response has invalid stages")
        return OciPublicBundle(
            certificate_pem, cert_chain_pem, retrieved_version, retrieved_name, tuple(stages)
        )
