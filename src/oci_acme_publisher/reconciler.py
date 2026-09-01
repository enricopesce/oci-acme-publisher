"""Idempotent local-to-OCI certificate publication reconciliation."""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from oci.exceptions import ServiceError

from .certificate_store import LineageMaterial
from .certificate_validator import CertificateValidationError, validate_public_certificate
from .chain_builder import OciCertificateChain
from .config import AppConfig, CertificateConfig
from .logging_config import log_event
from .oci_certificates import (
    OciCertificate,
    OciCertificateVersion,
    OciPublicBundle,
    version_name,
)
from .oci_retry import ReadRetryPolicy, retry_read_until_sync
from .state_store import OperationState, OperationType, StateStore


class ReconciliationError(RuntimeError):
    """Reconciliation cannot safely decide the next OCI mutation."""


_LOGGER = logging.getLogger(__name__)


class ManagementPort(Protocol):
    """The small management surface required by reconciliation."""

    def get_certificate(self, certificate_id: str, *, opc_request_id: str) -> OciCertificate: ...

    def list_versions(
        self, certificate_id: str, *, opc_request_id: str
    ) -> tuple[OciCertificateVersion, ...]: ...

    def get_version(
        self, certificate_id: str, version_number: int, *, opc_request_id: str
    ) -> OciCertificateVersion: ...

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
    ) -> None: ...

    def promote_current(
        self,
        certificate_id: str,
        version_number: int,
        *,
        etag: str | None,
        opc_request_id: str,
    ) -> None: ...


class RetrievalPort(Protocol):
    """The public-only retrieval surface required by reconciliation."""

    def get_public_bundle(
        self,
        certificate_id: str,
        *,
        opc_request_id: str,
        version_number: int | None = None,
    ) -> OciPublicBundle: ...


@dataclass(frozen=True, slots=True)
class PublicationResult:
    """Safe publication result suitable for logs, status and metrics."""

    certificate_id: str
    current_version_number: int
    local_fingerprint: str
    changed: bool


class PublicationReconciler:
    """Reconcile before every mutation; a timeout must be retried by re-entry, not blindly."""

    def __init__(
        self, management: ManagementPort, retrieval: RetrievalPort, state_store: StateStore
    ) -> None:
        self._management = management
        self._retrieval = retrieval
        self._state_store = state_store

    def publish(
        self,
        config: AppConfig,
        certificate: CertificateConfig,
        material: LineageMaterial,
        chain: OciCertificateChain,
        local_fingerprint: str,
        *,
        now: datetime,
        operation_type: OperationType = OperationType.PUBLISH,
    ) -> PublicationResult:
        """Converge one existing OCI certificate to validated local material."""
        certificate_id = certificate.oci.certificate_ocid
        if certificate_id is None:
            raise ReconciliationError("publish requires a configured OCI certificate OCID")
        operation = self._state_store.start_operation(
            certificate.id,
            operation_type,
            local_fingerprint=local_fingerprint,
            oci_certificate_ocid=certificate_id,
        )
        request_id = str(uuid.uuid4())
        remote = self._management.get_certificate(certificate_id, opc_request_id=request_id)
        current_bundle = self._retrieval.get_public_bundle(
            certificate_id, opc_request_id=request_id
        )
        current_fingerprint = self._verify_bundle(current_bundle, certificate, config, now)
        self._state_store.transition(
            operation.operation_id,
            OperationState.OCI_RECONCILED,
            oci_version_number=current_bundle.version_number,
            opc_request_id=request_id,
        )
        if current_fingerprint == local_fingerprint:
            log_event(
                _LOGGER,
                logging.INFO,
                "OCI_VERSION_REUSED",
                certificate_id=certificate.id,
                version_number=current_bundle.version_number,
            )
            return self._complete(
                operation.operation_id,
                certificate,
                local_fingerprint,
                current_fingerprint,
                current_bundle.version_number,
                changed=False,
                operation_type=operation_type,
            )
        candidate = self._find_matching_pending(
            certificate_id, certificate, config, local_fingerprint, now, request_id
        )
        if candidate is None:
            version_label = version_name(now, local_fingerprint)
            self._management.upload_pending_version(
                certificate_id,
                etag=remote.etag,
                version_name_value=version_label,
                certificate_pem=material.leaf_pem,
                cert_chain_pem=chain.cert_chain_pem,
                private_key_pem=material.private_key_pem,
                opc_request_id=request_id,
            )
            self._state_store.transition(
                operation.operation_id,
                OperationState.OCI_PENDING_UPLOADED,
                opc_request_id=request_id,
            )
            log_event(_LOGGER, logging.INFO, "OCI_VERSION_UPLOADED", certificate_id=certificate.id)
            candidate = self._find_matching_pending(
                certificate_id, certificate, config, local_fingerprint, now, request_id
            )
            if candidate is None:
                raise ReconciliationError(
                    "OCI upload outcome is not yet visible; reconcile before retry"
                )
        self._state_store.transition(
            operation.operation_id,
            OperationState.OCI_PENDING_VERIFIED,
            oci_version_number=candidate.version_number,
            opc_request_id=request_id,
        )
        log_event(
            _LOGGER,
            logging.INFO,
            "OCI_PENDING_VERIFIED",
            certificate_id=certificate.id,
            version_number=candidate.version_number,
        )
        self._promote_current(
            config,
            certificate_id,
            candidate.version_number,
            request_id,
        )
        log_event(
            _LOGGER,
            logging.INFO,
            "OCI_PROMOTED",
            certificate_id=certificate.id,
            version_number=candidate.version_number,
        )
        confirmed = retry_read_until_sync(
            lambda: self._retrieval.get_public_bundle(certificate_id, opc_request_id=request_id),
            lambda bundle: bundle.version_number == candidate.version_number,
            ReadRetryPolicy(max_attempts=config.oci.max_read_attempts),
        )
        confirmed_fingerprint = self._verify_bundle(confirmed, certificate, config, now)
        if confirmed_fingerprint != local_fingerprint:
            raise ReconciliationError("OCI CURRENT fingerprint does not match local certificate")
        self._state_store.transition(
            operation.operation_id,
            OperationState.OCI_CURRENT_CONFIRMED,
            oci_version_number=confirmed.version_number,
            opc_request_id=request_id,
        )
        log_event(
            _LOGGER,
            logging.INFO,
            "OCI_CURRENT_CONFIRMED",
            certificate_id=certificate.id,
            version_number=confirmed.version_number,
        )
        return self._complete(
            operation.operation_id,
            certificate,
            local_fingerprint,
            confirmed_fingerprint,
            confirmed.version_number,
            changed=True,
            operation_type=operation_type,
        )

    def _promote_current(
        self,
        config: AppConfig,
        certificate_id: str,
        version_number: int,
        request_id: str,
    ) -> None:
        """Promote after OCI settles, reconciling every ambiguous retry first."""
        policy = ReadRetryPolicy(
            max_attempts=config.oci.mutation_reconciliation_attempts,
            base_delay_seconds=1.0,
            maximum_delay_seconds=15.0,
        )
        for attempt in range(policy.max_attempts):
            refreshed = self._management.get_certificate(certificate_id, opc_request_id=request_id)
            if refreshed.current_version_number == version_number:
                return
            try:
                self._management.promote_current(
                    certificate_id,
                    version_number,
                    etag=refreshed.etag,
                    opc_request_id=request_id,
                )
                return
            except (ServiceError, TimeoutError, OSError) as error:
                retryable = not isinstance(error, ServiceError) or (
                    error.status in (429, 500, 502, 503, 504)
                    or (error.status == 409 and error.code == "IncorrectState")
                )
                if not retryable or attempt + 1 >= policy.max_attempts:
                    raise
                time.sleep(policy.delay(attempt, None))
        raise RuntimeError("OCI promotion retry policy has no attempts")

    def _find_matching_pending(
        self,
        certificate_id: str,
        certificate: CertificateConfig,
        config: AppConfig,
        local_fingerprint: str,
        now: datetime,
        request_id: str,
    ) -> OciCertificateVersion | None:
        for candidate in self._management.list_versions(certificate_id, opc_request_id=request_id):
            if not {"PENDING", "LATEST"}.intersection(candidate.stages):
                continue
            bundle = self._retrieval.get_public_bundle(
                certificate_id, version_number=candidate.version_number, opc_request_id=request_id
            )
            if self._verify_bundle(bundle, certificate, config, now) == local_fingerprint:
                return candidate
        return None

    @staticmethod
    def _verify_bundle(
        bundle: OciPublicBundle,
        certificate: CertificateConfig,
        config: AppConfig,
        now: datetime,
    ) -> str:
        try:
            return validate_public_certificate(
                bundle.certificate_pem, certificate, config.global_, now=now
            )
        except CertificateValidationError as error:
            raise ReconciliationError(
                "OCI public bundle failed local identity validation"
            ) from error

    def _complete(
        self,
        operation_id: str,
        certificate: CertificateConfig,
        local_fingerprint: str,
        remote_fingerprint: str,
        version_number: int,
        *,
        changed: bool,
        operation_type: OperationType,
    ) -> PublicationResult:
        self._state_store.record_publication_success(
            certificate.id,
            local_fingerprint=local_fingerprint,
            current_fingerprint=remote_fingerprint,
            current_version=version_number,
        )
        self._state_store.complete_reconciled_operations(
            certificate.id,
            local_fingerprint=local_fingerprint,
            current_version=version_number,
            excluding_operation_id=operation_id,
        )
        if operation_type is OperationType.RENEW:
            self._state_store.record_renewal_success(certificate.id)
        self._state_store.transition(
            operation_id,
            OperationState.COMPLETED,
            oci_version_number=version_number,
        )
        return PublicationResult(certificate.id, version_number, local_fingerprint, changed)
