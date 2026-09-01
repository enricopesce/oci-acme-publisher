"""Verified rollback to an OCI PREVIOUS certificate version."""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime

from .audit_service import AuditError, AuditService
from .certificate_validator import CertificateValidationError, validate_public_certificate
from .config import AppConfig, CertificateConfig
from .logging_config import log_event
from .oci_certificates import OciCertificateVersion
from .oci_retry import ReadRetryPolicy, retry_read_until_sync
from .reconciler import ManagementPort, RetrievalPort
from .state_store import OperationState, OperationType, StateStore


class RollbackError(RuntimeError):
    """Rollback cannot safely be completed with an eligible prior version."""


_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RollbackResult:
    """The version restored and its confirmed public fingerprint."""

    certificate_id: str
    version_number: int
    fingerprint: str


class RollbackService:
    """Promote only an eligible PREVIOUS version and verify the remote result."""

    def __init__(
        self, management: ManagementPort, retrieval: RetrievalPort, state_store: StateStore
    ) -> None:
        self._management = management
        self._retrieval = retrieval
        self._state_store = state_store

    def rollback(
        self,
        config: AppConfig,
        certificate: CertificateConfig,
        *,
        now: datetime,
        audit: AuditService | None = None,
    ) -> RollbackResult:
        """Restore a valid undeleted PREVIOUS version and confirm it is CURRENT."""
        certificate_ocid = certificate.oci.certificate_ocid
        if certificate_ocid is None:
            raise RollbackError("rollback requires a configured OCI certificate OCID")
        operation = self._state_store.start_operation(
            certificate.id,
            OperationType.ROLLBACK,
            oci_certificate_ocid=certificate_ocid,
        )
        log_event(_LOGGER, logging.INFO, "OCI_ROLLBACK_STARTED", certificate_id=certificate.id)
        request_id = str(uuid.uuid4())
        candidate = self._previous_version(certificate_ocid, request_id)
        bundle = self._retrieval.get_public_bundle(
            certificate_ocid, version_number=candidate.version_number, opc_request_id=request_id
        )
        fingerprint = self._validate_bundle(bundle.certificate_pem, certificate, config, now)
        remote = self._management.get_certificate(certificate_ocid, opc_request_id=request_id)
        self._state_store.transition(
            operation.operation_id,
            OperationState.OCI_RECONCILED,
            oci_version_number=candidate.version_number,
            opc_request_id=request_id,
        )
        self._management.promote_current(
            certificate_ocid,
            candidate.version_number,
            etag=remote.etag,
            opc_request_id=request_id,
        )
        confirmed = retry_read_until_sync(
            lambda: self._retrieval.get_public_bundle(certificate_ocid, opc_request_id=request_id),
            lambda current: current.version_number == candidate.version_number,
            ReadRetryPolicy(max_attempts=config.oci.max_read_attempts),
        )
        confirmed_fingerprint = self._validate_bundle(
            confirmed.certificate_pem, certificate, config, now
        )
        if (
            confirmed.version_number != candidate.version_number
            or confirmed_fingerprint != fingerprint
        ):
            raise RollbackError("OCI rollback promotion was not confirmed")
        self._state_store.transition(
            operation.operation_id,
            OperationState.OCI_CURRENT_CONFIRMED,
            oci_version_number=confirmed.version_number,
            opc_request_id=request_id,
        )
        self._state_store.record_rollback_success(
            certificate.id,
            current_fingerprint=confirmed_fingerprint,
            current_version=confirmed.version_number,
        )
        if audit is not None:
            self._state_store.transition(operation.operation_id, OperationState.AUDIT_PENDING)
            try:
                audit_result = asyncio.run(audit.audit(confirmed_fingerprint))
            except AuditError as error:
                self._state_store.transition(operation.operation_id, OperationState.ROLLBACK_FAILED)
                log_event(
                    _LOGGER, logging.ERROR, "OCI_ROLLBACK_FAILED", certificate_id=certificate.id
                )
                raise RollbackError(
                    "rollback completed but endpoint audit did not converge"
                ) from error
            if not audit_result.successful:
                self._state_store.transition(operation.operation_id, OperationState.ROLLBACK_FAILED)
                log_event(
                    _LOGGER, logging.ERROR, "OCI_ROLLBACK_FAILED", certificate_id=certificate.id
                )
                raise RollbackError("rollback completed but endpoint audit did not converge")
            self._state_store.transition(operation.operation_id, OperationState.AUDIT_SUCCESS)
        self._state_store.transition(
            operation.operation_id,
            OperationState.COMPLETED,
            oci_version_number=confirmed.version_number,
        )
        log_event(
            _LOGGER,
            logging.INFO,
            "OCI_ROLLBACK_SUCCESS",
            certificate_id=certificate.id,
            version_number=confirmed.version_number,
        )
        return RollbackResult(certificate.id, confirmed.version_number, confirmed_fingerprint)

    def _previous_version(self, certificate_ocid: str, request_id: str) -> OciCertificateVersion:
        candidates = tuple(
            version
            for version in self._management.list_versions(
                certificate_ocid, opc_request_id=request_id
            )
            if "PREVIOUS" in version.stages and version.time_of_deletion is None
        )
        if len(candidates) != 1:
            raise RollbackError("OCI does not expose exactly one eligible PREVIOUS version")
        return candidates[0]

    @staticmethod
    def _validate_bundle(
        certificate_pem: str,
        certificate: CertificateConfig,
        config: AppConfig,
        now: datetime,
    ) -> str:
        try:
            return validate_public_certificate(
                certificate_pem, certificate, config.global_, now=now
            )
        except CertificateValidationError as error:
            raise RollbackError("OCI rollback bundle failed local validation") from error
