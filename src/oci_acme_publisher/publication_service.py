"""Orchestration of validated local certificate material into OCI publication."""

from __future__ import annotations

import asyncio
import logging
import math
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .acme_service import AcmeOperationError, NativeAcmeService
from .audit_service import AuditError, AuditService, pinned_root_probe
from .certificate_store import (
    CertificateStoreError,
    LineageMaterial,
    certificate_store,
)
from .certificate_validator import (
    CertificateValidationError,
    validate_certificate_material,
    validate_public_certificate,
)
from .chain_builder import ChainBuildError, build_oci_chain
from .config import AppConfig, CertificateConfig, OciConfig
from .errors import ConfigurationError
from .http01_paths import publisher_uid
from .http01_preflight import Http01Preflight, PreflightError
from .logging_config import log_event
from .metrics import certificate_days_remaining
from .models import AuditMode, Environment
from .notification_service import NotificationError, NotificationService
from .oci_auth import OciAuthenticationError
from .oci_certificates import OciCertificateError, version_name
from .oci_clients import OciCertificatesAdapters, OciExecutor, create_certificates_adapters
from .reconciler import PublicationReconciler, PublicationResult, ReconciliationError
from .retention_service import plan_retention
from .rollback_service import RollbackError, RollbackResult, RollbackService
from .staging_evidence import require_qualified_profile
from .state_store import OperationState, OperationType, StateStore

AdaptersFactory = Callable[[str, OciConfig], OciCertificatesAdapters]
_LOGGER = logging.getLogger(__name__)


class PublicationServiceError(RuntimeError):
    """The requested certificate selection or orchestration operation is invalid."""


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    """A newly created OCI certificate OCID and verified current version."""

    certificate_id: str
    oci_certificate_ocid: str
    current_version_number: int


@dataclass(frozen=True, slots=True)
class RetentionResult:
    """Scheduled deletions after protected versions have been excluded."""

    certificate_id: str
    scheduled_version_numbers: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class RenewalFailure:
    """One isolated renewal failure, kept free of certificate material."""

    certificate_id: str
    error: Exception


@dataclass(frozen=True, slots=True)
class RenewalBatchResult:
    """All independently attempted renewal results for one timer invocation."""

    publications: tuple[PublicationResult, ...]
    failures: tuple[RenewalFailure, ...]


_RENEWABLE_CERTIFICATE_FAILURES = (
    AuditError,
    CertificateValidationError,
    ChainBuildError,
    ConfigurationError,
    OciAuthenticationError,
    OciCertificateError,
    AcmeOperationError,
    CertificateStoreError,
    PreflightError,
    PublicationServiceError,
    ReconciliationError,
    RollbackError,
)


def configured_certificate(config: AppConfig, certificate_id: str) -> CertificateConfig:
    """Return one configured certificate set or fail without defaulting silently."""
    for certificate in config.certificates:
        if certificate.id == certificate_id:
            return certificate
    raise PublicationServiceError("configured certificate id was not found")


def _failure_notification_event(error: Exception) -> str:
    """Map only known safe failure classes to documented notification events."""
    if isinstance(error, PreflightError):
        return "HTTP01_PREFLIGHT_FAILED"
    if isinstance(error, AcmeOperationError):
        return "ACME_FAILED"
    if isinstance(error, CertificateStoreError | CertificateValidationError | ChainBuildError):
        return "LOCAL_CERT_REJECTED"
    if isinstance(error, RollbackError):
        return "OCI_ROLLBACK_FAILED"
    if isinstance(error, AuditError):
        return "AUDIT_FAILED"
    return "OCI_UPLOAD_FAILED"


def _expiry_notification_event(
    config: AppConfig, certificate: CertificateConfig, *, now: datetime
) -> str | None:
    """Classify only an observable public-certificate expiry threshold."""
    days = certificate_days_remaining(config, certificate, now)
    if math.isnan(days):
        return None
    if days <= config.monitoring.critical_days:
        return "CERTIFICATE_EXPIRY_CRITICAL"
    if days <= config.monitoring.warning_days:
        return "CERTIFICATE_EXPIRY_WARNING"
    return None


class PublicationService:
    """Service boundary that keeps PEM/private keys transient and out of persistent state."""

    def __init__(
        self,
        adapters_factory: AdaptersFactory = create_certificates_adapters,
        *,
        expected_owner_uid: int | None = None,
    ) -> None:
        self._adapters_factory = adapters_factory
        self._expected_owner_uid = (
            publisher_uid() if expected_owner_uid is None else expected_owner_uid
        )

    def publish(
        self,
        config: AppConfig,
        certificate_id: str,
        *,
        operation_type: OperationType = OperationType.PUBLISH,
    ) -> PublicationResult:
        """Publish local already-issued material after full local validation."""
        certificate = configured_certificate(config, certificate_id)
        self._require_production_qualification(config, certificate)
        material = self._load_and_validate(config, certificate)
        fingerprint = validate_certificate_material(
            material,
            certificate,
            config.compatibility,
            config.global_,
            now=datetime.now(UTC),
        )
        chain = build_oci_chain(material, certificate, config.compatibility)
        log_event(_LOGGER, logging.INFO, "LOCAL_CERT_VALIDATED", certificate_id=certificate.id)
        adapters = self._adapters_factory(certificate.oci.region, config.oci)
        store = StateStore.open(Path(config.global_.state_dir) / "state.sqlite3")
        executor = OciExecutor()
        try:
            reconciler = PublicationReconciler(adapters.management, adapters.retrieval, store)
            result = asyncio.run(
                executor.run(
                    reconciler.publish,
                    config,
                    certificate,
                    material,
                    chain,
                    fingerprint,
                    now=datetime.now(UTC),
                    operation_type=operation_type,
                )
            )
            log_event(
                _LOGGER,
                logging.INFO,
                "OPERATION_COMPLETED",
                certificate_id=certificate.id,
                operation=operation_type.value.lower(),
                version_number=result.current_version_number,
            )
            self._run_post_publication_audit(config, certificate)
            self._run_post_publication_retention(config, certificate)
            return result
        finally:
            executor.close()
            store.close()

    def renew(
        self, config: AppConfig, certificate_id: str, *, force_acme_renewal: bool = False
    ) -> PublicationResult:
        """Issue natively when due, then reconcile local material into OCI."""
        certificate = configured_certificate(config, certificate_id)
        self._require_production_qualification(config, certificate)
        self._run_preflight(config, certificate)
        local_store = certificate_store(config.acme, self._expected_owner_uid)
        before_fingerprint: str | None = None
        if local_store.exists(certificate):
            before_fingerprint = validate_certificate_material(
                local_store.load(certificate),
                certificate,
                config.compatibility,
                config.global_,
                now=datetime.now(UTC),
            )
        log_event(_LOGGER, logging.INFO, "ACME_STARTED", certificate_id=certificate.id)
        NativeAcmeService(local_store).issue(config, certificate, force=force_acme_renewal)
        log_event(_LOGGER, logging.INFO, "ACME_COMPLETED", certificate_id=certificate.id)
        publication = self.publish(config, certificate_id, operation_type=OperationType.RENEW)
        if before_fingerprint == publication.local_fingerprint:
            return PublicationResult(
                publication.certificate_id,
                publication.current_version_number,
                publication.local_fingerprint,
                publication.changed,
            )
        return publication

    def renew_all(self, config: AppConfig) -> RenewalBatchResult:
        """Attempt every set sequentially, preserving failures without skipping later sets."""
        publications: list[PublicationResult] = []
        failures: list[RenewalFailure] = []
        for certificate in config.certificates:
            if not config.compatibility.live_verified:
                self._notify_event(config, certificate.id, "COMPATIBILITY_NOT_VERIFIED")
            try:
                if certificate.oci.certificate_ocid is None:
                    store = StateStore.open(Path(config.global_.state_dir) / "state.sqlite3")
                    try:
                        recovered_ocid = store.confirmed_oci_certificate_ocid(certificate.id)
                    finally:
                        store.close()
                    if recovered_ocid is None:
                        bootstrap = self.bootstrap(config, certificate.id)
                        publication = PublicationResult(
                            bootstrap.certificate_id,
                            bootstrap.current_version_number,
                            "initial-publication",
                            True,
                        )
                    else:
                        recovered_certificate = certificate.model_copy(
                            update={
                                "oci": certificate.oci.model_copy(
                                    update={"certificate_ocid": recovered_ocid}
                                )
                            }
                        )
                        recovered_config = config.model_copy(
                            update={
                                "certificates": tuple(
                                    recovered_certificate if item.id == certificate.id else item
                                    for item in config.certificates
                                )
                            }
                        )
                        publication = self.renew(recovered_config, certificate.id)
                else:
                    publication = self.renew(config, certificate.id)
                publications.append(publication)
                expiry_event = _expiry_notification_event(
                    config, certificate, now=datetime.now(UTC)
                )
                if expiry_event is not None:
                    self._notify_event(config, certificate.id, expiry_event)
            except _RENEWABLE_CERTIFICATE_FAILURES as error:
                failures.append(RenewalFailure(certificate.id, error))
                self._notify_renewal_failure(config, certificate.id, error)
        return RenewalBatchResult(tuple(publications), tuple(failures))

    def audit(self, config: AppConfig, certificate_id: str) -> bool:
        """Audit public endpoints against the OCI CURRENT public bundle fingerprint."""
        certificate = configured_certificate(config, certificate_id)
        if certificate.oci.certificate_ocid is None:
            raise PublicationServiceError("audit requires a configured OCI certificate OCID")
        adapters = self._adapters_factory(certificate.oci.region, config.oci)
        store = StateStore.open(Path(config.global_.state_dir) / "state.sqlite3")
        operation = store.start_operation(
            certificate.id,
            OperationType.AUDIT,
            oci_certificate_ocid=certificate.oci.certificate_ocid,
        )
        request_id = str(uuid.uuid4())
        store.transition(
            operation.operation_id,
            OperationState.AUDIT_PENDING,
            opc_request_id=request_id,
        )
        executor = OciExecutor()
        try:
            bundle = asyncio.run(
                executor.run(
                    adapters.retrieval.get_public_bundle,
                    certificate.oci.certificate_ocid,
                    opc_request_id=request_id,
                )
            )
            expected = validate_public_certificate(
                bundle.certificate_pem, certificate, config.global_, now=datetime.now(UTC)
            )
            result = asyncio.run(self._audit_service(config, certificate).audit(expected))
            if not result.successful:
                store.transition(
                    operation.operation_id,
                    OperationState.AUDIT_FAILED,
                    error_code="AUDIT_FAILED",
                )
                self._notify_audit_failure(config, certificate.id, store)
                log_event(_LOGGER, logging.ERROR, "AUDIT_FAILED", certificate_id=certificate.id)
                return False
            store.transition(operation.operation_id, OperationState.AUDIT_SUCCESS)
            store.record_audit_success(certificate.id)
            store.transition(operation.operation_id, OperationState.COMPLETED)
            store.complete_interrupted_audits(
                certificate.id, excluding_operation_id=operation.operation_id
            )
            log_event(_LOGGER, logging.INFO, "AUDIT_SUCCESS", certificate_id=certificate.id)
            return True
        except AuditError:
            store.transition(
                operation.operation_id,
                OperationState.AUDIT_FAILED,
                error_code="AUDIT_FAILED",
            )
            self._notify_audit_failure(config, certificate.id, store)
            log_event(_LOGGER, logging.ERROR, "AUDIT_FAILED", certificate_id=certificate.id)
            raise
        finally:
            executor.close()
            store.close()

    @staticmethod
    def _notify_audit_failure(config: AppConfig, certificate_id: str, store: StateStore) -> None:
        """Best-effort alerting must not turn an observe-mode audit into a new failure."""
        try:
            asyncio.run(
                NotificationService(config.notifications).notify(
                    "AUDIT_FAILED",
                    {"certificate_id": certificate_id, "status": "AUDIT_FAILED"},
                    deduplicator=store,
                )
            )
        except NotificationError:
            return

    @staticmethod
    def _notify_renewal_failure(config: AppConfig, certificate_id: str, error: Exception) -> None:
        """Best-effort, deduplicated failure notification that cannot stop later sets."""
        PublicationService._notify_event(config, certificate_id, _failure_notification_event(error))

    @staticmethod
    def _notify_event(config: AppConfig, certificate_id: str, event: str) -> None:
        """Deliver one safe event with durable cooldown; notification failure is non-blocking."""
        try:
            store = StateStore.open(Path(config.global_.state_dir) / "state.sqlite3")
        except (OSError, sqlite3.Error):
            return
        try:
            try:
                asyncio.run(
                    NotificationService(config.notifications).notify(
                        event,
                        {"certificate_id": certificate_id, "status": event},
                        deduplicator=store,
                    )
                )
            except NotificationError:
                return
        finally:
            store.close()

    def rollback(self, config: AppConfig, certificate_id: str) -> RollbackResult:
        """Restore one eligible OCI PREVIOUS version under the shared publisher lock."""
        certificate = configured_certificate(config, certificate_id)
        adapters = self._adapters_factory(certificate.oci.region, config.oci)
        store = StateStore.open(Path(config.global_.state_dir) / "state.sqlite3")
        executor = OciExecutor()
        try:
            service = RollbackService(adapters.management, adapters.retrieval, store)
            return asyncio.run(
                executor.run(
                    service.rollback,
                    config,
                    certificate,
                    now=datetime.now(UTC),
                    audit=self._audit_service(config, certificate),
                )
            )
        finally:
            executor.close()
            store.close()

    def retention(self, config: AppConfig, certificate_id: str) -> RetentionResult:
        """Schedule deletion only for safe deprecated versions."""
        certificate = configured_certificate(config, certificate_id)
        certificate_ocid = certificate.oci.certificate_ocid
        if certificate_ocid is None:
            raise PublicationServiceError("retention requires a configured OCI certificate OCID")
        adapters = self._adapters_factory(certificate.oci.region, config.oci)
        store = StateStore.open(Path(config.global_.state_dir) / "state.sqlite3")
        executor = OciExecutor()
        try:
            request_id = str(uuid.uuid4())
            versions = asyncio.run(
                executor.run(
                    adapters.management.list_versions,
                    certificate_ocid,
                    opc_request_id=request_id,
                )
            )
            referenced_versions = frozenset(
                operation.oci_version_number
                for operation in store.active_operations(certificate.id)
                if operation.oci_version_number is not None
            )
            plan = plan_retention(
                certificate.retention,
                versions,
                referenced_versions=referenced_versions,
                now=datetime.now(UTC),
            )
            for version_number in plan.version_numbers:
                request_id = str(uuid.uuid4())
                # Scheduling changes the parent certificate's ETag.  Read it immediately
                # before every mutation rather than reusing a stale token in this loop.
                version = asyncio.run(
                    executor.run(
                        adapters.management.get_version,
                        certificate_ocid,
                        version_number,
                        opc_request_id=request_id,
                    )
                )
                if version.etag is None:
                    raise OciCertificateError("OCI version deletion requires a version ETag")
                asyncio.run(
                    executor.run(
                        adapters.management.schedule_version_deletion,
                        certificate_ocid,
                        version_number,
                        time_of_deletion=plan.deletion_time,
                        etag=version.etag,
                        opc_request_id=request_id,
                    )
                )
                log_event(
                    _LOGGER,
                    logging.INFO,
                    "RETENTION_SCHEDULED",
                    certificate_id=certificate.id,
                    version_number=version_number,
                )
        finally:
            executor.close()
            store.close()
        return RetentionResult(certificate.id, plan.version_numbers)

    def _enforce_post_publication_audit(
        self, config: AppConfig, certificate: CertificateConfig
    ) -> None:
        """Audit publication in enforce mode and roll back only under explicit policy."""
        if certificate.audit.mode is not AuditMode.ENFORCE:
            return
        try:
            successful = self.audit(config, certificate.id)
        except AuditError:
            successful = False
        if successful:
            return
        if not certificate.audit.automatic_rollback_on_failure:
            raise AuditError("TLS audit failed after OCI publication")
        try:
            self.rollback(config, certificate.id)
        except RollbackError:
            log_event(_LOGGER, logging.ERROR, "OCI_ROLLBACK_FAILED", certificate_id=certificate.id)
            raise

    def _run_post_publication_audit(
        self, config: AppConfig, certificate: CertificateConfig
    ) -> None:
        """Run configured TLS observation; only enforce mode can block publication."""
        if certificate.audit.mode is AuditMode.DISABLED:
            return
        if certificate.audit.mode is AuditMode.ENFORCE:
            self._enforce_post_publication_audit(config, certificate)
            return
        try:
            self.audit(config, certificate.id)
        except AuditError:
            # Observe mode records/notifies the failed audit but retains OCI CURRENT.
            return

    def _run_post_publication_retention(
        self, config: AppConfig, certificate: CertificateConfig
    ) -> None:
        """Apply safe retention after publication; its failure never invalidates CURRENT."""
        if not certificate.retention.enabled:
            return
        try:
            result = self.retention(config, certificate.id)
        except (
            OciAuthenticationError,
            OciCertificateError,
            OSError,
            PublicationServiceError,
            sqlite3.Error,
        ):
            log_event(_LOGGER, logging.ERROR, "RETENTION_FAILED", certificate_id=certificate.id)
            self._notify_event(config, certificate.id, "RETENTION_FAILED")
            return
        if not result.scheduled_version_numbers:
            log_event(_LOGGER, logging.INFO, "RETENTION_SKIPPED", certificate_id=certificate.id)

    def bootstrap(self, config: AppConfig, certificate_id: str) -> BootstrapResult:
        """Issue the initial lineage then create and verify one imported OCI certificate."""
        certificate = configured_certificate(config, certificate_id)
        if certificate.oci.certificate_ocid is not None:
            raise PublicationServiceError("bootstrap requires certificate_ocid to be absent")
        self._require_production_qualification(config, certificate)
        self._run_preflight(config, certificate)
        local_store = certificate_store(config.acme, self._expected_owner_uid)
        log_event(_LOGGER, logging.INFO, "ACME_STARTED", certificate_id=certificate.id)
        NativeAcmeService(local_store).issue(config, certificate)
        log_event(_LOGGER, logging.INFO, "ACME_COMPLETED", certificate_id=certificate.id)
        material = self._load_and_validate(config, certificate)
        fingerprint = validate_certificate_material(
            material,
            certificate,
            config.compatibility,
            config.global_,
            now=datetime.now(UTC),
        )
        chain = build_oci_chain(material, certificate, config.compatibility)
        adapters = self._adapters_factory(certificate.oci.region, config.oci)
        store = StateStore.open(Path(config.global_.state_dir) / "state.sqlite3")
        try:
            recovered = self._recover_bootstrap(
                config,
                certificate,
                fingerprint,
                adapters,
                store,
            )
        except (CertificateValidationError, OciCertificateError, PublicationServiceError):
            store.close()
            raise
        if recovered is not None:
            store.close()
            return recovered
        operation = store.start_operation(
            certificate.id,
            OperationType.BOOTSTRAP,
            local_fingerprint=fingerprint,
        )
        store.transition(operation.operation_id, OperationState.LOCAL_CERT_VALIDATED)
        executor = OciExecutor()
        created = False
        try:
            request_id = str(uuid.uuid4())
            ocid = asyncio.run(
                executor.run(
                    adapters.management.create_imported_certificate,
                    compartment_id=certificate.oci.compartment_ocid,
                    certificate_name=certificate.oci.certificate_name,
                    version_name_value=version_name(datetime.now(UTC), fingerprint),
                    certificate_pem=material.leaf_pem,
                    cert_chain_pem=chain.cert_chain_pem,
                    private_key_pem=material.private_key_pem,
                    opc_request_id=request_id,
                )
            )
            created = True
            store.transition(
                operation.operation_id,
                OperationState.OCI_RECONCILED,
                oci_certificate_ocid=ocid,
                opc_request_id=request_id,
            )
            bundle = asyncio.run(
                executor.run(
                    adapters.retrieval.get_public_bundle,
                    ocid,
                    opc_request_id=request_id,
                )
            )
            remote_fingerprint = validate_public_certificate(
                bundle.certificate_pem, certificate, config.global_, now=datetime.now(UTC)
            )
            if remote_fingerprint != fingerprint:
                raise PublicationServiceError(
                    "initial OCI certificate current version does not match local material"
                )
            store.transition(
                operation.operation_id,
                OperationState.OCI_CURRENT_CONFIRMED,
                oci_version_number=bundle.version_number,
            )
            store.record_publication_success(
                certificate.id,
                local_fingerprint=fingerprint,
                current_fingerprint=remote_fingerprint,
                current_version=bundle.version_number,
            )
            store.transition(operation.operation_id, OperationState.COMPLETED)
            return BootstrapResult(certificate.id, ocid, bundle.version_number)
        except OciCertificateError:
            store.transition(
                operation.operation_id,
                OperationState.OCI_VERSION_FAILED if created else OperationState.OCI_UPLOAD_FAILED,
            )
            raise
        except (CertificateValidationError, PublicationServiceError):
            store.transition(operation.operation_id, OperationState.OCI_VERSION_FAILED)
            raise
        finally:
            executor.close()
            store.close()

    @staticmethod
    def _recover_bootstrap(
        config: AppConfig,
        certificate: CertificateConfig,
        fingerprint: str,
        adapters: OciCertificatesAdapters,
        store: StateStore,
    ) -> BootstrapResult | None:
        """Finish a post-create bootstrap crash without creating a second OCI OCID."""
        candidates = tuple(
            operation
            for operation in store.active_operations(certificate.id)
            if operation.operation_type is OperationType.BOOTSTRAP
            and operation.local_fingerprint == fingerprint
            and operation.oci_certificate_ocid is not None
        )
        if not candidates:
            return None
        if len(candidates) != 1:
            raise PublicationServiceError("bootstrap recovery has ambiguous OCI certificate state")
        operation = candidates[0]
        ocid = operation.oci_certificate_ocid
        if ocid is None:  # Kept for type narrowing; the candidate predicate proves this already.
            raise PublicationServiceError("bootstrap recovery lacks OCI certificate state")
        request_id = str(uuid.uuid4())
        executor = OciExecutor()
        try:
            bundle = asyncio.run(
                executor.run(
                    adapters.retrieval.get_public_bundle,
                    ocid,
                    opc_request_id=request_id,
                )
            )
            remote_fingerprint = validate_public_certificate(
                bundle.certificate_pem, certificate, config.global_, now=datetime.now(UTC)
            )
            if remote_fingerprint != fingerprint:
                raise PublicationServiceError(
                    "bootstrap recovery OCI certificate does not match local material"
                )
            store.transition(
                operation.operation_id,
                OperationState.OCI_CURRENT_CONFIRMED,
                oci_version_number=bundle.version_number,
                opc_request_id=request_id,
            )
            store.record_publication_success(
                certificate.id,
                local_fingerprint=fingerprint,
                current_fingerprint=remote_fingerprint,
                current_version=bundle.version_number,
            )
            store.transition(operation.operation_id, OperationState.COMPLETED)
            log_event(
                _LOGGER,
                logging.INFO,
                "OPERATION_COMPLETED",
                certificate_id=certificate.id,
                operation="bootstrap-recovery",
                version_number=bundle.version_number,
            )
            return BootstrapResult(certificate.id, ocid, bundle.version_number)
        finally:
            executor.close()

    @staticmethod
    def _run_preflight(config: AppConfig, certificate: CertificateConfig) -> None:
        log_event(_LOGGER, logging.INFO, "HTTP01_PREFLIGHT_STARTED", certificate_id=certificate.id)
        try:
            asyncio.run(Http01Preflight(config.http01).run(certificate))
        except PreflightError:
            log_event(
                _LOGGER, logging.ERROR, "HTTP01_PREFLIGHT_FAILED", certificate_id=certificate.id
            )
            raise
        log_event(_LOGGER, logging.INFO, "HTTP01_PREFLIGHT_SUCCESS", certificate_id=certificate.id)

    @staticmethod
    def _require_production_qualification(
        config: AppConfig, certificate: CertificateConfig
    ) -> None:
        """Block every production certificate mutation until Gate 0 evidence matches."""
        if config.global_.environment is Environment.PRODUCTION:
            require_qualified_profile(config, certificate)

    def _load_and_validate(
        self, config: AppConfig, certificate: CertificateConfig
    ) -> LineageMaterial:
        return certificate_store(config.acme, self._expected_owner_uid).load(certificate)

    @staticmethod
    def _audit_service(config: AppConfig, certificate: CertificateConfig) -> AuditService:
        """Use a pinned staging root while production uses normal system trust."""
        probe = (
            pinned_root_probe(certificate.chain.root_pem_path)
            if config.global_.environment is Environment.STAGING
            else None
        )
        if probe is not None:
            return AuditService(certificate.audit, probe=probe)
        return AuditService(certificate.audit)
