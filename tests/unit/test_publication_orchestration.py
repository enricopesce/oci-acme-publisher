"""Isolated orchestration tests: no network, subprocess or real OCI SDK calls."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from oci_acme_publisher import publication_service
from oci_acme_publisher.acme_service import AcmeOperationError
from oci_acme_publisher.audit_service import AuditError
from oci_acme_publisher.compatibility_probe import LiveCompatibilityProbeResult
from oci_acme_publisher.config import load_config
from oci_acme_publisher.oci_certificates import OciPublicBundle
from oci_acme_publisher.publication_service import PublicationService
from oci_acme_publisher.reconciler import PublicationResult
from oci_acme_publisher.staging_evidence import write_evidence
from oci_acme_publisher.state_store import OperationState, OperationType, StateStore

from .test_certificate_validator import material_with_root


class _Executor:
    async def run(self, function: object, *arguments: object, **keywords: object) -> object:
        return function(*arguments, **keywords)  # type: ignore[operator]

    def close(self) -> None:
        return None


class _Store:
    closed = False

    def __init__(self) -> None:
        self.transitions: list[object] = []
        self.audit_successes: list[str] = []
        self.interrupted_audits_closed: list[tuple[str, str]] = []

    def close(self) -> None:
        self.closed = True

    def active_operations(self, _: str) -> tuple[object, ...]:
        return ()

    def start_operation(self, *_: object, **__: object) -> object:
        return SimpleNamespace(operation_id="operation")

    def transition(self, *arguments: object, **_: object) -> None:
        self.transitions.append(arguments[1])

    def record_audit_success(self, certificate_id: str) -> None:
        self.audit_successes.append(certificate_id)

    def complete_interrupted_audits(
        self, certificate_id: str, *, excluding_operation_id: str
    ) -> int:
        self.interrupted_audits_closed.append((certificate_id, excluding_operation_id))
        return 0


@pytest.fixture
def config(tmp_path_factory: pytest.TempPathFactory) -> object:
    base = load_config("config/config.example.yaml")
    state_directory = tmp_path_factory.mktemp("state")
    global_config = base.global_.model_copy(update={"state_dir": str(state_directory)})
    evidence = state_directory / "gate0.json"
    write_evidence(
        str(evidence),
        base.certificates[0],
        LiveCompatibilityProbeResult(
            certificate_id="main-site",
            oci_certificate_ocid="ocid1.certificate.oc1..test",
            initial_version_number=1,
            promoted_version_number=2,
            rollback_version_number=1,
            leaf_fingerprint="a" * 64,
            root_fingerprint="b" * 64,
            chain_bytes=100,
            documented_subject_country_enforced=True,
        ),
    )
    compatibility = base.compatibility.model_copy(
        update={"live_verified": True, "live_evidence_paths": (str(evidence),)}
    )
    return base.model_copy(update={"global_": global_config, "compatibility": compatibility})


def test_publish_loads_validates_builds_and_reconciles(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    material, root = material_with_root()
    events: list[str] = []
    store = _Store()
    result = PublicationResult("main-site", 4, "fingerprint", True)

    class Reconciler:
        def __init__(self, *_: object) -> None:
            events.append("reconciler")

        def publish(self, *_: object, **keywords: object) -> PublicationResult:
            assert keywords["operation_type"] is OperationType.PUBLISH
            events.append("publish")
            return result

    service = PublicationService(
        adapters_factory=lambda *_: SimpleNamespace(management=object(), retrieval=object()),
        expected_owner_uid=0,
    )
    monkeypatch.setattr(service, "_load_and_validate", lambda *_: material)
    monkeypatch.setattr(
        publication_service,
        "validate_certificate_material",
        lambda *_args, **_kw: "a" * 64,
    )
    monkeypatch.setattr(
        publication_service,
        "build_oci_chain",
        lambda *_: SimpleNamespace(cert_chain_pem=material.chain_pem, root=root),
    )
    monkeypatch.setattr(publication_service, "StateStore", SimpleNamespace(open=lambda _: store))
    monkeypatch.setattr(publication_service, "OciExecutor", _Executor)
    monkeypatch.setattr(publication_service, "PublicationReconciler", Reconciler)
    monkeypatch.setattr(service, "_run_post_publication_audit", lambda *_: events.append("audit"))
    monkeypatch.setattr(
        service, "_run_post_publication_retention", lambda *_: events.append("retention")
    )

    assert service.publish(config, "main-site") is result  # type: ignore[arg-type]
    assert events == ["reconciler", "publish", "audit", "retention"]
    assert store.closed is True


def test_renew_runs_preflight_native_acme_then_publish(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    material, _ = material_with_root()
    events: list[str] = []
    publication = PublicationResult("main-site", 5, "after", True)
    service = PublicationService(expected_owner_uid=0)
    monkeypatch.setattr(service, "_run_preflight", lambda *_: events.append("preflight"))
    local_store = SimpleNamespace(exists=lambda _: True, load=lambda _: material)
    monkeypatch.setattr(publication_service, "certificate_store", lambda *_: local_store)
    monkeypatch.setattr(
        publication_service,
        "validate_certificate_material",
        lambda *_args, **_kw: "before",
    )
    monkeypatch.setattr(
        publication_service.NativeAcmeService,
        "issue",
        lambda *_args, **_kwargs: material,
    )
    monkeypatch.setattr(service, "publish", lambda *_args, **_kw: publication)

    assert service.renew(config, "main-site") is publication  # type: ignore[arg-type]
    assert events == ["preflight"]


def test_renew_rejects_failed_native_acme_before_publication(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    service = PublicationService(expected_owner_uid=0)
    monkeypatch.setattr(service, "_run_preflight", lambda *_: None)
    material, _ = material_with_root()
    local_store = SimpleNamespace(exists=lambda _: True, load=lambda _: material)
    monkeypatch.setattr(publication_service, "certificate_store", lambda *_: local_store)
    monkeypatch.setattr(
        publication_service,
        "validate_certificate_material",
        lambda *_args, **_kw: "before",
    )
    monkeypatch.setattr(
        publication_service.NativeAcmeService,
        "issue",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AcmeOperationError("failed")),
    )
    with pytest.raises(AcmeOperationError):
        service.renew(config, "main-site")  # type: ignore[arg-type]


def test_renew_all_continues_after_an_isolated_certificate_failure(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    service = PublicationService(expected_owner_uid=0)
    calls: list[str] = []

    def renew(_: object, certificate_id: str) -> PublicationResult:
        calls.append(certificate_id)
        if certificate_id == "first":
            raise AcmeOperationError("failed")
        return PublicationResult(certificate_id, 7, "fingerprint", True)

    first = config.certificates[0].model_copy(update={"id": "first"})  # type: ignore[attr-defined]
    second = config.certificates[0].model_copy(update={"id": "second"})  # type: ignore[attr-defined]
    two_certificates = config.model_copy(update={"certificates": (first, second)})  # type: ignore[attr-defined]
    monkeypatch.setattr(service, "renew", renew)

    result = service.renew_all(two_certificates)

    assert calls == ["first", "second"]
    assert [publication.certificate_id for publication in result.publications] == ["second"]
    assert [failure.certificate_id for failure in result.failures] == ["first"]


def test_renew_all_notifies_when_live_compatibility_is_not_attested(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    service = PublicationService(expected_owner_uid=0)
    notifications: list[tuple[str, str]] = []
    monkeypatch.setattr(
        service,
        "renew",
        lambda _config, certificate_id: PublicationResult(certificate_id, 3, "fingerprint", False),
    )
    monkeypatch.setattr(
        service,
        "_notify_event",
        lambda _config, certificate_id, event: notifications.append((certificate_id, event)),
    )

    unqualified = config.model_copy(  # type: ignore[attr-defined]
        update={
            "compatibility": config.compatibility.model_copy(
                update={"live_verified": False, "live_evidence_paths": ()}
            )
        }
    )
    result = service.renew_all(unqualified)  # type: ignore[arg-type]

    assert [publication.certificate_id for publication in result.publications] == ["main-site"]
    assert notifications == [("main-site", "COMPATIBILITY_NOT_VERIFIED")]


def test_renew_all_notifies_each_isolated_failure_without_stopping_later_sets(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    service = PublicationService(expected_owner_uid=0)
    notifications: list[tuple[str, str, Exception]] = []

    def renew(_: object, certificate_id: str) -> PublicationResult:
        if certificate_id == "first":
            raise AcmeOperationError("internal-only diagnostic")
        return PublicationResult(certificate_id, 7, "fingerprint", True)

    def notify(_: object, certificate_id: str, error: Exception) -> None:
        notifications.append(("notification", certificate_id, error))

    first = config.certificates[0].model_copy(update={"id": "first"})  # type: ignore[attr-defined]
    second = config.certificates[0].model_copy(update={"id": "second"})  # type: ignore[attr-defined]
    two_certificates = config.model_copy(update={"certificates": (first, second)})  # type: ignore[attr-defined]
    monkeypatch.setattr(service, "renew", renew)
    monkeypatch.setattr(service, "_notify_renewal_failure", notify)

    result = service.renew_all(two_certificates)

    assert [publication.certificate_id for publication in result.publications] == ["second"]
    assert notifications == [("notification", "first", result.failures[0].error)]


@pytest.mark.parametrize(
    ("days", "event"),
    ((7, "CERTIFICATE_EXPIRY_CRITICAL"), (20, "CERTIFICATE_EXPIRY_WARNING")),
)
def test_renew_all_notifies_expiring_public_certificate(
    monkeypatch: pytest.MonkeyPatch, config: object, days: int, event: str
) -> None:
    service = PublicationService(expected_owner_uid=0)
    notifications: list[tuple[str, str]] = []
    monkeypatch.setattr(
        service,
        "renew",
        lambda *_: PublicationResult("main-site", 7, "fingerprint", True),
    )
    monkeypatch.setattr(publication_service, "certificate_days_remaining", lambda *_: days)
    monkeypatch.setattr(
        service,
        "_notify_event",
        lambda _config, certificate_id, received_event: notifications.append(
            (certificate_id, received_event)
        ),
    )

    unqualified = config.model_copy(  # type: ignore[attr-defined]
        update={
            "compatibility": config.compatibility.model_copy(
                update={"live_verified": False, "live_evidence_paths": ()}
            )
        }
    )
    result = service.renew_all(unqualified)  # type: ignore[arg-type]

    assert result.failures == ()
    assert notifications == [
        ("main-site", "COMPATIBILITY_NOT_VERIFIED"),
        ("main-site", event),
    ]


@pytest.mark.parametrize(
    ("error", "event"),
    (
        (publication_service.PreflightError("failed"), "HTTP01_PREFLIGHT_FAILED"),
        (AcmeOperationError("failed"), "ACME_FAILED"),
        (publication_service.CertificateStoreError("failed"), "LOCAL_CERT_REJECTED"),
        (AuditError("failed"), "AUDIT_FAILED"),
        (publication_service.RollbackError("failed"), "OCI_ROLLBACK_FAILED"),
        (publication_service.OciCertificateError("failed"), "OCI_UPLOAD_FAILED"),
    ),
)
def test_renewal_failure_event_mapping_is_safe_and_stable(error: Exception, event: str) -> None:
    assert publication_service._failure_notification_event(error) == event


def test_renewal_failure_notification_is_best_effort_and_redacted(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    delivered: list[tuple[str, dict[str, str]]] = []
    store = _Store()

    class Notifier:
        def __init__(self, _: object) -> None:
            pass

        async def notify(self, event: str, fields: dict[str, str], **_: object) -> bool:
            delivered.append((event, fields))
            return True

    monkeypatch.setattr(publication_service, "StateStore", SimpleNamespace(open=lambda _: store))
    monkeypatch.setattr(publication_service, "NotificationService", Notifier)

    PublicationService._notify_renewal_failure(
        config,
        "main-site",
        AcmeOperationError("private internal detail"),  # type: ignore[arg-type]
    )

    assert delivered == [("ACME_FAILED", {"certificate_id": "main-site", "status": "ACME_FAILED"})]
    assert store.closed is True


def test_renewal_failure_notification_error_is_non_blocking(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    store = _Store()

    class FailingNotifier:
        def __init__(self, _: object) -> None:
            pass

        async def notify(self, *_: object, **__: object) -> bool:
            raise publication_service.NotificationError("delivery failed")

    monkeypatch.setattr(publication_service, "StateStore", SimpleNamespace(open=lambda _: store))
    monkeypatch.setattr(publication_service, "NotificationService", FailingNotifier)

    PublicationService._notify_renewal_failure(
        config,
        "main-site",
        AcmeOperationError("private internal detail"),  # type: ignore[arg-type]
    )

    assert store.closed is True


@pytest.mark.parametrize(
    "error",
    (publication_service.AuditError("audit"), publication_service.RollbackError("rollback")),
)
def test_renew_all_isolates_audit_and_rollback_failures(
    monkeypatch: pytest.MonkeyPatch, config: object, error: Exception
) -> None:
    service = PublicationService(expected_owner_uid=0)
    calls: list[str] = []

    def renew(_: object, certificate_id: str) -> PublicationResult:
        calls.append(certificate_id)
        if certificate_id == "first":
            raise error
        return PublicationResult(certificate_id, 7, "fingerprint", True)

    first = config.certificates[0].model_copy(update={"id": "first"})  # type: ignore[attr-defined]
    second = config.certificates[0].model_copy(update={"id": "second"})  # type: ignore[attr-defined]
    two_certificates = config.model_copy(update={"certificates": (first, second)})  # type: ignore[attr-defined]
    monkeypatch.setattr(service, "renew", renew)

    result = service.renew_all(two_certificates)

    assert calls == ["first", "second"]
    assert [publication.certificate_id for publication in result.publications] == ["second"]
    assert [failure.error for failure in result.failures] == [error]


def test_audit_fetches_public_bundle_then_compares_endpoint_fingerprint(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    events: list[str] = []
    request_ids: list[str] = []

    class Audit:
        def __init__(self, _: object) -> None:
            pass

        async def audit(self, fingerprint: str) -> object:
            events.append(fingerprint)
            return SimpleNamespace(successful=True)

    adapters = SimpleNamespace(
        retrieval=SimpleNamespace(
            get_public_bundle=lambda *_args, **kw: (
                request_ids.append(kw["opc_request_id"])
                or OciPublicBundle("leaf", "chain", 3, "v3", ())
            )
        )
    )
    store = _Store()
    service = PublicationService(adapters_factory=lambda *_: adapters, expected_owner_uid=0)
    monkeypatch.setattr(publication_service, "OciExecutor", _Executor)
    monkeypatch.setattr(publication_service, "StateStore", SimpleNamespace(open=lambda _: store))
    monkeypatch.setattr(
        publication_service,
        "validate_public_certificate",
        lambda *_args, **_kw: "a" * 64,
    )
    monkeypatch.setattr(publication_service, "AuditService", Audit)

    assert service.audit(config, "main-site") is True  # type: ignore[arg-type]
    assert events == ["a" * 64]
    assert len(request_ids) == 1
    assert str(UUID(request_ids[0])) == request_ids[0]
    assert store.audit_successes == ["main-site"]
    assert store.interrupted_audits_closed == [("main-site", "operation")]
    assert store.closed is True


def test_audit_records_failure_and_notifies_without_exposing_certificate_data(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    notifications: list[dict[str, str]] = []
    store = _Store()
    adapters = SimpleNamespace(
        retrieval=SimpleNamespace(
            get_public_bundle=lambda *_args, **_kw: OciPublicBundle("leaf", "chain", 3, "v3", ())
        )
    )

    class Audit:
        def __init__(self, _: object) -> None:
            pass

        async def audit(self, _: str) -> object:
            return SimpleNamespace(successful=False)

    class Notifier:
        def __init__(self, _: object) -> None:
            pass

        async def notify(self, _: str, fields: dict[str, str], **__: object) -> bool:
            notifications.append(fields)
            return True

    service = PublicationService(adapters_factory=lambda *_: adapters, expected_owner_uid=0)
    monkeypatch.setattr(publication_service, "OciExecutor", _Executor)
    monkeypatch.setattr(publication_service, "StateStore", SimpleNamespace(open=lambda _: store))
    monkeypatch.setattr(publication_service, "AuditService", Audit)
    monkeypatch.setattr(publication_service, "NotificationService", Notifier)
    monkeypatch.setattr(
        publication_service,
        "validate_public_certificate",
        lambda *_args, **_kw: "a" * 64,
    )

    assert service.audit(config, "main-site") is False  # type: ignore[arg-type]
    assert notifications == [{"certificate_id": "main-site", "status": "AUDIT_FAILED"}]
    assert store.closed is True


def test_retention_schedules_only_versions_in_calculated_plan(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    scheduled: list[tuple[int, str | None, str]] = []
    retained_references: list[frozenset[int]] = []
    etags = iter(("version-etag-2", "version-etag-3"))
    store = _Store()
    store.active_operations = lambda _: (  # type: ignore[method-assign]
        SimpleNamespace(oci_version_number=8),
        SimpleNamespace(oci_version_number=None),
    )
    management = SimpleNamespace(
        list_versions=lambda *_args, **_kw: (),
        get_version=lambda *_args, **_kw: SimpleNamespace(etag=next(etags)),
        schedule_version_deletion=lambda _ocid, version, **kw: scheduled.append(
            (version, kw["etag"], kw["opc_request_id"])
        ),
    )
    service = PublicationService(
        adapters_factory=lambda *_: SimpleNamespace(management=management, retrieval=object()),
        expected_owner_uid=0,
    )
    monkeypatch.setattr(publication_service, "OciExecutor", _Executor)
    monkeypatch.setattr(publication_service, "StateStore", SimpleNamespace(open=lambda _: store))
    monkeypatch.setattr(
        publication_service,
        "plan_retention",
        lambda *_args, **keywords: (
            retained_references.append(keywords["referenced_versions"])
            or SimpleNamespace(version_numbers=(2, 3), deletion_time="later")
        ),
    )

    result = service.retention(config, "main-site")  # type: ignore[arg-type]
    assert result.scheduled_version_numbers == (2, 3)
    assert [(version, etag) for version, etag, _ in scheduled] == [
        (2, "version-etag-2"),
        (3, "version-etag-3"),
    ]
    assert all(str(UUID(request_id)) == request_id for _, _, request_id in scheduled)
    assert retained_references == [frozenset({8})]
    assert store.closed is True


def test_post_publication_retention_failure_does_not_invalidate_current(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    service = PublicationService(expected_owner_uid=0)
    notifications: list[tuple[str, str]] = []
    monkeypatch.setattr(
        service,
        "retention",
        lambda *_: (_ for _ in ()).throw(publication_service.OciCertificateError("failed")),
    )
    monkeypatch.setattr(
        service,
        "_notify_event",
        lambda _config, certificate_id, event: notifications.append((certificate_id, event)),
    )

    service._run_post_publication_retention(config, config.certificates[0])  # type: ignore[arg-type]

    assert notifications == [("main-site", "RETENTION_FAILED")]


def test_post_publication_retention_skips_disabled_policy(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    certificate = config.certificates[0]  # type: ignore[attr-defined]
    disabled = certificate.model_copy(
        update={"retention": certificate.retention.model_copy(update={"enabled": False})}
    )
    service = PublicationService(expected_owner_uid=0)
    monkeypatch.setattr(
        service, "retention", lambda *_: pytest.fail("retention must stay disabled")
    )

    service._run_post_publication_retention(config, disabled)  # type: ignore[arg-type]


def test_bootstrap_issues_then_creates_and_verifies_initial_current_version(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    material, root = material_with_root()
    certificate = config.certificates[0]  # type: ignore[attr-defined]
    bootstrap_certificate = certificate.model_copy(
        update={"oci": certificate.oci.model_copy(update={"certificate_ocid": None})}
    )
    bootstrap_config = config.model_copy(  # type: ignore[attr-defined]
        update={"certificates": (bootstrap_certificate,)}
    )
    request_ids: list[str] = []
    management = SimpleNamespace(
        create_imported_certificate=lambda **kw: (
            request_ids.append(kw["opc_request_id"]) or "ocid1.certificate.oc1.bootstrap"
        )
    )
    retrieval = SimpleNamespace(
        get_public_bundle=lambda *_args, **_kw: OciPublicBundle("leaf", "chain", 1, "v1", ())
    )
    service = PublicationService(
        adapters_factory=lambda *_: SimpleNamespace(management=management, retrieval=retrieval),
        expected_owner_uid=0,
    )
    monkeypatch.setattr(service, "_run_preflight", lambda *_: None)
    monkeypatch.setattr(service, "_load_and_validate", lambda *_: material)
    local_store = SimpleNamespace()
    monkeypatch.setattr(publication_service, "certificate_store", lambda *_: local_store)
    monkeypatch.setattr(publication_service, "OciExecutor", _Executor)
    monkeypatch.setattr(
        publication_service.NativeAcmeService,
        "issue",
        lambda *_args, **_kwargs: material,
    )
    monkeypatch.setattr(
        publication_service,
        "validate_certificate_material",
        lambda *_args, **_kw: "a" * 64,
    )
    monkeypatch.setattr(
        publication_service,
        "build_oci_chain",
        lambda *_: SimpleNamespace(cert_chain_pem=material.chain_pem, root=root),
    )
    monkeypatch.setattr(
        publication_service,
        "validate_public_certificate",
        lambda *_args, **_kw: "a" * 64,
    )

    result = service.bootstrap(bootstrap_config, "main-site")
    assert result.oci_certificate_ocid == "ocid1.certificate.oc1.bootstrap"
    assert result.current_version_number == 1
    assert len(request_ids) == 1
    assert str(UUID(request_ids[0])) == request_ids[0]
    database = bootstrap_config.global_.state_dir + "/state.sqlite3"
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT state, local_fingerprint, oci_certificate_ocid, oci_version_number
            FROM operations WHERE certificate_id = ? AND operation_type = ?
            """,
            ("main-site", "BOOTSTRAP"),
        ).fetchone()
    assert row == ("COMPLETED", "a" * 64, "ocid1.certificate.oc1.bootstrap", 1)


def test_bootstrap_recovers_created_ocid_without_creating_another_certificate(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    certificate = config.certificates[0]  # type: ignore[attr-defined]
    bootstrap_certificate = certificate.model_copy(
        update={"oci": certificate.oci.model_copy(update={"certificate_ocid": None})}
    )
    bootstrap_config = config.model_copy(  # type: ignore[attr-defined]
        update={"certificates": (bootstrap_certificate,)}
    )
    database = bootstrap_config.global_.state_dir + "/state.sqlite3"
    store = StateStore.open(Path(database))
    try:
        operation = store.start_operation(
            "main-site",
            OperationType.BOOTSTRAP,
            local_fingerprint="a" * 64,
        )
        store.transition(
            operation.operation_id,
            OperationState.OCI_RECONCILED,
            oci_certificate_ocid="ocid1.certificate.oc1.recovered",
        )
    finally:
        store.close()
    material, root = material_with_root()
    management = SimpleNamespace(
        create_imported_certificate=lambda **_: pytest.fail("must not create a second certificate")
    )
    retrieval = SimpleNamespace(
        get_public_bundle=lambda *_args, **_kw: OciPublicBundle("leaf", "chain", 1, "v1", ())
    )
    service = PublicationService(
        adapters_factory=lambda *_: SimpleNamespace(management=management, retrieval=retrieval),
        expected_owner_uid=0,
    )
    monkeypatch.setattr(service, "_run_preflight", lambda *_: None)
    monkeypatch.setattr(service, "_load_and_validate", lambda *_: material)
    local_store = SimpleNamespace()
    monkeypatch.setattr(publication_service, "certificate_store", lambda *_: local_store)
    monkeypatch.setattr(publication_service, "OciExecutor", _Executor)
    monkeypatch.setattr(
        publication_service.NativeAcmeService,
        "issue",
        lambda *_args, **_kwargs: material,
    )
    monkeypatch.setattr(
        publication_service,
        "validate_certificate_material",
        lambda *_args, **_kw: "a" * 64,
    )
    monkeypatch.setattr(
        publication_service,
        "build_oci_chain",
        lambda *_: SimpleNamespace(cert_chain_pem=material.chain_pem, root=root),
    )
    monkeypatch.setattr(
        publication_service,
        "validate_public_certificate",
        lambda *_args, **_kw: "a" * 64,
    )

    result = service.bootstrap(bootstrap_config, "main-site")

    assert result.oci_certificate_ocid == "ocid1.certificate.oc1.recovered"
    assert result.current_version_number == 1
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT state FROM operations WHERE operation_id = ?", (operation.operation_id,)
        ).fetchone()
    assert row == ("COMPLETED",)


def test_rollback_delegates_to_the_rollback_service_and_closes_state(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    store = _Store()
    expected = SimpleNamespace(certificate_id="main-site", version_number=2)
    received_audits: list[object] = []

    class Rollback:
        def __init__(self, *_: object) -> None:
            pass

        def rollback(self, *_: object, **keywords: object) -> object:
            received_audits.append(keywords["audit"])
            return expected

    service = PublicationService(
        adapters_factory=lambda *_: SimpleNamespace(management=object(), retrieval=object()),
        expected_owner_uid=0,
    )
    monkeypatch.setattr(publication_service, "StateStore", SimpleNamespace(open=lambda _: store))
    monkeypatch.setattr(publication_service, "OciExecutor", _Executor)
    monkeypatch.setattr(publication_service, "RollbackService", Rollback)

    assert service.rollback(config, "main-site") is expected  # type: ignore[arg-type]
    assert len(received_audits) == 1
    assert store.closed is True
