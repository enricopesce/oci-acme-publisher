from __future__ import annotations

import pytest

from oci_acme_publisher import cli, publication_service
from oci_acme_publisher.audit_service import AuditError
from oci_acme_publisher.cli import _parser
from oci_acme_publisher.config import AppConfig, load_config
from oci_acme_publisher.exit_codes import ExitCode
from oci_acme_publisher.models import AuditMode
from oci_acme_publisher.publication_service import (
    PublicationService,
    PublicationServiceError,
    RetentionResult,
    configured_certificate,
)


def test_selects_configured_certificate() -> None:
    config = load_config("config/config.example.yaml")
    assert configured_certificate(config, "main-site").id == "main-site"


def test_rejects_unknown_configured_certificate() -> None:
    config = load_config("config/config.example.yaml")
    with pytest.raises(PublicationServiceError):
        configured_certificate(config, "missing")


def test_cli_accepts_publish_and_reconcile_with_explicit_certificate_id() -> None:
    parser = _parser()
    publish = parser.parse_args(
        ["publish", "--config", "config.yaml", "--certificate-id", "main-site"]
    )
    reconcile = parser.parse_args(
        ["reconcile", "--config", "config.yaml", "--certificate-id", "main-site"]
    )
    assert publish.command == "publish"
    assert reconcile.command == "reconcile"


def test_cli_accepts_renew_for_all_configured_certificate_sets() -> None:
    arguments = _parser().parse_args(["renew", "--config", "config.yaml"])
    assert arguments.certificate_id is None


@pytest.mark.parametrize(
    ("mode", "expected_exit"),
    ((AuditMode.OBSERVE, ExitCode.SUCCESS), (AuditMode.ENFORCE, ExitCode.AUDIT_ENFORCE_FAILED)),
)
def test_audit_only_fails_process_in_enforce_mode(
    monkeypatch: pytest.MonkeyPatch, mode: AuditMode, expected_exit: ExitCode
) -> None:
    base_config = load_config("config/config.example.yaml")
    first_certificate = base_config.certificates[0].model_copy(
        update={"audit": base_config.certificates[0].audit.model_copy(update={"mode": mode})}
    )
    config = base_config.model_copy(update={"certificates": (first_certificate,)})

    class FailingAuditService:
        def audit(self, received_config: object, certificate_id: str) -> bool:
            assert received_config is config
            assert certificate_id == "main-site"
            return False

    monkeypatch.setattr(cli, "load_config", lambda _: config)
    monkeypatch.setattr(cli, "PublicationService", FailingAuditService)

    assert cli._audit("config.yaml", "main-site") == expected_exit


def test_automatic_rollback_requires_enforce_mode() -> None:
    raw = load_config("config/config.example.yaml").model_dump(by_alias=True)
    raw["certificates"][0]["audit"]["automatic_rollback_on_failure"] = True
    with pytest.raises(ValueError, match="automatic_rollback_on_failure"):
        AppConfig.model_validate(raw)


def test_enforced_failed_audit_rolls_back_only_when_explicitly_authorized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = load_config("config/config.example.yaml")
    audit = base.certificates[0].audit.model_copy(
        update={"mode": AuditMode.ENFORCE, "automatic_rollback_on_failure": True}
    )
    certificate = base.certificates[0].model_copy(update={"audit": audit})
    config = base.model_copy(update={"certificates": (certificate,)})
    service = PublicationService(expected_owner_uid=0)
    calls: list[str] = []
    monkeypatch.setattr(service, "audit", lambda *_: False)
    monkeypatch.setattr(service, "rollback", lambda *_: calls.append("rollback"))

    service._enforce_post_publication_audit(config, certificate)

    assert calls == ["rollback"]


def test_enforced_failed_audit_without_policy_does_not_roll_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = load_config("config/config.example.yaml")
    audit = base.certificates[0].audit.model_copy(update={"mode": AuditMode.ENFORCE})
    certificate = base.certificates[0].model_copy(update={"audit": audit})
    config = base.model_copy(update={"certificates": (certificate,)})
    service = PublicationService(expected_owner_uid=0)
    monkeypatch.setattr(service, "audit", lambda *_: False)
    monkeypatch.setattr(service, "rollback", lambda *_: pytest.fail("unexpected rollback"))

    with pytest.raises(AuditError, match="TLS audit failed"):
        service._enforce_post_publication_audit(config, certificate)


def test_enforced_audit_exception_is_rolled_back_when_policy_authorizes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = load_config("config/config.example.yaml")
    audit = base.certificates[0].audit.model_copy(
        update={"mode": AuditMode.ENFORCE, "automatic_rollback_on_failure": True}
    )
    certificate = base.certificates[0].model_copy(update={"audit": audit})
    config = base.model_copy(update={"certificates": (certificate,)})
    service = PublicationService(expected_owner_uid=0)
    calls: list[str] = []

    def failed_audit(*_: object) -> bool:
        raise AuditError("failed")

    monkeypatch.setattr(service, "audit", failed_audit)
    monkeypatch.setattr(service, "rollback", lambda *_: calls.append("rollback"))
    service._enforce_post_publication_audit(config, certificate)
    assert calls == ["rollback"]


def test_successful_enforced_audit_never_rolls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    base = load_config("config/config.example.yaml")
    audit = base.certificates[0].audit.model_copy(update={"mode": AuditMode.ENFORCE})
    certificate = base.certificates[0].model_copy(update={"audit": audit})
    config = base.model_copy(update={"certificates": (certificate,)})
    service = PublicationService(expected_owner_uid=0)
    monkeypatch.setattr(service, "audit", lambda *_: True)
    monkeypatch.setattr(service, "rollback", lambda *_: pytest.fail("unexpected rollback"))
    service._enforce_post_publication_audit(config, certificate)


def test_observe_post_publication_audit_runs_and_never_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config("config/config.example.yaml")
    certificate = config.certificates[0]
    service = PublicationService(expected_owner_uid=0)
    calls: list[str] = []
    monkeypatch.setattr(service, "audit", lambda *_: calls.append("audit") or False)

    service._run_post_publication_audit(config, certificate)

    assert calls == ["audit"]


def test_observe_post_publication_audit_swallows_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config("config/config.example.yaml")
    certificate = config.certificates[0]
    service = PublicationService(expected_owner_uid=0)
    monkeypatch.setattr(
        service,
        "audit",
        lambda *_: (_ for _ in ()).throw(AuditError("endpoint unavailable")),
    )

    service._run_post_publication_audit(config, certificate)


def test_disabled_post_publication_audit_performs_no_network_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = load_config("config/config.example.yaml")
    certificate = base.certificates[0].model_copy(
        update={"audit": base.certificates[0].audit.model_copy(update={"mode": AuditMode.DISABLED})}
    )
    service = PublicationService(expected_owner_uid=0)
    monkeypatch.setattr(service, "audit", lambda *_: pytest.fail("audit must stay disabled"))

    service._run_post_publication_audit(base, certificate)


def test_enforce_post_publication_audit_delegates_to_enforcement_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = load_config("config/config.example.yaml")
    audit = base.certificates[0].audit.model_copy(update={"mode": AuditMode.ENFORCE})
    certificate = base.certificates[0].model_copy(update={"audit": audit})
    config = base.model_copy(update={"certificates": (certificate,)})
    service = PublicationService(expected_owner_uid=0)
    calls: list[str] = []
    monkeypatch.setattr(
        service, "_enforce_post_publication_audit", lambda *_: calls.append("enforce")
    )

    service._run_post_publication_audit(config, certificate)

    assert calls == ["enforce"]


def test_post_publication_retention_logs_safe_no_deletion_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config("config/config.example.yaml")
    certificate = config.certificates[0]
    service = PublicationService(expected_owner_uid=0)
    monkeypatch.setattr(service, "retention", lambda *_: RetentionResult("main-site", ()))

    service._run_post_publication_retention(config, certificate)


def test_bootstrap_rejects_existing_oci_certificate() -> None:
    service = PublicationService(expected_owner_uid=0)
    config = load_config("config/config.example.yaml")
    with pytest.raises(PublicationServiceError, match="certificate_ocid"):
        service.bootstrap(config, "main-site")


def test_run_preflight_logs_both_success_and_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_config("config/config.example.yaml")
    certificate = config.certificates[0]

    class SuccessfulPreflight:
        def __init__(self, _: object) -> None:
            pass

        async def run(self, _: object, **__: object) -> None:
            return None

    monkeypatch.setattr(publication_service, "Http01Preflight", SuccessfulPreflight)
    PublicationService._run_preflight(config, certificate)

    class FailedPreflight(SuccessfulPreflight):
        async def run(self, _: object, **__: object) -> None:
            raise publication_service.PreflightError("failed")

    monkeypatch.setattr(publication_service, "Http01Preflight", FailedPreflight)
    with pytest.raises(publication_service.PreflightError):
        PublicationService._run_preflight(config, certificate)


def test_load_and_validate_delegates_to_bound_certificate_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config("config/config.example.yaml")
    certificate = config.certificates[0]
    expected = object()

    class Loader:
        def load(self, received: object) -> object:
            assert received is certificate
            return expected

    monkeypatch.setattr(publication_service, "certificate_store", lambda *_: Loader())
    assert (
        PublicationService(expected_owner_uid=0)._load_and_validate(config, certificate) is expected
    )
