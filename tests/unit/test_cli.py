"""Command-output and exit-code tests for the operator CLI."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from oci_acme_publisher import cli
from oci_acme_publisher.acme_service import AcmeOperationError
from oci_acme_publisher.audit_service import AuditError
from oci_acme_publisher.certificate_store import CertificateStoreError
from oci_acme_publisher.certificate_validator import CertificateValidationError
from oci_acme_publisher.chain_builder import ChainBuildError
from oci_acme_publisher.compatibility_probe import (
    CompatibilityProbeError,
    LiveCompatibilityProbeResult,
)
from oci_acme_publisher.errors import ConfigurationError
from oci_acme_publisher.exit_codes import ExitCode
from oci_acme_publisher.http01_preflight import PreflightError
from oci_acme_publisher.models import Environment
from oci_acme_publisher.publication_service import (
    PublicationServiceError,
    RenewalFailure,
)
from oci_acme_publisher.rollback_service import RollbackError
from oci_acme_publisher.state_store import OperationType


@pytest.fixture
def config() -> object:
    return cli.load_config("config/config.example.yaml")


def test_validate_config_and_status_render_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], config: object
) -> None:
    monkeypatch.setattr(cli, "load_config", lambda _: config)
    assert cli._validate_config("unused", as_json=True) == ExitCode.SUCCESS
    assert '"result": "CONFIG_VALIDATED"' in capsys.readouterr().out

    monkeypatch.setattr(
        cli,
        "status",
        lambda _: [{"certificate_id": "main-site", "state": "CURRENT"}],
    )
    assert cli._status("unused", as_json=True) == ExitCode.SUCCESS
    assert '"state": "CURRENT"' in capsys.readouterr().out


def test_status_renders_human_readable_rows(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], config: object
) -> None:
    monkeypatch.setattr(cli, "load_config", lambda _: config)
    monkeypatch.setattr(
        cli,
        "status",
        lambda _: [{"certificate_id": "main-site", "state": "CURRENT"}],
    )
    assert cli._status("unused", as_json=False) == ExitCode.SUCCESS
    assert capsys.readouterr().out == "main-site: CURRENT\n"


def test_publish_and_reconcile_render_publication_result(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], config: object
) -> None:
    calls: list[OperationType] = []

    class Service:
        def publish(
            self, received_config: object, certificate_id: str, *, operation_type: OperationType
        ) -> object:
            assert received_config is config
            assert certificate_id == "main-site"
            calls.append(operation_type)
            return SimpleNamespace(
                certificate_id=certificate_id,
                changed=True,
                current_version_number=7,
            )

    monkeypatch.setattr(cli, "load_config", lambda _: config)
    monkeypatch.setattr(cli, "PublicationService", Service)
    assert cli._publish("unused", "main-site", OperationType.PUBLISH) == ExitCode.SUCCESS
    assert cli._publish("unused", "main-site", OperationType.RECONCILE) == ExitCode.SUCCESS
    assert calls == [OperationType.PUBLISH, OperationType.RECONCILE]
    assert capsys.readouterr().out.count("OCI_CURRENT_CONFIRMED") == 2


def test_renew_one_and_all_render_result(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], config: object
) -> None:
    result = SimpleNamespace(certificate_id="main-site", changed=True, current_version_number=3)

    class Service:
        def renew(self, received_config: object, certificate_id: str) -> object:
            assert received_config is config
            return result

        def renew_all(self, received_config: object) -> object:
            assert received_config is config
            return SimpleNamespace(publications=(result,), failures=())

    monkeypatch.setattr(cli, "load_config", lambda _: config)
    monkeypatch.setattr(cli, "PublicationService", Service)
    assert cli._renew("unused", "main-site") == ExitCode.SUCCESS
    assert cli._renew("unused", None) == ExitCode.SUCCESS
    assert capsys.readouterr().out.count("RENEW_COMPLETED") == 2


def test_force_renewal_is_limited_to_one_explicit_certificate_set(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    calls: list[tuple[str, bool]] = []

    class Service:
        def renew(
            self, _: object, certificate_id: str, *, force_acme_renewal: bool = False
        ) -> object:
            calls.append((certificate_id, force_acme_renewal))
            return SimpleNamespace(
                certificate_id=certificate_id, changed=True, current_version_number=2
            )

    monkeypatch.setattr(cli, "load_config", lambda _: config)
    monkeypatch.setattr(cli, "PublicationService", Service)
    assert cli._renew("unused", "main-site", force_acme_renewal=True) == ExitCode.SUCCESS
    assert calls == [("main-site", True)]


def test_cli_rejects_force_renewal_for_all_certificate_sets() -> None:
    with pytest.raises(SystemExit):
        cli.main(["renew", "--config", "config.yaml", "--force-acme-renewal"])


def test_public_cli_identifies_the_stable_command_and_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli._parser().prog == "oci-acme"
    with pytest.raises(SystemExit) as raised:
        cli.main(["--version"])
    assert raised.value.code == 0
    assert capsys.readouterr().out == "oci-acme 2.0.0\n"


def test_operator_configuration_workflows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config_directory = tmp_path / "oci-acme"
    assert cli.main(["config", "init", "--config-dir", str(config_directory)]) == 0
    assert (config_directory / "settings.yaml").is_file()
    assert (config_directory / "certificates" / "example-com.yaml").is_file()
    assert "CONFIG_INITIALIZED" in capsys.readouterr().out

    assert cli.main(["init", "--config-dir", str(tmp_path / "dry-run"), "--dry-run"]) == 0
    assert not (tmp_path / "dry-run").exists()
    assert "CONFIG_INIT_DRY_RUN" in capsys.readouterr().out


def test_config_init_refuses_to_overwrite_existing_configuration(tmp_path: Path) -> None:
    config_directory = tmp_path / "oci-acme"
    assert cli.main(["config", "init", "--config-dir", str(config_directory)]) == 0
    assert cli.main(["config", "init", "--config-dir", str(config_directory)]) == 2


def test_config_add_certificate_creates_only_a_new_validated_name(tmp_path: Path) -> None:
    config_directory = tmp_path / "oci-acme"
    assert cli.main(["config", "init", "--config-dir", str(config_directory)]) == 0
    arguments = [
        "config",
        "add-certificate",
        "--config-dir",
        str(config_directory),
        "--id",
        "second-site",
        "--domain",
        "second.example.com",
        "--region",
        "eu-frankfurt-1",
        "--compartment-ocid",
        "ocid1.compartment.oc1..example",
    ]
    assert cli.main(arguments) == 0
    assert (config_directory / "certificates" / "second-site.yaml").is_file()
    assert cli.main(arguments) == 2


def test_effective_config_and_diagnose_are_redacted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["config", "show-effective", "--config", "config/config.example.yaml"]) == 0
    assert '"email": "[REDACTED]"' in capsys.readouterr().out
    assert cli.main(["diagnose", "--config", "config/config.example.yaml"]) == 0
    assert "DIAGNOSE_CONFIGURATION_VALID" in capsys.readouterr().out


def test_onboard_runs_only_the_read_only_preflight(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        cli, "_preflight", lambda path, certificate_id: calls.append((path, certificate_id))
    )
    assert cli.main(["onboard", "--config", "unused", "--certificate-id", "main-site"]) == 0
    assert calls == [("unused", "main-site")]
    assert "ONBOARDING_PREREQUISITES_PASSED" in capsys.readouterr().out


def test_staging_verify_writes_immutable_gate_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, config: object
) -> None:
    staging_global = config.global_.model_copy(  # type: ignore[attr-defined]
        update={"environment": Environment.STAGING}
    )
    staging_acme = config.acme.model_copy(  # type: ignore[attr-defined]
        update={"directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"}
    )
    staging_config = config.model_copy(  # type: ignore[attr-defined]
        update={"global_": staging_global, "acme": staging_acme}
    )
    result = LiveCompatibilityProbeResult(
        certificate_id="main-site",
        oci_certificate_ocid="ocid1.certificate.oc1..test",
        initial_version_number=1,
        promoted_version_number=2,
        rollback_version_number=1,
        leaf_fingerprint="a" * 64,
        root_fingerprint="b" * 64,
        chain_bytes=100,
        documented_subject_country_enforced=True,
    )
    monkeypatch.setattr(cli, "load_config", lambda _: staging_config)
    monkeypatch.setattr(cli, "publisher_uid", lambda: 0)
    monkeypatch.setattr(cli, "live_probe", lambda *_args, **_kwargs: result)
    monkeypatch.setattr(cli, "AdvisoryLock", _NoopLock)
    evidence = tmp_path / "gate0.json"
    assert (
        cli.main(
            [
                "staging",
                "verify",
                "--config",
                "unused",
                "--certificate-id",
                "main-site",
                "--evidence-output",
                str(evidence),
            ]
        )
        == 0
    )
    assert '"result": "STAGING_COMPATIBILITY_PASSED"' in evidence.read_text(encoding="utf-8")


class _NoopLock:
    def __init__(self, _: object) -> None:
        pass

    def __enter__(self) -> _NoopLock:
        return self

    def __exit__(self, *_: object) -> None:
        return None


@pytest.mark.parametrize(
    ("error", "expected"),
    (
        (PreflightError("failed"), ExitCode.HTTP01_PREFLIGHT_FAILED),
        (AcmeOperationError("failed"), ExitCode.ACME_FAILED),
        (CertificateStoreError("failed"), ExitCode.X509_VALIDATION_FAILED),
        (CertificateValidationError("failed"), ExitCode.X509_VALIDATION_FAILED),
        (ChainBuildError("failed"), ExitCode.X509_VALIDATION_FAILED),
        (AuditError("failed"), ExitCode.AUDIT_ENFORCE_FAILED),
        (RollbackError("failed"), ExitCode.ROLLBACK_FAILED),
        (PublicationServiceError("failed"), ExitCode.OCI_IMPORT_FAILED),
    ),
)
def test_renewal_failure_exit_codes_are_stable(error: Exception, expected: ExitCode) -> None:
    failure = RenewalFailure("main-site", error)
    assert cli._renewal_exit_code((failure,)) == expected


def test_renew_all_reports_isolated_failures(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], config: object
) -> None:
    success = SimpleNamespace(certificate_id="second", changed=True, current_version_number=3)

    class Service:
        def renew_all(self, received_config: object) -> object:
            assert received_config is config
            return SimpleNamespace(
                publications=(success,),
                failures=(RenewalFailure("first", AcmeOperationError("failed")),),
            )

    monkeypatch.setattr(cli, "load_config", lambda _: config)
    monkeypatch.setattr(cli, "PublicationService", Service)

    assert cli._renew("unused", None) == ExitCode.ACME_FAILED
    output = capsys.readouterr().out
    assert '"certificate_ids": ["second"]' in output
    assert '"failed_certificate_ids": ["first"]' in output


def test_bootstrap_rollback_and_retention_render_results(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], config: object
) -> None:
    class Service:
        def bootstrap(self, _: object, certificate_id: str) -> object:
            return SimpleNamespace(
                certificate_id=certificate_id,
                current_version_number=1,
                oci_certificate_ocid="ocid1.certificate.oc1.example",
            )

        def rollback(self, _: object, certificate_id: str) -> object:
            return SimpleNamespace(certificate_id=certificate_id, version_number=2)

        def retention(self, _: object, certificate_id: str) -> object:
            return SimpleNamespace(certificate_id=certificate_id, scheduled_version_numbers=(1, 2))

    monkeypatch.setattr(cli, "load_config", lambda _: config)
    monkeypatch.setattr(cli, "PublicationService", Service)
    assert cli._bootstrap("unused", "main-site") == ExitCode.SUCCESS
    assert cli._rollback("unused", "main-site") == ExitCode.SUCCESS
    assert cli._retention("unused", "main-site") == ExitCode.SUCCESS
    output = capsys.readouterr().out
    assert "BOOTSTRAP_COMPLETED" in output
    assert "ROLLBACK_SUCCESS" in output
    assert "RETENTION_SCHEDULED" in output


def test_compatibility_probe_and_preflight_render_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], config: object
) -> None:
    certificate = config.certificates[0]  # type: ignore[attr-defined]
    probe_result = SimpleNamespace(
        certificate_id="main-site",
        chain_bytes=123,
        documented_subject_country_enforced=True,
        leaf_fingerprint="leaf",
        root_fingerprint="root",
    )
    ran_for: list[str] = []

    class Preflight:
        def run(self, _: object, selected: tuple[object, ...]) -> None:
            ran_for.extend(item.id for item in selected)  # type: ignore[attr-defined]

    staging_global = config.global_.model_copy(  # type: ignore[attr-defined]
        update={"environment": Environment.STAGING}
    )
    staging_acme = config.acme.model_copy(  # type: ignore[attr-defined]
        update={"directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"}
    )
    staging_config = config.model_copy(  # type: ignore[attr-defined]
        update={"global_": staging_global, "acme": staging_acme}
    )
    monkeypatch.setattr(cli, "load_config", lambda _: staging_config)
    monkeypatch.setattr(cli, "publisher_uid", lambda: 4242)
    monkeypatch.setattr(cli, "offline_probe", lambda *args, **kwargs: probe_result)
    monkeypatch.setattr(cli, "OperationalPreflight", Preflight)
    assert cli._compatibility_probe("unused", "main-site", live=False) == ExitCode.SUCCESS
    assert cli._preflight("unused", "main-site") == ExitCode.SUCCESS
    assert ran_for == [certificate.id]
    assert "COMPATIBILITY_OFFLINE_PASSED" in capsys.readouterr().out


def test_live_compatibility_probe_renders_gate_evidence(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], config: object
) -> None:
    result = LiveCompatibilityProbeResult(
        certificate_id="main-site",
        oci_certificate_ocid="ocid1.certificate.oc1..test",
        initial_version_number=1,
        promoted_version_number=2,
        rollback_version_number=1,
        leaf_fingerprint="leaf",
        root_fingerprint="root",
        chain_bytes=456,
        documented_subject_country_enforced=False,
    )
    monkeypatch.setattr(cli, "load_config", lambda _: config)
    monkeypatch.setattr(cli, "publisher_uid", lambda: 4242)
    monkeypatch.setattr(cli, "require_live_test_environment", lambda *_: None)
    monkeypatch.setattr(cli, "live_probe", lambda *_, **__: result)
    assert cli._compatibility_probe("unused", "main-site", live=True) == ExitCode.SUCCESS
    output = capsys.readouterr().out
    assert "COMPATIBILITY_LIVE_PASSED" in output
    assert '"promoted_version_number": 2' in output
    assert '"rollback_version_number": 1' in output


def test_preflight_rejects_missing_certificate(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    monkeypatch.setattr(cli, "load_config", lambda _: config)
    with pytest.raises(CompatibilityProbeError):
        cli._preflight("unused", "missing")


@pytest.mark.parametrize(
    ("error", "expected"),
    (
        (ConfigurationError("invalid config"), ExitCode.CONFIGURATION_INVALID),
        (CompatibilityProbeError("incompatible"), ExitCode.OCI_CERTIFICATE_PROFILE_INCOMPATIBLE),
        (PublicationServiceError("OCI failed"), ExitCode.OCI_IMPORT_FAILED),
    ),
)
def test_main_maps_expected_errors_to_stable_exit_codes(
    monkeypatch: pytest.MonkeyPatch, error: Exception, expected: ExitCode
) -> None:
    def fail(*_: object, **__: object) -> int:
        raise error

    monkeypatch.setattr(cli, "_validate_config", fail)
    assert cli.main(["validate-config", "--config", "unused"]) == expected


def test_main_locks_and_dispatches_mutating_command(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []

    class Lock:
        def __init__(self, _: object) -> None:
            pass

        def __enter__(self) -> Lock:
            events.append("enter")
            return self

        def __exit__(self, *_: object) -> None:
            events.append("exit")

    monkeypatch.setattr(cli, "AdvisoryLock", Lock)
    monkeypatch.setattr(cli, "_run_mutating_command", lambda *_: ExitCode.SUCCESS)
    assert cli.main(["publish", "--config", "unused", "--certificate-id", "main-site"]) == 0
    assert events == ["enter", "exit"]


def test_main_locks_live_compatibility_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []

    class Lock:
        def __init__(self, _: object) -> None:
            pass

        def __enter__(self) -> Lock:
            events.append("enter")
            return self

        def __exit__(self, *_: object) -> None:
            events.append("exit")

    monkeypatch.setattr(cli, "AdvisoryLock", Lock)
    monkeypatch.setattr(cli, "_compatibility_probe", lambda *_, **__: ExitCode.SUCCESS)
    assert (
        cli.main(
            [
                "compatibility-probe",
                "--config",
                "unused",
                "--certificate-id",
                "main-site",
                "--live",
            ]
        )
        == ExitCode.SUCCESS
    )
    assert events == ["enter", "exit"]


def test_main_generates_schema_file(tmp_path: Path) -> None:
    output = tmp_path / "schema.json"
    assert cli.main(["generate-schema", "--output", str(output)]) == ExitCode.SUCCESS
    assert '"schema_version"' in output.read_text(encoding="utf-8")


def test_main_maps_local_certificate_validation_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(*_: object, **__: object) -> int:
        raise CertificateStoreError("bad local material")

    monkeypatch.setattr(cli, "_validate_config", fail)
    assert cli.main(["validate-config", "--config", "unused"]) == ExitCode.X509_VALIDATION_FAILED
    assert capsys.readouterr().out == "local certificate validation failed\n"


@pytest.mark.parametrize(
    ("command", "expected"),
    (
        ("publish", "publish"),
        ("reconcile", "publish"),
        ("renew", "renew"),
        ("bootstrap", "bootstrap"),
        ("rollback", "rollback"),
        ("retention", "retention"),
        ("audit", "audit"),
    ),
)
def test_mutating_dispatch_routes_each_command_to_its_handler(
    monkeypatch: pytest.MonkeyPatch, command: str, expected: str
) -> None:
    calls: list[str] = []

    def handler(*_: object, **__: object) -> int:
        calls.append(expected)
        return 42

    for name in ("_publish", "_renew", "_bootstrap", "_rollback", "_retention", "_audit"):
        monkeypatch.setattr(cli, name, handler)
    args = SimpleNamespace(config="config.yaml", certificate_id="main-site")
    assert cli._run_mutating_command(command, args) == 42
    assert calls == [expected]


def test_compatibility_probe_rejects_unknown_certificate(
    monkeypatch: pytest.MonkeyPatch, config: object
) -> None:
    monkeypatch.setattr(cli, "load_config", lambda _: config)
    with pytest.raises(CompatibilityProbeError):
        cli._compatibility_probe("unused", "missing", live=False)


@pytest.mark.parametrize(
    ("arguments", "handler"),
    (
        (
            (
                "compatibility-probe",
                "--config",
                "unused",
                "--certificate-id",
                "main-site",
                "--offline",
            ),
            "_compatibility_probe",
        ),
        (("status", "--config", "unused"), "_status"),
        (("preflight", "--config", "unused"), "_preflight"),
    ),
)
def test_main_dispatches_each_read_only_command(
    monkeypatch: pytest.MonkeyPatch, arguments: tuple[str, ...], handler: str
) -> None:
    monkeypatch.setattr(cli, handler, lambda *_: ExitCode.SUCCESS)
    assert cli.main(list(arguments)) == ExitCode.SUCCESS


@pytest.mark.parametrize(
    ("error", "expected"),
    (
        (PreflightError("preflight"), ExitCode.HTTP01_PREFLIGHT_FAILED),
        (AcmeOperationError("acme"), ExitCode.ACME_FAILED),
        (AuditError("audit"), ExitCode.AUDIT_ENFORCE_FAILED),
        (RollbackError("rollback"), ExitCode.ROLLBACK_FAILED),
    ),
)
def test_main_maps_operational_failures_to_stable_exit_codes(
    monkeypatch: pytest.MonkeyPatch, error: Exception, expected: ExitCode
) -> None:
    def fail(*_: object, **__: object) -> int:
        raise error

    monkeypatch.setattr(cli, "_validate_config", fail)
    assert cli.main(["validate-config", "--config", "unused"]) == expected
