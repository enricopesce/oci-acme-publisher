"""Command line interface for safe read-only operations."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .acme_service import AcmeOperationError
from .audit_service import AuditError
from .certificate_store import CertificateStoreError
from .certificate_validator import CertificateValidationError
from .chain_builder import ChainBuildError
from .compatibility_probe import (
    CompatibilityProbeError,
    CompatibilityProbeResult,
    LiveCompatibilityProbeResult,
    LiveProbePrerequisiteError,
    live_probe,
    offline_probe,
    require_live_test_environment,
)
from .config import AppConfig, load_config
from .errors import PublisherError
from .exit_codes import ExitCode
from .http01_paths import publisher_uid
from .http01_preflight import PreflightError
from .locking import AdvisoryLock
from .logging_config import configure_json_logging, log_event
from .metrics import collect_read_only_metrics, write_configured_metrics, write_metrics
from .models import AuditMode, Environment
from .oci_auth import OciAuthenticationError
from .oci_certificates import OciCertificateError
from .operator import (
    DEFAULT_CONFIG_DIRECTORY,
    add_certificate,
    diagnose_configuration,
    effective_configuration,
    initialize_configuration,
    render_json,
)
from .preflight_service import OperationalPreflight
from .publication_service import (
    PublicationService,
    PublicationServiceError,
    RenewalFailure,
    configured_certificate,
)
from .reconciler import PublicationResult, ReconciliationError
from .rollback_service import RollbackError
from .staging_evidence import require_qualified_profile, write_evidence
from .state_store import OperationType
from .status_service import status
from .support import service_status, support_bundle, write_support_bundle

_LOGGER = logging.getLogger(__name__)


def _configure_runtime_logging(config: AppConfig) -> None:
    """Keep command JSON on stdout and structured operational events on stderr."""
    if config.global_.json_logging:
        configure_json_logging(config.global_.log_level, stream=sys.stderr)


def _operation_failed(error_code: str) -> None:
    """Emit the terminal process event without exposing the original exception text."""
    log_event(_LOGGER, logging.ERROR, "OPERATION_FAILED", error_code=error_code)


def _parser() -> argparse.ArgumentParser:
    """Create the public operator CLI parser.

    ``oci-acme`` is the stable public command.  The historical
    ``oci-acme-publisher`` entry point intentionally dispatches to this same
    parser so existing systemd units and automation remain compatible.
    """
    parser = argparse.ArgumentParser(prog="oci-acme")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)
    init = subcommands.add_parser("init", help="create a safe staging configuration skeleton")
    init.add_argument("--config-dir", default=DEFAULT_CONFIG_DIRECTORY)
    init.add_argument("--dry-run", action="store_true")
    config = subcommands.add_parser("config", help="manage configuration files")
    config_commands = config.add_subparsers(dest="config_command", required=True)
    config_init = config_commands.add_parser(
        "init", help="create a safe staging configuration skeleton"
    )
    config_init.add_argument("--config-dir", default=DEFAULT_CONFIG_DIRECTORY)
    config_init.add_argument("--dry-run", action="store_true")
    config_validate = config_commands.add_parser("validate", help="validate configuration")
    config_validate.add_argument("--config", required=True)
    config_validate.add_argument("--json", action="store_true", dest="as_json")
    config_add = config_commands.add_parser(
        "add-certificate", help="create one certificate configuration file"
    )
    config_add.add_argument("--config-dir", default=DEFAULT_CONFIG_DIRECTORY)
    config_add.add_argument("--id", required=True, dest="certificate_id")
    config_add.add_argument("--domain", required=True, action="append", dest="domains")
    config_add.add_argument("--region", required=True)
    config_add.add_argument("--compartment-ocid", required=True)
    config_add.add_argument("--certificate-ocid")
    config_add.add_argument("--dry-run", action="store_true")
    config_show = config_commands.add_parser(
        "show-effective", help="print normalized, redacted configuration"
    )
    config_show.add_argument("--config", required=True)
    diagnose = subcommands.add_parser(
        "diagnose", help="collect safe local configuration diagnostics"
    )
    diagnose.add_argument("--config", required=True)
    diagnose.add_argument("--output", help="write a new redacted support bundle JSON file")
    metrics = subcommands.add_parser("metrics", help="collect read-only Prometheus metrics")
    metrics_commands = metrics.add_subparsers(dest="metrics_command", required=True)
    metrics_collect = metrics_commands.add_parser(
        "collect", help="render metrics without creating state"
    )
    metrics_collect.add_argument("--config", required=True)
    metrics_collect.add_argument("--output", help="write metrics to an explicit textfile path")
    service = subcommands.add_parser("service", help="read systemd service state")
    service_commands = service.add_subparsers(dest="service_command", required=True)
    service_commands.add_parser("status", help="show bounded state for OCI ACME systemd units")
    check = subcommands.add_parser("check", help="run the read-only operational preflight")
    check.add_argument("--config", required=True)
    check.add_argument("--certificate-id", required=False)
    onboard = subcommands.add_parser(
        "onboard", help="validate a staging configuration and its live prerequisites"
    )
    onboard.add_argument("--config", required=True)
    onboard.add_argument("--certificate-id", required=False)
    staging = subcommands.add_parser(
        "staging", help="run and retain staging qualification evidence"
    )
    staging_commands = staging.add_subparsers(dest="staging_command", required=True)
    staging_verify = staging_commands.add_parser(
        "verify", help="run the live Gate 0 probe and write immutable evidence"
    )
    staging_verify.add_argument("--config", required=True)
    staging_verify.add_argument("--certificate-id", required=True)
    staging_verify.add_argument("--evidence-output", required=True)
    validate = subcommands.add_parser(
        "validate-config", help="validate configuration without mutations"
    )
    validate.add_argument("--config", required=True)
    validate.add_argument("--json", action="store_true", dest="as_json")
    schema = subcommands.add_parser("generate-schema", help="write the JSON configuration schema")
    schema.add_argument("--output", required=True)
    probe = subcommands.add_parser("compatibility-probe", help="run OCI certificate profile Gate 0")
    probe.add_argument("--config", required=True)
    probe.add_argument("--certificate-id", required=True)
    probe_mode = probe.add_mutually_exclusive_group(required=True)
    probe_mode.add_argument("--offline", action="store_true")
    probe_mode.add_argument("--live", action="store_true")
    status_command = subcommands.add_parser("status", help="show safe local certificate status")
    status_command.add_argument("--config", required=True)
    status_command.add_argument("--json", action="store_true", dest="as_json")
    preflight = subcommands.add_parser(
        "preflight", help="verify root pins, read-only OCI access and HTTP-01 routing"
    )
    preflight.add_argument("--config", required=True)
    preflight.add_argument("--certificate-id", required=False)
    for command, help_text in (
        ("audit", "audit TLS endpoints against OCI CURRENT"),
        ("rollback", "promote one eligible OCI PREVIOUS version"),
        ("retention", "schedule safe OCI deprecated-version retention"),
    ):
        operation = subcommands.add_parser(command, help=help_text)
        operation.add_argument("--config", required=True)
        operation.add_argument("--certificate-id", required=True)
    for command, help_text in (
        ("bootstrap", "issue an initial lineage and create one imported OCI certificate"),
        ("renew", "preflight, renew one native ACME certificate, then reconcile OCI"),
        ("publish", "publish validated local lineage material to OCI"),
        ("reconcile", "complete an interrupted OCI publication without new ACME issuance"),
    ):
        operation = subcommands.add_parser(command, help=help_text)
        operation.add_argument("--config", required=True)
        operation.add_argument("--certificate-id", required=command != "renew")
        if command == "renew":
            operation.add_argument(
                "--force-acme-renewal",
                action="store_true",
                help=(
                    "intentionally request a new ACME certificate for one explicit certificate set"
                ),
            )
    return parser


def _validate_config(path: str, as_json: bool) -> int:
    config = load_config(path)
    _configure_runtime_logging(config)
    log_event(_LOGGER, logging.INFO, "CONFIG_VALIDATED", certificate_count=len(config.certificates))
    payload = {
        "result": "CONFIG_VALIDATED",
        "schema_version": config.schema_version,
        "environment": config.global_.environment,
        "certificate_count": len(config.certificates),
    }
    if as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print("configuration valid")
    return int(ExitCode.SUCCESS)


def _initialize_config(config_directory: str, *, dry_run: bool) -> int:
    files = initialize_configuration(config_directory, dry_run=dry_run)
    print(
        render_json(
            {
                "config_directory": config_directory,
                "files": files,
                "result": "CONFIG_INIT_DRY_RUN" if dry_run else "CONFIG_INITIALIZED",
            }
        )
    )
    return int(ExitCode.SUCCESS)


def _show_effective_config(path: str) -> int:
    print(render_json(effective_configuration(path)))
    return int(ExitCode.SUCCESS)


def _add_certificate_config(args: argparse.Namespace) -> int:
    path = add_certificate(
        args.config_dir,
        certificate_id=args.certificate_id,
        domains=tuple(args.domains),
        region=args.region,
        compartment_ocid=args.compartment_ocid,
        certificate_ocid=args.certificate_ocid,
        dry_run=args.dry_run,
    )
    print(
        render_json(
            {
                "certificate_path": path,
                "result": (
                    "CERTIFICATE_CONFIG_DRY_RUN" if args.dry_run else "CERTIFICATE_CONFIG_ADDED"
                ),
            }
        )
    )
    return int(ExitCode.SUCCESS)


def _diagnose(path: str, output: str | None = None) -> int:
    config = load_config(path)
    if output is None:
        print(render_json(diagnose_configuration(path)))
        return int(ExitCode.SUCCESS)
    bundle = support_bundle(path, config)
    write_support_bundle(output, bundle)
    print(render_json({"output": output, "result": "SUPPORT_BUNDLE_WRITTEN"}))
    return int(ExitCode.SUCCESS)


def _collect_metrics(path: str, output: str | None) -> int:
    config = load_config(path)
    metrics = collect_read_only_metrics(config)
    if output is None:
        print("".join(metric.render() for metric in metrics), end="")
    else:
        write_metrics(Path(output), metrics)
        print(render_json({"output": output, "result": "METRICS_WRITTEN"}))
    return int(ExitCode.SUCCESS)


def _service_status() -> int:
    print(render_json(service_status()))
    return int(ExitCode.SUCCESS)


def _onboard(path: str, certificate_id: str | None) -> int:
    """Run the non-mutating gate before the operator chooses to issue a certificate."""
    _preflight(path, certificate_id)
    print(
        render_json(
            {
                "result": "ONBOARDING_PREREQUISITES_PASSED",
                "next_action": (
                    "Review the staging result, then run an explicit bootstrap or issuance command."
                ),
            }
        )
    )
    return int(ExitCode.SUCCESS)


def _staging_verify(path: str, certificate_id: str, evidence_output: str) -> int:
    """Run the staging-only live probe and retain its result for production qualification."""
    config = load_config(path)
    _configure_runtime_logging(config)
    certificate = configured_certificate(config, certificate_id)
    require_live_test_environment(config, certificate)
    result = live_probe(config, certificate, expected_owner_uid=publisher_uid())
    write_evidence(evidence_output, certificate, result)
    print(
        render_json(
            {
                "certificate_id": certificate.id,
                "evidence_path": evidence_output,
                "promoted_version_number": result.promoted_version_number,
                "result": "STAGING_EVIDENCE_WRITTEN",
                "rollback_version_number": result.rollback_version_number,
            }
        )
    )
    return int(ExitCode.SUCCESS)


def _publish(path: str, certificate_id: str, operation_type: OperationType) -> int:
    config = load_config(path)
    _configure_runtime_logging(config)
    result = PublicationService().publish(config, certificate_id, operation_type=operation_type)
    write_configured_metrics(config)
    print(
        json.dumps(
            {
                "certificate_id": result.certificate_id,
                "changed": result.changed,
                "current_version_number": result.current_version_number,
                "result": "OCI_CURRENT_CONFIRMED",
            },
            sort_keys=True,
        )
    )
    return int(ExitCode.SUCCESS)


def _renew(path: str, certificate_id: str | None, *, force_acme_renewal: bool = False) -> int:
    config = load_config(path)
    _configure_runtime_logging(config)
    service = PublicationService()
    results: tuple[PublicationResult, ...]
    failures: tuple[RenewalFailure, ...]
    if certificate_id is not None:
        if force_acme_renewal:
            results = (service.renew(config, certificate_id, force_acme_renewal=True),)
        else:
            results = (service.renew(config, certificate_id),)
        failures = ()
    else:
        batch = service.renew_all(config)
        results = batch.publications
        failures = batch.failures
    write_configured_metrics(config)
    print(
        json.dumps(
            {
                "certificate_ids": [result.certificate_id for result in results],
                "changed": any(result.changed for result in results),
                "current_version_numbers": [result.current_version_number for result in results],
                "failed_certificate_ids": [failure.certificate_id for failure in failures],
                "result": "RENEW_COMPLETED",
            },
            sort_keys=True,
        )
    )
    return int(ExitCode.SUCCESS if not failures else _renewal_exit_code(failures))


def _renewal_exit_code(failures: Sequence[object]) -> ExitCode:
    """Return the most specific stable code without printing internal diagnostics."""
    errors = tuple(getattr(failure, "error", None) for failure in failures)
    if any(isinstance(error, PreflightError) for error in errors):
        return ExitCode.HTTP01_PREFLIGHT_FAILED
    if any(isinstance(error, AcmeOperationError) for error in errors):
        return ExitCode.ACME_FAILED
    if any(
        isinstance(error, CertificateStoreError | CertificateValidationError | ChainBuildError)
        for error in errors
    ):
        return ExitCode.X509_VALIDATION_FAILED
    if any(isinstance(error, AuditError) for error in errors):
        return ExitCode.AUDIT_ENFORCE_FAILED
    if any(isinstance(error, RollbackError) for error in errors):
        return ExitCode.ROLLBACK_FAILED
    return ExitCode.OCI_IMPORT_FAILED


def _bootstrap(path: str, certificate_id: str) -> int:
    config = load_config(path)
    _configure_runtime_logging(config)
    result = PublicationService().bootstrap(config, certificate_id)
    write_configured_metrics(config)
    print(
        json.dumps(
            {
                "certificate_id": result.certificate_id,
                "current_version_number": result.current_version_number,
                "oci_certificate_ocid": result.oci_certificate_ocid,
                "result": "BOOTSTRAP_COMPLETED",
            },
            sort_keys=True,
        )
    )
    return int(ExitCode.SUCCESS)


def _compatibility_probe(path: str, certificate_id: str, live: bool) -> int:
    config = load_config(path)
    _configure_runtime_logging(config)
    certificate = next(
        (item for item in config.certificates if item.id == certificate_id),
        None,
    )
    if certificate is None:
        raise CompatibilityProbeError("configured certificate id was not found")
    result: CompatibilityProbeResult | LiveCompatibilityProbeResult
    if live:
        require_live_test_environment(config, certificate)
        result = live_probe(config, certificate, expected_owner_uid=publisher_uid())
    else:
        result = offline_probe(config, certificate, expected_owner_uid=publisher_uid())
    payload: dict[str, object] = {
        "certificate_id": result.certificate_id,
        "chain_bytes": result.chain_bytes,
        "documented_subject_country_enforced": result.documented_subject_country_enforced,
        "leaf_fingerprint": result.leaf_fingerprint,
        "root_fingerprint": result.root_fingerprint,
    }
    if isinstance(result, LiveCompatibilityProbeResult):
        payload.update(
            {
                "initial_version_number": result.initial_version_number,
                "oci_certificate_ocid": result.oci_certificate_ocid,
                "promoted_version_number": result.promoted_version_number,
                "result": "COMPATIBILITY_LIVE_PASSED",
                "rollback_version_number": result.rollback_version_number,
            }
        )
    else:
        payload["result"] = "COMPATIBILITY_OFFLINE_PASSED"
    print(json.dumps(payload, sort_keys=True))
    return int(ExitCode.SUCCESS)


def _status(path: str, as_json: bool) -> int:
    config = load_config(path)
    _configure_runtime_logging(config)
    results = status(config)
    if as_json:
        print(json.dumps(results, sort_keys=True))
    else:
        for result in results:
            print(f"{result['certificate_id']}: {result['state']}")
    return int(ExitCode.SUCCESS)


def _preflight(path: str, certificate_id: str | None) -> int:
    config = load_config(path)
    _configure_runtime_logging(config)
    certificates = (
        tuple(
            certificate for certificate in config.certificates if certificate.id == certificate_id
        )
        if certificate_id is not None
        else config.certificates
    )
    if not certificates:
        raise CompatibilityProbeError("configured certificate id was not found")
    if config.global_.environment is Environment.PRODUCTION:
        for certificate in certificates:
            require_qualified_profile(config, certificate)
    OperationalPreflight().run(config, certificates)
    print(
        json.dumps(
            {
                "certificate_ids": [certificate.id for certificate in certificates],
                "result": "PREFLIGHT_SUCCESS",
            },
            sort_keys=True,
        )
    )
    return int(ExitCode.SUCCESS)


def _audit(path: str, certificate_id: str) -> int:
    config = load_config(path)
    _configure_runtime_logging(config)
    successful = PublicationService().audit(config, certificate_id)
    write_configured_metrics(config)
    is_observe_only = configured_certificate(config, certificate_id).audit.mode is AuditMode.OBSERVE
    print(
        json.dumps(
            {
                "certificate_id": certificate_id,
                "result": (
                    "AUDIT_SUCCESS"
                    if successful
                    else "AUDIT_FAILED_OBSERVE"
                    if is_observe_only
                    else "AUDIT_FAILED_ENFORCE"
                ),
            },
            sort_keys=True,
        )
    )
    return int(ExitCode.SUCCESS if successful or is_observe_only else ExitCode.AUDIT_ENFORCE_FAILED)


def _rollback(path: str, certificate_id: str) -> int:
    config = load_config(path)
    _configure_runtime_logging(config)
    result = PublicationService().rollback(config, certificate_id)
    write_configured_metrics(config)
    print(
        json.dumps(
            {
                "certificate_id": result.certificate_id,
                "result": "ROLLBACK_SUCCESS",
                "version_number": result.version_number,
            },
            sort_keys=True,
        )
    )
    return int(ExitCode.SUCCESS)


def _retention(path: str, certificate_id: str) -> int:
    config = load_config(path)
    _configure_runtime_logging(config)
    result = PublicationService().retention(config, certificate_id)
    write_configured_metrics(config)
    print(
        json.dumps(
            {
                "certificate_id": result.certificate_id,
                "result": "RETENTION_SCHEDULED",
                "version_numbers": result.scheduled_version_numbers,
            },
            sort_keys=True,
        )
    )
    return int(ExitCode.SUCCESS)


def main(argv: Sequence[str] | None = None) -> int:
    """Run a CLI command and map expected failures to stable exit codes."""
    args = _parser().parse_args(argv)
    if args.command == "renew" and args.force_acme_renewal and args.certificate_id is None:
        _parser().error("--force-acme-renewal requires --certificate-id")
    try:
        if args.command == "init":
            return _initialize_config(args.config_dir, dry_run=args.dry_run)
        if args.command == "config":
            if args.config_command == "init":
                return _initialize_config(args.config_dir, dry_run=args.dry_run)
            if args.config_command == "validate":
                return _validate_config(args.config, args.as_json)
            if args.config_command == "add-certificate":
                return _add_certificate_config(args)
            if args.config_command == "show-effective":
                return _show_effective_config(args.config)
        if args.command == "diagnose":
            return _diagnose(args.config, args.output)
        if args.command == "metrics":
            return _collect_metrics(args.config, args.output)
        if args.command == "service":
            return _service_status()
        if args.command == "check":
            return _preflight(args.config, args.certificate_id)
        if args.command == "onboard":
            return _onboard(args.config, args.certificate_id)
        if args.command == "staging":
            with AdvisoryLock(Path("/run/oci-acme-publisher/renew.lock")):
                return _staging_verify(args.config, args.certificate_id, args.evidence_output)
        mutating_commands = frozenset(
            {
                "audit",
                "bootstrap",
                "renew",
                "publish",
                "reconcile",
                "rollback",
                "retention",
            }
        )
        if args.command in mutating_commands or (
            args.command == "compatibility-probe" and args.live
        ):
            with AdvisoryLock(Path("/run/oci-acme-publisher/renew.lock")):
                if args.command == "compatibility-probe":
                    return _compatibility_probe(args.config, args.certificate_id, live=True)
                return _run_mutating_command(args.command, args)
        if args.command == "validate-config":
            return _validate_config(args.config, args.as_json)
        if args.command == "generate-schema":
            with open(args.output, "w", encoding="utf-8") as schema_file:
                json.dump(AppConfig.model_json_schema(), schema_file, indent=2, sort_keys=True)
                schema_file.write("\n")
            return int(ExitCode.SUCCESS)
        if args.command == "compatibility-probe":
            return _compatibility_probe(args.config, args.certificate_id, args.live)
        if args.command == "status":
            return _status(args.config, args.as_json)
        if args.command == "preflight":
            return _preflight(args.config, args.certificate_id)
        if args.command == "audit":
            return _audit(args.config, args.certificate_id)
    except PublisherError as error:
        _operation_failed("CONFIGURATION_INVALID")
        print(error.public_message)
        return int(error.code)
    except (CertificateStoreError, CertificateValidationError, ChainBuildError):
        _operation_failed("X509_VALIDATION_FAILED")
        print("local certificate validation failed")
        return int(ExitCode.X509_VALIDATION_FAILED)
    except PreflightError:
        _operation_failed("HTTP01_PREFLIGHT_FAILED")
        print("HTTP-01 preflight failed")
        return int(ExitCode.HTTP01_PREFLIGHT_FAILED)
    except AcmeOperationError:
        _operation_failed("ACME_FAILED")
        print("ACME operation failed")
        return int(ExitCode.ACME_FAILED)
    except AuditError:
        _operation_failed("AUDIT_ENFORCE_FAILED")
        print("TLS audit failed")
        return int(ExitCode.AUDIT_ENFORCE_FAILED)
    except RollbackError:
        _operation_failed("ROLLBACK_FAILED")
        print("OCI rollback failed")
        return int(ExitCode.ROLLBACK_FAILED)
    except (CompatibilityProbeError, LiveProbePrerequisiteError):
        _operation_failed("OCI_CERTIFICATE_PROFILE_INCOMPATIBLE")
        print("OCI_CERTIFICATE_PROFILE_INCOMPATIBLE")
        return int(ExitCode.OCI_CERTIFICATE_PROFILE_INCOMPATIBLE)
    except (
        OciAuthenticationError,
        OciCertificateError,
        ReconciliationError,
        PublicationServiceError,
    ):
        _operation_failed("OCI_IMPORT_FAILED")
        print("OCI publication failed")
        return int(ExitCode.OCI_IMPORT_FAILED)
    return int(ExitCode.CONFIGURATION_INVALID)


def _run_mutating_command(command: str, args: argparse.Namespace) -> int:
    """Dispatch a command only while the host-local publisher lock is held."""
    if command == "publish":
        return _publish(args.config, args.certificate_id, OperationType.PUBLISH)
    if command == "reconcile":
        return _publish(args.config, args.certificate_id, OperationType.RECONCILE)
    if command == "renew":
        return _renew(
            args.config,
            args.certificate_id,
            force_acme_renewal=bool(getattr(args, "force_acme_renewal", False)),
        )
    if command == "bootstrap":
        return _bootstrap(args.config, args.certificate_id)
    if command == "rollback":
        return _rollback(args.config, args.certificate_id)
    if command == "retention":
        return _retention(args.config, args.certificate_id)
    if command == "audit":
        return _audit(args.config, args.certificate_id)
    return int(ExitCode.CONFIGURATION_INVALID)


if __name__ == "__main__":
    raise SystemExit(main())
