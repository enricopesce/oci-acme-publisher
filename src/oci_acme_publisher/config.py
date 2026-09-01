"""Strict, bounded YAML configuration loading and validation."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path, PurePath
from typing import Annotated, Any, Literal

import idna
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .errors import ConfigurationError
from .models import AuditMode, Environment, KeyType

MAX_CONFIG_BYTES = 1_048_576
_CN_MAX_BYTES = 64
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class _NoDuplicateSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that treats duplicate mapping keys as an error."""


def _construct_mapping(
    loader: _NoDuplicateSafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)  # type: ignore[no-untyped-call]
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)  # type: ignore[no-untyped-call]
    return mapping


_NoDuplicateSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def normalize_domain(value: str) -> str:
    """Return a normalized DNS A-label or raise a safe configuration error."""
    candidate = value.strip().rstrip(".").lower()
    if not candidate or "_" in candidate or "*" in candidate:
        raise ValueError("must be a non-empty non-wildcard FQDN without underscores")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        is_ip_address = False
    else:
        is_ip_address = True
    if is_ip_address:
        raise ValueError("must not be an IP address")
    try:
        normalized = idna.encode(candidate, uts46=True, std3_rules=True).decode("ascii")
    except idna.IDNAError as error:
        raise ValueError("is not a valid IDNA domain") from error
    if len(normalized.encode("ascii")) > 253:
        raise ValueError("exceeds DNS maximum length")
    for label in normalized.split("."):
        if not 1 <= len(label.encode("ascii")) <= 63:
            raise ValueError("contains a label outside DNS length limits")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError("contains a label beginning or ending with a hyphen")
    return normalized


def _absolute_path(value: str) -> str:
    if not PurePath(value).is_absolute():
        raise ValueError("must be an absolute path")
    return value


class StrictModel(BaseModel):
    """Mandatory settings for every configuration model."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class GlobalConfig(StrictModel):
    environment: Environment
    state_dir: str
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    json_logging: bool = True
    max_parallel_certificates: Annotated[int, Field(ge=1, le=16)] = 1
    clock_skew_tolerance_seconds: Annotated[int, Field(ge=0, le=3600)] = 300

    _state_dir_absolute = field_validator("state_dir")(_absolute_path)

    @field_validator("environment", mode="before")
    @classmethod
    def yaml_environment(cls, value: object) -> object:
        return Environment(value) if isinstance(value, str) else value


class CompatibilityConfig(StrictModel):
    # This is an operator-attested release gate, set only with retained live evidence.
    live_verified: bool = False
    live_evidence_paths: tuple[str, ...] = ()
    enforce_documented_subject_country: bool = True
    require_complete_chain_to_root: bool = True
    reject_mixed_algorithm_chain: bool = True

    @field_validator("live_evidence_paths", mode="before")
    @classmethod
    def evidence_paths_from_yaml_are_immutable(cls, values: object) -> object:
        return tuple(values) if isinstance(values, list) else values

    _evidence_paths_absolute = field_validator("live_evidence_paths")(
        lambda values: tuple(_absolute_path(value) for value in values)
    )

    @model_validator(mode="after")
    def verified_requires_retained_evidence(self) -> CompatibilityConfig:
        if not self.live_verified and self.live_evidence_paths:
            raise ValueError("live_evidence_paths require live_verified")
        if len(set(self.live_evidence_paths)) != len(self.live_evidence_paths):
            raise ValueError("live_evidence_paths must be unique")
        return self


class AcmeConfig(StrictModel):
    email: str
    agree_to_terms: bool
    directory_url: str
    account_key_path: str
    certificates_dir: str
    operation_timeout_seconds: Annotated[int, Field(ge=30, le=7200)] = 1800
    renew_before_days: Annotated[int, Field(ge=1, le=90)] = 30
    rotate_private_key_on_renewal: bool = True
    preferred_profile: Literal["shortlived"] | None = None

    _paths_absolute = field_validator("account_key_path", "certificates_dir")(_absolute_path)

    @field_validator("email")
    @classmethod
    def email_is_present(cls, value: str) -> str:
        if not value or "@" not in value or any(char.isspace() for char in value):
            raise ValueError("must be a valid non-empty email address")
        return value

    @field_validator("directory_url")
    @classmethod
    def directory_is_https(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("must use HTTPS")
        return value


class ResponderConfig(StrictModel):
    bind_address: str
    bind_port: Annotated[int, Field(ge=1, le=65535)]
    health_path: Literal["/healthz"] = "/healthz"
    readiness_path: Literal["/readyz"] = "/readyz"
    max_request_body_bytes: Annotated[int, Field(ge=0, le=1024)] = 1024
    max_challenge_file_bytes: Annotated[int, Field(ge=1, le=4096)] = 4096
    max_concurrent_requests: Annotated[int, Field(ge=1, le=1024)] = 128
    request_timeout_seconds: Annotated[int, Field(ge=1, le=60)] = 5
    keepalive_timeout_seconds: Annotated[int, Field(ge=1, le=60)] = 5
    backlog: Annotated[int, Field(ge=1, le=1024)] = 128


class SelfCheckConfig(StrictModel):
    enabled: bool = True
    require_all_domains: bool = True
    require_all_addresses: bool = True
    allow_redirects: bool = False
    reject_non_global_addresses: bool = True
    connect_timeout_seconds: Annotated[int, Field(ge=1, le=60)] = 3
    response_timeout_seconds: Annotated[int, Field(ge=1, le=60)] = 5
    total_timeout_seconds: Annotated[int, Field(ge=1, le=600)] = 90


class Http01Config(StrictModel):
    webroot_base: str
    responder: ResponderConfig
    self_check: SelfCheckConfig

    _webroot_absolute = field_validator("webroot_base")(_absolute_path)


class OciConfig(StrictModel):
    authentication: Literal["instance_principal"]
    connect_timeout_seconds: Annotated[int, Field(ge=1, le=60)] = 10
    read_timeout_seconds: Annotated[int, Field(ge=1, le=300)] = 60
    max_read_attempts: Annotated[int, Field(ge=1, le=30)] = 5
    mutation_reconciliation_attempts: Annotated[int, Field(ge=1, le=10)] = 5
    operation_timeout_seconds: Annotated[int, Field(ge=30, le=3600)] = 1200
    # OCI certificate mutations must use optimistic concurrency whenever available.
    use_etag: Literal[True] = True


class NotificationsConfig(StrictModel):
    enabled: bool = False
    provider: Literal["slack", "webhook"] = "slack"
    credential_ref: str | None = None
    allowed_hosts: tuple[str, ...] = ()
    minimum_repeat_interval_minutes: Annotated[int, Field(ge=1, le=1440)] = 60
    connect_timeout_seconds: Annotated[int, Field(ge=1, le=60)] = 5
    total_timeout_seconds: Annotated[int, Field(ge=1, le=120)] = 10

    @field_validator("allowed_hosts", mode="before")
    @classmethod
    def hosts_from_yaml_are_immutable(cls, values: object) -> object:
        return tuple(values) if isinstance(values, list) else values

    @model_validator(mode="after")
    def enabled_notifier_requires_credential_and_allowlist(self) -> NotificationsConfig:
        if not self.enabled:
            return self
        if self.credential_ref is None or not self.credential_ref.startswith("systemd-credential:"):
            raise ValueError("enabled notifications require a systemd credential reference")
        if not self.allowed_hosts:
            raise ValueError("enabled notifications require an HTTPS host allowlist")
        return self


class MetricsTextfileConfig(StrictModel):
    """Optional Prometheus node-exporter textfile target."""

    enabled: bool = False
    path: str = "/var/lib/oci-acme-publisher/metrics/oci_acme.prom"

    _path_absolute = field_validator("path")(_absolute_path)


class MonitoringConfig(StrictModel):
    """Bounded operational monitoring policy with no remote credentials."""

    warning_days: Annotated[int, Field(ge=1, le=3650)] = 20
    critical_days: Annotated[int, Field(ge=0, le=3650)] = 7
    metrics_textfile: MetricsTextfileConfig = MetricsTextfileConfig()

    @model_validator(mode="after")
    def thresholds_are_ordered(self) -> MonitoringConfig:
        if self.critical_days > self.warning_days:
            raise ValueError("critical_days must not exceed warning_days")
        return self


class KeyConfig(StrictModel):
    type: KeyType
    rsa_size: Literal[2048, 4096] | None = None
    ecdsa_curve: Literal["secp256r1", "secp384r1"] | None = None

    @field_validator("type", mode="before")
    @classmethod
    def yaml_key_type(cls, value: object) -> object:
        return KeyType(value) if isinstance(value, str) else value

    @model_validator(mode="after")
    def family_parameters_match(self) -> KeyConfig:
        if self.type is KeyType.RSA and self.rsa_size is None:
            raise ValueError("rsa_size is required for RSA")
        if self.type is KeyType.RSA and self.ecdsa_curve is not None:
            raise ValueError("ecdsa_curve is forbidden for RSA")
        if self.type is KeyType.ECDSA and self.ecdsa_curve is None:
            raise ValueError("ecdsa_curve is required for ECDSA")
        if self.type is KeyType.ECDSA and self.rsa_size is not None:
            raise ValueError("rsa_size is forbidden for ECDSA")
        return self


class ChainConfig(StrictModel):
    root_pem_path: str
    allowed_root_sha256: tuple[str, ...]
    allowed_issuer_common_names: tuple[str, ...]

    _root_path_absolute = field_validator("root_pem_path")(_absolute_path)

    @field_validator("allowed_root_sha256", "allowed_issuer_common_names", mode="before")
    @classmethod
    def yaml_lists_are_immutable_tuples(cls, values: object) -> object:
        return tuple(values) if isinstance(values, list) else values

    @field_validator("allowed_root_sha256")
    @classmethod
    def valid_root_hashes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values or any(_SHA256_HEX.fullmatch(value) is None for value in values):
            raise ValueError("must contain lowercase SHA-256 fingerprints")
        return values


class CertificateOciConfig(StrictModel):
    region: str
    compartment_ocid: str
    certificate_ocid: str | None = None
    certificate_name: str


class AuditEndpoint(StrictModel):
    hostname: str
    port: Annotated[int, Field(ge=1, le=65535)]

    _hostname_normalized = field_validator("hostname")(normalize_domain)


class AuditConfig(StrictModel):
    mode: AuditMode = AuditMode.OBSERVE
    automatic_rollback_on_failure: bool = False
    propagation_timeout_seconds: Annotated[int, Field(ge=0, le=3600)] = 600
    retry_interval_seconds: Annotated[int, Field(ge=1, le=300)] = 15
    require_all_addresses: bool = True
    reject_non_global_addresses: bool = True
    endpoints: tuple[AuditEndpoint, ...] = ()

    @field_validator("mode", mode="before")
    @classmethod
    def yaml_audit_mode(cls, value: object) -> object:
        return AuditMode(value) if isinstance(value, str) else value

    @field_validator("endpoints", mode="before")
    @classmethod
    def endpoint_list_is_immutable(cls, values: object) -> object:
        return tuple(values) if isinstance(values, list) else values

    @model_validator(mode="after")
    def automatic_rollback_requires_enforcement(self) -> AuditConfig:
        if self.automatic_rollback_on_failure and self.mode is not AuditMode.ENFORCE:
            raise ValueError("automatic_rollback_on_failure requires audit mode enforce")
        return self


class RetentionConfig(StrictModel):
    enabled: bool = True
    keep_deprecated_versions: Annotated[int, Field(ge=1, le=100)] = 2
    minimum_age_days: Annotated[int, Field(ge=0, le=3650)] = 30
    deletion_delay_days: Annotated[int, Field(ge=1, le=3650)] = 30


class CertificateConfig(StrictModel):
    id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")]
    webroot_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")]
    common_name: str
    domains: tuple[str, ...]
    key: KeyConfig
    chain: ChainConfig
    oci: CertificateOciConfig
    audit: AuditConfig = AuditConfig()
    retention: RetentionConfig = RetentionConfig()

    _common_name_normalized = field_validator("common_name")(normalize_domain)

    @field_validator("domains", mode="before")
    @classmethod
    def domains_from_yaml_are_normalized(cls, values: object) -> object:
        if not isinstance(values, list):
            return values
        if not all(isinstance(value, str) for value in values):
            raise ValueError("must contain only domain strings")
        return tuple(normalize_domain(value) for value in values)

    @model_validator(mode="after")
    def certificate_invariants(self) -> CertificateConfig:
        if not self.domains:
            raise ValueError("domains must not be empty")
        if len(set(self.domains)) != len(self.domains):
            raise ValueError("domains must be unique within a certificate")
        if self.domains[0] != self.common_name:
            raise ValueError("common_name must be the first domain")
        if len(self.common_name.encode("utf-8")) > _CN_MAX_BYTES:
            raise ValueError("common_name exceeds 64 bytes")
        if self.oci.certificate_ocid is not None and not self.oci.certificate_ocid.startswith(
            "ocid1.certificate."
        ):
            raise ValueError("certificate_ocid is not an OCI certificate OCID")
        if self.audit.mode is not AuditMode.DISABLED and not self.audit.endpoints:
            raise ValueError("audit endpoints are required unless audit mode is disabled")
        return self


class AppConfig(StrictModel):
    schema_version: Literal[4]
    global_: GlobalConfig = Field(alias="global")
    compatibility: CompatibilityConfig
    acme: AcmeConfig
    http01: Http01Config
    oci: OciConfig
    notifications: NotificationsConfig = NotificationsConfig()
    monitoring: MonitoringConfig = MonitoringConfig()
    certificates: tuple[CertificateConfig, ...]

    @field_validator("certificates", mode="before")
    @classmethod
    def certificate_list_is_immutable(cls, values: object) -> object:
        return tuple(values) if isinstance(values, list) else values

    @model_validator(mode="after")
    def cross_field_invariants(self) -> AppConfig:
        if not self.certificates:
            raise ValueError("certificates must not be empty")
        ids = [certificate.id for certificate in self.certificates]
        if len(set(ids)) != len(ids):
            raise ValueError("certificate ids must be globally unique")
        webroots = [certificate.webroot_id for certificate in self.certificates]
        if len(set(webroots)) != len(webroots):
            raise ValueError("webroot_id must be globally unique")
        seen_domains: set[str] = set()
        seen_ocids: dict[str, CertificateConfig] = {}
        for certificate in self.certificates:
            duplicate = seen_domains.intersection(certificate.domains)
            if duplicate:
                raise ValueError(
                    f"domain configured by multiple certificate sets: {sorted(duplicate)[0]}"
                )
            seen_domains.update(certificate.domains)
            ocid = certificate.oci.certificate_ocid
            if ocid is not None:
                previous = seen_ocids.get(ocid)
                if previous is not None and previous.common_name != certificate.common_name:
                    raise ValueError("certificate OCID cannot have incompatible common names")
                seen_ocids[ocid] = certificate
        if (
            self.global_.environment is Environment.PRODUCTION
            and "staging" in self.acme.directory_url
        ):
            raise ValueError("production environment cannot use an ACME staging directory")
        if (
            self.global_.environment is Environment.STAGING
            and "staging" not in self.acme.directory_url
        ):
            raise ValueError("staging environment must use an ACME staging directory")
        if self.http01.webroot_base.startswith(self.acme.certificates_dir.rstrip("/") + "/"):
            raise ValueError("webroot_base must not be inside ACME certificates_dir")
        return self


def load_config(path: str) -> AppConfig:
    """Read one legacy file or a directory of independent certificate files."""
    source = Path(path)
    if source.is_dir():
        return _load_config_directory(source)
    parsed = _load_yaml_file(source)
    return _validate_config(parsed)


def _load_config_directory(directory: Path) -> AppConfig:
    """Compose immutable service settings and one YAML document per certificate."""
    settings = _load_yaml_file(directory / "settings.yaml")
    if "certificates" in settings or "certificate" in settings:
        raise ConfigurationError("settings.yaml must not define certificates")
    certificate_files = sorted((directory / "certificates").glob("*.yaml"))
    if not certificate_files:
        raise ConfigurationError("configuration directory contains no certificate files")
    certificates: list[object] = []
    for certificate_file in certificate_files:
        document = _load_yaml_file(certificate_file)
        if set(document) != {"certificate"} or not isinstance(document["certificate"], dict):
            raise ConfigurationError(
                "certificate files must contain exactly one certificate mapping"
            )
        certificates.append(document["certificate"])
    settings["certificates"] = certificates
    return _validate_config(settings)


def _load_yaml_file(path: Path) -> dict[str, object]:
    """Read one bounded YAML mapping without interpolation or custom tags."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ConfigurationError("unable to read configuration file") from error
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigurationError("configuration file exceeds maximum size")
    try:
        # The loader subclasses SafeLoader and adds only duplicate-key rejection.
        parsed: Any = yaml.load(raw, Loader=_NoDuplicateSafeLoader)  # noqa: S506
    except yaml.YAMLError as error:
        raise ConfigurationError("invalid YAML configuration") from error
    if not isinstance(parsed, dict):
        raise ConfigurationError("configuration root must be a mapping")
    return parsed


def _validate_config(parsed: dict[str, object]) -> AppConfig:
    try:
        return AppConfig.model_validate(parsed)
    except ValidationError as error:
        locations = [".".join(str(item) for item in entry["loc"]) for entry in error.errors()]
        raise ConfigurationError(f"invalid configuration fields: {', '.join(locations)}") from error
