"""Process exit codes defined by the product contract."""

from enum import IntEnum


class ExitCode(IntEnum):
    """Stable exit codes exposed by the command line interface."""

    SUCCESS = 0
    CONFIGURATION_INVALID = 2
    HTTP01_PREFLIGHT_FAILED = 3
    ACME_FAILED = 4
    X509_VALIDATION_FAILED = 5
    OCI_IMPORT_FAILED = 6
    OCI_PROMOTION_FAILED = 7
    AUDIT_ENFORCE_FAILED = 8
    ROLLBACK_FAILED = 9
    RETENTION_STRICT_FAILED = 10
    OCI_CERTIFICATE_PROFILE_INCOMPATIBLE = 11
    LINEAGE_DRIFT = 12
    LOCKED_OR_TEMPORARY_FAILURE = 75
