# ADR 0002: accepted OCI SDK dependency-audit exception for release 1.0

The OCI SDK currently constrains `cryptography` below `50.0.0`, which prevents
use of the version fixing `PYSEC-2026-3552`. The project uses the highest
compatible release, `cryptography 49.0.0`, together with `pyOpenSSL 26.4.0`.
The SBOM/audit toolchain permits an explicit safe `lxml` pin, so it is pinned to
`6.1.1` and is no longer an exception.

## Decision

For release 1.0, `PYSEC-2026-3552` is an explicitly accepted, narrowly scoped
release risk. `make quality` runs `pip-audit` with this vulnerability identifier
as its sole exception; `make audit` remains the strict, unsuppressed audit and
therefore continues to expose the finding.

This decision does not accept new findings or a different affected package.
Upgrade the OCI SDK as soon as it permits `cryptography >=50.0.0`, remove the
exception from the release audit and retire this ADR. Reassess the exception at
every dependency refresh and before each subsequent minor or major release.
