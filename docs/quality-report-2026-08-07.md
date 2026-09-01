# Quality and verification report — 2026-08-07

## Executed successfully

| Check | Result |
| --- | --- |
| Unit, security and fault-injection tests | 263 passed |
| Coverage | 90% (configured threshold: 90%) |
| Ruff | passed |
| Mypy strict | passed for all 35 source files |
| Formatter | passed |
| Wheel and sdist | built successfully |
| SBOM | generated as `sbom.json` from the locked environment |
| Static Load Balancer boundary | passed: application package imports no `oci.load_balancer` module |
| Systemd unit verification | accepted for both installed OCI ACME units |
| Systemd hardening | responder `3.9 OK`; publisher `4.0 OK` |
| Installation verifier | passed as root against the protected installed configuration |
| Production responder/timer | both active after hardening deployment; a post-deployment scheduled renewal completed without publishing a change |
| Production certificate state | OCI version 2 is CURRENT; local and OCI fingerprints match; no pending publication |
| Post-restoration application audit | `AUDIT_SUCCESS` at `2026-08-07T16:44:39Z`; the public listener serves OCI CURRENT |
| Bootstrap recovery persistence | verified by unit test: operation, created OCID, confirmed version and fingerprint are persisted without certificate material |
| Retention concurrency | verified by unit test: each scheduled deletion reads a fresh OCI ETag and uses a distinct UUID request ID |
| Bootstrap crash recovery | verified by unit test: a persisted post-create OCID is revalidated and completed without a second OCI create call |
| Renewal failure notifications | verified by unit tests: classified, redacted, deduplicated and non-blocking for subsequent certificate sets |
| Expiry threshold notification | verified by unit tests: public-leaf warning/critical events follow the configured monitoring thresholds |
| Compatibility notification | verified by unit test: unverified live compatibility emits a deduplicated pre-renewal alert |
| OCI pending crash re-entry | verified by fault injection: persisted `PENDING` is promoted and no duplicate version upload occurs |
| OCI verified-PENDING crash re-entry | verified by fault injection: the verified candidate is promoted once after restart without reimport |
| OCI promotion crash re-entry | verified by fault injection: already-current version is confirmed without another upload or promotion |
| Pre-import crash re-entry | verified by fault injection: validated local lineage results in exactly one PENDING import and promotion on re-entry |
| Post-publication retention | verified by unit tests: safe retention runs after publication and failure remains non-blocking |
| OCI optimistic concurrency | verified by unit test: configuration rejects attempts to disable ETag protection |
| Automatic TLS audit | verified by unit tests: observe audits run post-publication non-blockingly; enforce retains controlled rollback behavior |
| Audit crash re-entry | verified by fault injection: a successful later audit closes only stale `AUDIT_PENDING` operations |
| Retention crash re-entry | verified by fault injection: a version already scheduled for deletion is never scheduled twice after restart |
| Operational preflight | verified by unit tests: synchronized clock, responder readiness, webroots, pinned trust roots, read-only OCI certificate access and HTTP-01 routing are all required without mutation |
| Administrative HTTP-01 preflight | verified by unit test: a root-run synthetic challenge is safely owned by the restricted publisher user before the responder reads it |
| DNS-only HTTP-01 preflight | verified by unit tests: every configured domain is resolved and checked directly without any Load Balancer object or address in the configuration |
| Structured log redaction | verified by unit tests: PEM and HTTPS URLs are redacted recursively, including nested event fields |
| Production operational preflight | passed: root pin, OCI read-only access, responder readiness and synthetic HTTP-01 route through public DNS |

The systemd verification command also reported an unrelated warning from the
distribution-provided `iscsi-init.service`. It did not report an error in an
OCI ACME unit.

## Live evidence obtained

- Let’s Encrypt production issuance and forced renewal completed for the
  standard profile; OCI version 2 was promoted and observed through TLS.
- Rollback to version 1 and restoration of version 2 were verified through OCI
  and the public TLS endpoint.
- Let’s Encrypt staging Gate 0 completed on its dedicated OCID: version 2 was
  published and audited through the test listener, then rolled back to version
  1 and audited again through TLS.
- OCI’s initial bundle read returned eventual-consistency `NotAuthorizedOrNotFound`;
  bounded reconciliation later confirmed the same version without creating a
  second OCID.
- The deployed metrics snapshot reports `oci_acme_compatibility_gate 1`, aligned
  with the retained live Gate 0 evidence and structured `LIVE_VERIFIED` status.
- The administrative production preflight passed after assigning root-created
  synthetic challenge files to the restricted publisher account. It confirmed
  OCI CURRENT version 2, matching local/OCI fingerprints and no pending
  publication.

See the dedicated [staging Gate 0 report](compatibility-gate-report-staging-2026-08-07.md)
and [standard-profile report](compatibility-gate-report-standard-2026-08-07.md)
for timestamps and certificate evidence.

## Remaining planned execution

- Retention deletion remains intentionally unexecuted until an eligible version
  reaches its configured minimum age; a safe no-deletion retention run has been
  verified.

## Deliberately failing dependency audit

`pip-audit` remains enabled and reports `PYSEC-2026-3552` in `cryptography
49.0.0`; version `50.0.0` contains the available fix. Oracle’s currently
pinned OCI SDK dependency constraint prevents the required upgrade. The finding
is not suppressed; see
[ADR 0002](adr/0002-dependency-audit-exceptions.md).
