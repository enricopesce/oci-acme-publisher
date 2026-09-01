# Changelog

## 2.0.0

- Replace external certificate-client execution with an in-process Python ACME
  implementation for account registration, HTTP-01 orders and finalization.
- Add protected account-key handling and atomic, generation-based certificate
  storage with strict ownership, permissions and size validation.
- Introduce configuration schema v4 and remove all executable-specific fields.
- Correct Gate 0 reuse across staging and production trust chains by qualifying
  only the CA-independent request shape; retain mandatory production chain
  validation for every issuance.
- Add protected recovery provenance for the retained staging qualification and
  an interactive, passphrase-protected release-key bootstrap workflow.

## 1.0.0

- Declare the first production-stable release after live qualification of the
  standard and staging ACME profiles, OCI publication, TLS audit and rollback.
- Record `PYSEC-2026-3552` as the sole, accepted release-audit exception while
  the OCI SDK requires `cryptography <50`; retain a strict audit target for
  visibility.
- Add the final release checklist, including the outstanding real retention
  deletion evidence required by the operating policy.

## 0.1.0

- Initial project baseline.
- Align compatibility status and Prometheus Gate metric with the retained live
  qualification evidence.
- Recover stale `AUDIT_PENDING` state after a later independent audit succeeds.
- Persist bootstrap OCID/version/fingerprint transitions for crash recovery.
- Isolate audit and rollback failures in multi-certificate renewals and return
  their stable exit codes.
- Refresh OCI ETags and use UUID request IDs for every retention scheduling
  mutation.
- Recover an interrupted post-create bootstrap from its persisted OCID without
  creating a second OCI certificate.
- Emit best-effort, deduplicated notifications for isolated renewal failures.
- Emit deduplicated warning/critical expiry events from public local certificate
  metadata after successful renewals.
- Add fault-injection coverage for re-entry after an interrupted OCI PENDING
  upload, proving no duplicate version is created.
- Add fault-injection coverage for re-entry after OCI promotion has already
  completed, proving no duplicate mutation is issued.
- Add fault-injection coverage for re-entry after local validation and before
  OCI import, proving one and only one pending version is created.
- Run safe retention automatically after publication; retain CURRENT on any
  retention error and emit a deduplicated failure event.
- Make OCI optimistic concurrency fail-closed: `use_etag` cannot be disabled.
- Run configured observe-mode TLS audits automatically after publication without
  invalidating OCI CURRENT on an observation failure.
- Emit a deduplicated compatibility-not-verified event before each renewal
  attempt when live Gate 0 evidence has not been attested.
- Redact nested structured-log fields recursively and omit unsupported object
  representations to prevent sensitive diagnostic leakage.
- Make root-run administrative HTTP-01 preflight compatible with the
  responder's publisher-owner policy without weakening normal timer execution.
- Document and test multiple pre-existing Load Balancer addresses per
  certificate set, while retaining the no-Load-Balancer-control-plane boundary.
- Add a declared N:N topology of logical Load Balancer targets and certificate
  sets, used by HTTP-01 preflight and TLS audit without LB API access.
- Extend the explicit preflight command with pinned-root validation and an
  instance-principal, read-only OCI certificate access check before HTTP-01.
