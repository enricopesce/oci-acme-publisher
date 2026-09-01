# Release checklist 1.0

## Preconditions

- [ ] The retention policy has deleted one eligible `DEPRECATED` OCI version
  in staging or production, with operation ID, OCI request ID and post-delete
  reconciliation retained as evidence.
- [ ] The operator has reviewed and accepted ADR 0002 for this release.
- [ ] `compatibility.live_verified` is present for each enabled certificate set.

## Build and quality gate

Run from a clean, locked environment:

```bash
uv sync --all-extras --locked
make quality
make audit
```

`make audit` is expected to report only `PYSEC-2026-3552` as documented in ADR
0002. Any additional finding blocks the release.

- [ ] Tests and 90% branch coverage pass.
- [ ] Ruff, formatter and mypy strict pass.
- [ ] `make quality` creates wheel, sdist and SBOM.
- [ ] Strict audit contains no finding other than the accepted identifier.

## Operational gate

- [ ] `scripts/verify-installation.sh` passes against the protected production
  configuration.
- [ ] `oci-acme-publisher preflight --config /etc/oci-acme-publisher` passes.
- [ ] The responder is active and the renewal timer is enabled.
- [ ] `status --json` shows no pending publication and expected OCI CURRENT
  fingerprints.
- [ ] The release artifacts, SBOM, audit output and Gate 0 reports are stored
  with the release record.

## Release

- [ ] Tag the verified commit as `v1.0.0`.
- [ ] Publish the wheel and sdist from that commit.
- [ ] Record the deployed artifact hash and rollback target.
