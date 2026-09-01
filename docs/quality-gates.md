# Quality gates

Every pull request runs the Python 3.11/3.12 unit, lint, formatting, type,
dependency-audit, and configuration-schema gates. An Oracle Linux x86_64
self-hosted worker also builds the RPM and installs its payload into an
isolated RPM database with scriptlets disabled.

Run the release-equivalent gate on that Oracle Linux worker:

```bash
scripts/verify-release.sh
```

The payload test deliberately verifies files and dependencies without executing
RPM scriptlets on the build host. Full systemd installation/upgrade validation
belongs in a disposable Oracle Linux VM and is not run against a developer
host.

The OCI staging integration gate is manually authorized because it creates a
staging certificate version and must use an operator-provided disposable OCID:

```bash
scripts/run-staging-integration.sh \
  --config /etc/oci-acme-publisher-staging \
  --certificate-id example-com \
  --evidence-output /etc/oci-acme-publisher/evidence/gate0-example-com.json
```

It runs the read-only preflight first, then the already restricted staging
verification. It never changes DNS, IAM, firewall rules, or Load Balancer
configuration.
