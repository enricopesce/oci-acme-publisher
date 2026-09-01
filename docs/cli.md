# Operator CLI

`oci-acme` is the stable public command for operating OCI ACME Certificate
Publisher.  The older `oci-acme-publisher` command remains supported as a
compatibility alias for existing installations and systemd units.

All commands that read or change runtime configuration take a configuration
file or directory with `--config`.  A production installation uses the
following layout:

```text
/etc/oci-acme-publisher/
  settings.yaml
  certificates/
    example-com.yaml
  roots/
    isrg-root-x1.pem
```

`settings.yaml` contains only global, ACME, HTTP-01, OCI and monitoring
settings.  Each file in `certificates/` contains exactly one mapping named
`certificate`.  This separation makes certificate additions and reviews
independent, while configuration validation rejects an empty directory,
certificate data in `settings.yaml`, malformed documents, and duplicate or
invalid configuration values.

The established commands are:

```bash
oci-acme config init --config-dir /etc/oci-acme-publisher
oci-acme config add-certificate --config-dir /etc/oci-acme-publisher \
  --id example-com --domain example.com --region eu-frankfurt-1 \
  --compartment-ocid ocid1.compartment.oc1..example
oci-acme config validate --config /etc/oci-acme-publisher
oci-acme config show-effective --config /etc/oci-acme-publisher
oci-acme check --config /etc/oci-acme-publisher
oci-acme onboard --config /etc/oci-acme-publisher
oci-acme staging verify --config /etc/oci-acme-publisher-staging \
  --certificate-id example-com --evidence-output /etc/oci-acme-publisher/evidence/gate0-example-com.json
oci-acme diagnose --config /etc/oci-acme-publisher
oci-acme metrics collect --config /etc/oci-acme-publisher
oci-acme service status
oci-acme status --config /etc/oci-acme-publisher --json
oci-acme renew --config /etc/oci-acme-publisher
```

`config init` creates an intentionally incomplete **staging** skeleton and
refuses to overwrite a non-empty directory. Use `--dry-run` to show the files
it would create. It does not install packages, alter network routing, change
IAM, or issue a certificate. `check` and `onboard` are read-only: they run the
operational preflight and do not create ACME orders or change OCI resources.
`staging verify` is the explicit, staging-only mutating Gate 0 workflow; see
[staging qualification](staging-qualification.md) before using it.
See [observability and support](observability.md) for metrics, journal, and
support-bundle safety guarantees.
The automated and manually authorized test paths are described in
[quality gates](quality-gates.md).

Run `oci-acme --help` for the complete command list and `oci-acme --version`
to identify the installed release.  Mutating operations retain the existing
host-local lock and stable exit-code behaviour.
