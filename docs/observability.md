# Observability and support

The service writes structured, redacted JSON events to the system journal. It
does not emit certificate PEMs, private keys, ACME account material, or
systemd credential values.

Read-only operator commands:

```bash
oci-acme status --config /etc/oci-acme-publisher --json
oci-acme metrics collect --config /etc/oci-acme-publisher
oci-acme service status
oci-acme diagnose --config /etc/oci-acme-publisher \
  --output /var/tmp/oci-acme-support-$(date -u +%Y%m%dT%H%M%SZ).json
```

`metrics collect` never creates the SQLite state database. When state is
missing or unreadable it emits `oci_acme_state_available 0`; alert on that only
after accounting for a new installation. When configured, normal renewal runs
also atomically update the Prometheus textfile.

The support bundle is write-once, mode `0640`, and contains only application
version, safe configuration diagnostics, safe certificate status, and a small
set of systemd state fields. It explicitly excludes configuration values,
credentials, journal entries, PEMs/private keys, and ACME account material.
Review it before sharing.
