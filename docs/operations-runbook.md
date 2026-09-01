# Operations runbook

Install a built wheel on Oracle Linux as root:

```bash
scripts/install-oracle-linux.sh \
  --wheel dist/oci_acme_certificate_publisher-1.0.0-py3-none-any.whl \
  --config /secure/path/config-directory
```

Before enabling the timer, configure the permanent port-80 route and the
HTTPS listener's existing certificate OCID outside this product. Then run:

```bash
scripts/verify-installation.sh
systemctl status oci-acme-http01.service oci-acme-renew.timer
```

### Certificate-name limitation

The `domains` list supports one certificate with multiple exact DNS SANs; its
first entry must be the `common_name`. Wildcards are not supported because this
product implements HTTP-01 only, while wildcard issuance requires DNS-01.

The publisher does not associate OCI Certificates with Load Balancer listeners.
After issuing or rotating a certificate, make the matching listener/SNI
association in the operator-owned IaC. If multiple hostnames use one listener,
attach a certificate whose SANs cover every hostname, or configure separate SNI
certificate associations. Add an audit endpoint for each public hostname and
verify client hostname validation after the change.

Before a first issuance, or after an infrastructure/authentication change, run
the read-only operational preflight:

```bash
oci-acme check --config /etc/oci-acme-publisher
```

It requires a synchronized system clock, checks the local responder readiness
endpoint and every configured webroot, then checks each configured trust root
against its SHA-256 pin. It initializes the instance-principal OCI client and
reads the configured certificate when an OCID exists, then performs the
synthetic HTTP-01 routing check. It neither creates ACME orders nor changes OCI
resources.

Run recovery without a new ACME order:

```bash
oci-acme reconcile --config /etc/oci-acme-publisher --certificate-id main-site
```

The uninstall script stops and removes units but intentionally preserves all
certificate lineage and state directories. Back them up only with encryption.

When notifications are enabled, each successful timer run also reads only the
public local leaf certificate. It emits `CERTIFICATE_EXPIRY_WARNING` at or below
`monitoring.warning_days` and `CERTIFICATE_EXPIRY_CRITICAL` at or below
`monitoring.critical_days`. Events use the same durable cooldown as failure
notifications; a notifier outage never changes the renewal result.
