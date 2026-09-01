# Scope and supported topology

The publisher manages ACME HTTP-01 issuance, local certificate lineages and OCI
Certificates. It never creates, reads, updates or associates Load Balancer
resources. DNS and every Load Balancer/listener association are external
operator or IaC responsibilities.

Each certificate is defined independently in
`/etc/oci-acme-publisher/certificates/<domain>.yaml`; shared, non-certificate
settings are in `/etc/oci-acme-publisher/settings.yaml`. The service loads the
directory atomically at each execution. Adding or removing a certificate file,
then restarting the HTTP-01 responder, is the only service-side configuration
operation required.

HTTP-01 preflight resolves the configured certificate DNS names and sends a
direct HTTP request to every resolved global address. It does not contain a
Load Balancer address, OCID, target, listener or certificate association.

## Recommended HTTP-01 routing through a Load Balancer

For a public application, keep the DNS name pointed at the public Load
Balancer. The publisher VM does not need a public IP address and does not need
to receive normal application traffic. Configure the Load Balancer to route
the ACME path to the restricted responder and retain the normal production
backends for all other traffic:

```text
DNS: jamon.enricopesce.it -> public Load Balancer IP

HTTP  :80
  /.well-known/acme-challenge/*  -> OCI ACME HTTP-01 responder VM
  all other paths                -> application backend or HTTPS redirect

HTTPS :443
  all paths                      -> production application backends
```

The ACME path rule must take precedence over a catch-all rule or an HTTP to
HTTPS redirect. The responder must be reachable from the Load Balancer on its
configured backend port, and public TCP/80 traffic for every certificate SAN
must reach it without a redirect. The preflight deliberately connects directly
to every public A and AAAA address resolved for each configured name; a single
unhealthy address causes failure under the default policy.

The responder exposes only these GET endpoints on its configured bind address
and port:

- `/.well-known/acme-challenge/<token>` for configured hostnames and valid
  ACME tokens;
- `/healthz` and `/readyz` for service health checks.

All other paths are unmatched. Restrict health-check access to the Load
Balancer or private network where possible; they are operational endpoints,
not application routes.

The responder should remain available while issuance or renewal can run. It
does not need to serve HTTPS traffic. ACME HTTP-01 validation follows the DNS
answer, so assigning a separate public IP directly to the VM does not help
while the domain continues to resolve to the Load Balancer. A DNS-01 design
would remove the port-80 requirement, but it is intentionally outside this
HTTP-01-only project and would require a separate DNS credential boundary.

## Publication boundary and operational impact

The publisher obtains and validates certificate material, uploads an OCI
certificate version, verifies the public bundle, and makes the matching
version CURRENT. It can also audit public TLS endpoints, roll back to an
eligible OCI version, and schedule deletion of old deprecated versions.

It never changes the Load Balancer configuration or its certificate/SNI
association. However, when an existing listener consumes an OCI Certificate,
making a new version CURRENT can change the certificate served to clients.
Treat production publication, automatic rollback, and retention as
security-relevant changes. Begin with audit mode `observe`; enable audit
enforcement or automatic rollback only after a full staging qualification and
an explicit operational review.

## Certificate names: SAN supported; wildcards unsupported

One certificate set may contain multiple exact DNS names in `domains`. The
first name must equal `common_name`; all names are encoded directly into the
CSR and the issued certificate's DNS SAN list must exactly match the
configured list. A domain may belong to only one certificate set. For example:

```yaml
certificates:
  - id: public-sites
    webroot_id: public-sites
    common_name: oci.example.com
    domains: [oci.example.com, app.example.com, www.example.com]
    # Remaining required certificate settings omitted.
```

Wildcard names, for example `*.example.com`, are not supported and are
rejected during configuration validation. This publisher uses ACME HTTP-01;
Let's Encrypt requires DNS-01 for wildcard issuance. Supporting wildcards
would require a separate, explicitly designed DNS-01 workflow and credential
boundary, rather than a configuration-only change.

Publishing a correct certificate does not configure its consumer. The operator
or IaC must associate the matching OCI Certificate with each HTTPS listener,
or attach the one multi-SAN certificate to an SNI-capable listener. The
publisher does not make or verify those listener associations; configure audit
endpoints for every public hostname to detect a consumer serving a different
certificate.
