# Compatibility Gate (Gate 0)

This gate qualifies the certificate request shape and publication lifecycle
against OCI Certificates. It is not a
mock test and it never modifies a Load Balancer. Until the live run below has
passed in the target tenancy, compatibility is **not verified** and the product
must not be declared production-ready.

## Preconditions

Prepare a disposable OCI test compartment/tenancy, a non-production DNS name,
an imported-certificate OCID created only for this test, and a test Load
Balancer already associated manually with that OCID. The HTTP-01 route must
already forward public port 80 to the responder. Do not use a production OCID,
domain, certificate, or Load Balancer.

Record the tenancy/compartment OCIDs, certificate OCID, test domain, UTC start
time, OCI CLI/SDK version, and the issuer selected by the ACME server. Keep the output
and OCI request IDs with the release evidence; do not retain private keys or
full PEM in the report.

## Procedure

1. Use Let's Encrypt staging and issue a certificate with the same identifier
   count, key family, key size, and SAN shape planned for production. The first
   domain must be the immutable Common Name. The literal names and CA trust
   chain need not match production.
2. Run `oci-acme-publisher compatibility-probe --config /etc/oci-acme-publisher/oci-acme-publisher.yaml --certificate-id <test-id> --offline`.
   Record the leaf and root fingerprints, chain size, subject, Common Name,
   country-code presence, and algorithm family. This validates the local key,
   root-pinned complete chain, and configured country policy.
3. Run `bootstrap` first in the dedicated tenancy to create the disposable
   imported-certificate OCID. Associate that OCID manually to the test listener.
   Then run `compatibility-probe --live`; it issues a second equivalent
   certificate and imports it as a second version of that same OCID. The
   publisher must create it in `PENDING` and record its version number and
   request ID.
4. Retrieve the `PENDING` public bundle by version number and verify its
   fingerprint, Common Name, SANs, and validity against the local material.
   Promote it through the separate `CURRENT` operation, then retrieve `CURRENT`
   and verify the same fingerprint again.
5. With the pre-existing manual test Load Balancer association, observe a TLS
   endpoint until it presents the promoted `CURRENT` fingerprint. Record the
   endpoint, observations, and propagation time. The publisher must make no
   Load Balancer API calls.
6. Promote the previous still-valid version, retrieve `CURRENT`, and verify
   that both OCI and the TLS endpoint return its fingerprint. This is the
   rollback proof.

## Temporary responder switch for the same hostname

When the staging and production tests use the same hostname, the responder can
map that host to only one confined webroot at a time. Before the live command,
the operator must make the staging webroot active locally; this does **not**
modify any OCI Load Balancer, listener, routing rule, or DNS record.

```bash
sudo systemctl stop oci-acme-renew.timer
sudo install -m 0640 -o oci-acme-publisher -g oci-acme-challenge \
  /etc/oci-acme-publisher/config.staging-gate0.yaml \
  /etc/oci-acme-publisher/config.yaml
sudo systemctl restart oci-acme-http01.service
curl -fsS http://10.0.0.147:8080/readyz

sudo -u oci-acme-publisher /opt/oci-acme-publisher/venv/bin/oci-acme-publisher \
  compatibility-probe --config /etc/oci-acme-publisher/config.staging-gate0.yaml \
  --certificate-id oci-enricopesce-it-staging --live

sudo install -m 0640 -o oci-acme-publisher -g oci-acme-challenge \
  /etc/oci-acme-publisher/config.production.yaml \
  /etc/oci-acme-publisher/config.yaml
sudo systemctl restart oci-acme-http01.service
sudo systemctl start oci-acme-renew.timer
```

The `config.production.yaml` file in the procedure is a protected copy of the
installed standard configuration. Confirm responder readiness after both
switches. The operation takes only as long as the staging issuance and does not
alter an already issued production certificate.

## Required evidence and result

The report must name both version numbers and include these results: staging
issuance, stable Common Name, subject/country observation, complete root chain,
single algorithm family, initial import, second-version import, `PENDING`
verification, `CURRENT` promotion, public-bundle retrieval, manual consumer
propagation, and rollback. Mark every item pass or fail with its timestamp and
OCI request ID where applicable.

If OCI rejects the actual signed certificate profile for a requirement the
client cannot control (for example country code, complete root chain, algorithm
family, or immutable Common Name), record
`OCI_CERTIFICATE_PROFILE_INCOMPATIBLE`, preserve the error/request ID, and block
production qualification. Never change signed subject fields or the Common Name
to bypass a rejection; choose a compatible CA/profile, use another distribution
mechanism, or block the release.

`compatibility-probe --live` is restricted to `environment: staging`, an
explicit public test address, a configured TLS audit endpoint, and an existing
disposable OCID produced by `bootstrap`. The last precondition is necessary
because the operator must manually associate that known OCID before the probe
can verify the consumer. The probe imports and promotes a second version on the
same OCID, verifies the consumer, and rolls back. `--offline` is safe to run
against local lineage material but is insufficient to qualify OCI.

If `compatibility.enforce_documented_subject_country` is disabled only after a
successful target-tenancy qualification, `oci-acme-publisher status --json`
emits `DOCUMENTED_SUBJECT_COUNTRY_NOT_ENFORCED` in
`compatibility_warnings`; retain the corresponding Gate 0 report as evidence.

Set `compatibility.live_verified: true` only after the retained Gate 0 record
contains the second-version publication, TLS audit, rollback, and final TLS
audit evidence. The record qualifies only its CA-independent request shape.
Production chain trust remains a separate mandatory validation on every order.
This makes `status` report `LIVE_VERIFIED`; it is an explicit operator
attestation, not an inference from a single certificate state.
