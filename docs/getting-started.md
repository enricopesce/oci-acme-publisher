# Production quick start

This guide installs the service on **Oracle Linux 10 x86_64**. It assumes you
operate OCI infrastructure and have a signed RPM built or supplied by your
release process.

## 1. Prepare infrastructure

Before installing, complete these operator-owned tasks:

- Choose a public non-wildcard DNS name. HTTP-01 does not support wildcard
  certificates.
- Point public DNS to infrastructure that routes TCP/80 to the responder's
  configured address and port. Redirects and private addresses are rejected by
  default.
- Create or choose the OCI Certificate that will receive versions, and attach
  it to the required HTTPS listener/SNI association in your IaC.
- Give the instance dynamic group only the certificate permission described in
  [IAM policy](iam.md). Do not give this service Load Balancer or network
  permissions.
- Obtain the trusted CA root PEM and its SHA-256 fingerprint through your
  organization’s trust process. Do not copy the placeholder in the generated
  configuration.

## 2. Install a verified RPM

Import your organization’s RPM signing key, then verify and install the release
artifact. The private signing key must remain in the release system.

```bash
sudo rpm --import /path/to/release-signing-key.asc
rpmkeys --checksig /path/to/oci-acme-publisher-*.x86_64.rpm
sudo dnf install /path/to/oci-acme-publisher-*.x86_64.rpm
```

The package builds its Python runtime from bundled hash-locked wheels and does
not contact PyPI at installation time. ACME account registration, order
handling, HTTP-01 authorization, finalization, and certificate storage are
implemented inside the Python service. No separate certificate client or
executable is required. Configuration, native certificate generations, and
runtime state are not RPM-owned and survive upgrades/removal.

For subsequent signed upgrades, use the installed wrapper:

```bash
sudo oci-acme-upgrade --package /path/to/oci-acme-publisher-*.x86_64.rpm
```

## 3. Create staging configuration

Run initialization as root after installation; it creates files with the
restricted service-account ownership expected by systemd.

```bash
sudo oci-acme init
sudo mv /etc/oci-acme-publisher/certificates/example-com.yaml \
  /etc/oci-acme-publisher/certificates/example-com.yaml.disabled
sudo oci-acme config add-certificate --config-dir /etc/oci-acme-publisher \
  --id example-com --domain example.com --region eu-frankfurt-1 \
  --compartment-ocid ocid1.compartment.oc1..example
```

Edit `/etc/oci-acme-publisher/settings.yaml` and the certificate file. Set:

- a real ACME email and acceptance of the CA terms;
- protected absolute paths for the ACME account key and certificate generations;
- responder bind address reachable from your port-80 route;
- OCI region, compartment OCID, certificate OCID, and audit endpoint;
- the trusted root PEM path, SHA-256 pin, and permitted issuer name;
- the real domain/SAN list.

Keep `environment: staging` and Let’s Encrypt’s staging directory until the
full staging qualification is retained. Remove the disabled sample file before
validation so it is not loaded as an extra certificate.

## 4. Validate before issuance

```bash
sudo oci-acme config validate --config /etc/oci-acme-publisher
sudo oci-acme check --config /etc/oci-acme-publisher
sudo oci-acme service status
```

`check` is read-only. It checks local responder readiness, webroots, root pins,
clock, OCI read access, and synthetic public HTTP-01 routing. Fix every failure
before invoking a mutating command.

## 5. Qualify staging, then production

Follow [staging qualification](staging-qualification.md) with a disposable OCI
certificate and test listener. It writes evidence that production mutations
must match exactly. After review, record the immutable evidence path under
`compatibility.live_evidence_paths` in the production config and set
`compatibility.live_verified: true`.

Then change only the intended production settings: `environment: production`,
the production ACME directory, production domains/OCI certificate, and the
matching retained evidence. Run `oci-acme check` again before first production
`bootstrap` or `renew`.

## Day-two commands

```bash
sudo oci-acme status --config /etc/oci-acme-publisher --json
sudo oci-acme metrics collect --config /etc/oci-acme-publisher
sudo oci-acme diagnose --config /etc/oci-acme-publisher \
  --output /var/tmp/oci-acme-support.json
sudo oci-acme renew --config /etc/oci-acme-publisher
```

For failures, run `check`, inspect `oci-acme service status`, and create a
support bundle. Do not attach private keys, ACME account files, or raw
journal output to support requests.
