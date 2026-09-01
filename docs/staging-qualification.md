# Staging qualification

Production certificate mutation is blocked unless a retained staging Gate 0
record matches the production certificate's CA-independent request shape: key
configuration, identifier count, Common Name placement, and wildcard usage.
One record may qualify multiple certificate sets with the same shape.

Issuer names and root fingerprints deliberately do not participate in this
match because staging and production use different trust chains. Every
production issuance still fails closed unless its actual chain matches the
configured issuer allowlist and pinned production root.

1. Use a disposable OCI certificate, staging DNS name, and manually associated
   test TLS consumer. The publisher must not manage the Load Balancer.
2. Bootstrap the disposable certificate and complete the manual listener
   association described in [the compatibility gate](compatibility-gate.md).
3. Run the live staging proof and write a new evidence file:

   ```bash
   sudo install -d -m 0750 /etc/oci-acme-publisher/evidence
   sudo oci-acme staging verify --config /etc/oci-acme-publisher-staging \
     --certificate-id example-com --evidence-output /etc/oci-acme-publisher/evidence/gate0-example-com.json
   ```

4. Review the immutable JSON record. It contains no PEM or private key, but
   retains OCI version numbers, public fingerprints, the qualified profile, and
   the rollback proof.
5. In the production configuration, set `compatibility.live_verified: true`
   and list the evidence file in `compatibility.live_evidence_paths`. Keep the
   file non-group/non-world-writable; production `check`, `bootstrap`, `renew`,
   `publish`, and `reconcile` reject missing, unsafe, malformed, or mismatched
   evidence.

Repeat qualification if the identifier count, Common Name placement, wildcard
usage, or key type/size changes. A production issuer or root-policy change does
not reuse trust blindly: the newly issued chain must still pass its independent
allowlist, signature-path, and root-pin validation before OCI is modified.

If an older completed Gate 0 run predates schema-v2 evidence but its immutable
report and durable operation database still prove promotion, TLS audit,
rollback, and final TLS audit, an administrator may recover the JSON record.
The recovered record must retain the report SHA-256 and the exact operation IDs;
it is not permissible to infer a pass from configuration or certificate status
alone.
