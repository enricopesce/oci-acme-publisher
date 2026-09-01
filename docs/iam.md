# IAM and least-privilege runtime access

The publisher authenticates to OCI with an instance principal. Its dynamic
group therefore needs access only to the OCI Certificates resources that the
configured operations use. It does not use, read, or change DNS, Load
Balancers, listeners, backend sets, NSGs, route tables, security lists, or
certificate associations.

Create a dynamic group that identifies only the publisher VM, preferably by
its instance OCID rather than by a broad compartment rule. For example:

```text
instance.id = 'ocid1.instance.oc1..<publisher-instance-ocid>'
```

The following policy is the recommended runtime baseline for an existing
imported certificate. Replace the placeholders with the actual dynamic-group
and certificate compartment names. It permits reading the certificate and its
versions, uploading a replacement version, making that version CURRENT, and
retrieving only the public bundle used for verification and audit.

```text
Allow dynamic-group <OCI_ACME_PUBLISHER_DG> to use leaf-certificates in compartment <CERTIFICATE_COMPARTMENT>
Allow dynamic-group <OCI_ACME_PUBLISHER_DG> to read leaf-certificate-versions in compartment <CERTIFICATE_COMPARTMENT>
Allow dynamic-group <OCI_ACME_PUBLISHER_DG> to read leaf-certificate-bundles in compartment <CERTIFICATE_COMPARTMENT> where target.leaf-certificate.bundle-type = 'CERTIFICATE_CONTENT_PUBLIC_ONLY'
```

`use leaf-certificates` includes the certificate update permission required to
publish an imported version and make it CURRENT. The public-bundle condition
is intentional: the publisher verifies the public OCI bundle and must not be
granted permission to retrieve private keys from OCI.

## Optional operations

When retention is enabled (it is enabled by the configuration default), it
schedules deletion only for old deprecated versions. Add this statement to
allow that optional cleanup; otherwise set `retention.enabled: false` for each
certificate:

```text
Allow dynamic-group <OCI_ACME_PUBLISHER_DG> to manage leaf-certificate-versions in compartment <CERTIFICATE_COMPARTMENT>
```

This permission is broader because OCI requires the version-delete permission
to schedule a version deletion. It is not needed for normal issue, renew,
publish, reconcile, audit, or rollback operations. Without it, a successful
publication remains CURRENT but retention is reported as failed and skipped.

`bootstrap` creates the first imported OCI Certificate. Treat that as a
separate, reviewed change: either run it from a separately controlled instance
principal, or temporarily add the following grant to the publisher's dynamic
group, run bootstrap for the intended certificate, then remove the grant. The
normal runtime policy should not retain create or delete privileges just
because bootstrap was once required.

```text
Allow dynamic-group <OCI_ACME_PUBLISHER_DG> to manage leaf-certificates in compartment <CERTIFICATE_COMPARTMENT>
Allow dynamic-group <OCI_ACME_PUBLISHER_DG> to read leaf-certificate-versions in compartment <CERTIFICATE_COMPARTMENT>
Allow dynamic-group <OCI_ACME_PUBLISHER_DG> to read leaf-certificate-bundles in compartment <CERTIFICATE_COMPARTMENT> where target.leaf-certificate.bundle-type = 'CERTIFICATE_CONTENT_PUBLIC_ONLY'
```

For a stricter tenancy, scope policies further with OCI policy conditions such
as `target.leaf-certificate.name` or `target.leaf-certificate.id` where the
operation and lifecycle allow it. Test every condition in staging first:
creation cannot be restricted by a certificate OCID that does not yet exist.

Do **not** grant the runtime dynamic group any of the following:

- `manage all-resources`, or a tenancy-wide certificate policy without a
  documented reason;
- `manage load-balancers`, `manage virtual-network-family`, DNS, or firewall/
  NSG permissions;
- permission to retrieve `CERTIFICATE_CONTENT_WITH_PRIVATE_KEY` bundles;
- Vault, Object Storage, or Certificate Authority permissions. They are not
  required for imported ACME certificates managed by this project.

OCI policy verbs and resource types evolve. Validate the final statements
against Oracle's current [Certificates IAM policy reference](https://docs.oracle.com/en-us/iaas/Content/Identity/policyreference/certificatespolicyreference.htm)
and apply them through the organisation's normal IAM change process.
