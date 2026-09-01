# Disaster recovery

Preserve encrypted backups of the ACME account key, certificate generations, and the
SQLite state database. Do not copy them to an unencrypted location. Restore the
same system users, permissions and webroot layout, then run `reconcile` before
ordering a new ACME certificate. The OCI certificate OCID remains the source of
truth for consumer association; never replace it merely because the publisher
host was rebuilt.

If `bootstrap` was interrupted after OCI created the imported certificate but
before the command returned its OCID, keep the restored SQLite database and
rerun the same `bootstrap` command with the unchanged configuration. The
publisher reads the incomplete bootstrap operation, verifies the public OCI
bundle against the local lineage, persists the confirmed version, and returns
the existing OCID. It does not create another OCI certificate. If that bundle
does not match the local lineage, the command fails closed; investigate the
stored operation and OCI resource rather than retrying creation.
