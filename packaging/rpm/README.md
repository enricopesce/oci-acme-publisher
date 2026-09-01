# RPM release workflow

The RPM intentionally includes a platform-specific Python 3.12 wheelhouse and creates `/opt/oci-acme-publisher/venv`
without downloading packages at installation time. Configuration, certificate lineages,
and SQLite state are never RPM-owned, so upgrade and removal preserve them.

Build a release RPM on an Oracle Linux build host with `rpmbuild`, Python build tooling,
and network access only for the release build:

```bash
scripts/build-rpm.sh --output-dir dist/rpm
scripts/sign-rpm.sh --key-id <release-key-id> dist/rpm/*.rpm
scripts/verify-rpm.sh dist/rpm/*.rpm
```

If the organization does not yet have a release key, bootstrap it on a trusted
release workstation, never inside the repository:

```bash
scripts/generate-release-signing-key.sh \
  --gnupg-home /secure/release-keyring \
  --identity "OCI ACME Publisher Release <release@example.com>" \
  --public-key /secure/oci-acme-publisher-release.asc
scripts/sign-rpm.sh --gnupg-home /secure/release-keyring \
  --key-id <full-fingerprint> dist/rpm/*.rpm
```

The generator deliberately invokes interactive pinentry and refuses to create
an unprotected key. Transfer only the armored public key and signed RPM to the
production host, verify the fingerprint through a second channel, then import
that public key with `sudo rpm --import`. Generating the private key directly on
the managed production host is an emergency bootstrap with weaker separation
of duties and must be recorded as such.

Install or upgrade only a signature-verified artifact:

```bash
sudo scripts/upgrade-oracle-linux.sh --package dist/rpm/oci-acme-publisher-*.x86_64.rpm
```

The signing key is an external release-system secret; it is never accepted from,
or stored in, this repository.
