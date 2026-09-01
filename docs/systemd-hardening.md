# systemd hardening

The responder runs as `oci-acme-http`, has read-only access only to the
challenge webroots, and is explicitly denied ACME account and certificate storage. The
publisher runs as `oci-acme-publisher` with the challenge group supplementary.
Both units use a deliberately portable Oracle Linux hardening profile.

`/etc/oci-acme-publisher` is installed as `root:oci-acme-publisher` mode
`0751`: the responder can traverse it without listing it. `settings.yaml` and
the independent files below `certificates/` are owned by `oci-acme-publisher`,
group `oci-acme-challenge`, mode `0640`. The configuration
contains no credentials; OCI authentication is instance principal and notifier
credentials are supplied by systemd credentials rather than the YAML file.

After installation, validate the rendered units on the target host:

```bash
systemd-analyze verify /etc/systemd/system/oci-acme-http01.service
systemd-analyze verify /etc/systemd/system/oci-acme-renew.service
systemd-analyze security oci-acme-http01.service
systemd-analyze security oci-acme-renew.service
```

The result is host-specific and must be recorded in the installation report.

## Milan test-host evidence (2026-08-07)

`systemd-analyze verify` accepted both installed OCI ACME units. The host also
reported an unrelated warning in the distribution-provided `iscsi-init.service`;
it is not part of this deployment. `systemd-analyze security` reported exposure
levels `3.9 OK` for the responder and `4.0 OK` for the publisher. No syscall
filters were added because they have not been validated on the target Oracle
Linux image. The responder is active with `User=oci-acme-http`,
`Group=oci-acme-challenge`, no supplementary groups, and `UMask=0027`.
