# Troubleshooting

Run these commands first; they neither issue certificates nor modify OCI:

```bash
sudo oci-acme config validate --config /etc/oci-acme-publisher
sudo oci-acme check --config /etc/oci-acme-publisher
sudo oci-acme service status
```

| Symptom | Likely cause | Safe next action |
| --- | --- | --- |
| `HTTP-01 preflight failed` | DNS, port-80 route, responder address, webroot permissions, or public reachability is wrong. | Run `check`; verify the exact public path shown in its error. Do not use a production ACME order to test routing. |
| `OCI publication failed` | Instance principal/IAM, OCID, region, or OCI service state is wrong. | Confirm the dynamic-group policy in [IAM](iam.md), then run `check`. |
| Production mutation is rejected before ACME issuance | Live evidence is absent, unsafe, or does not match the configured profile. | Follow [staging qualification](staging-qualification.md); do not set the boolean alone. |
| Timer is inactive | Service not enabled, config is invalid, or prior renewal failed. | Run `service status`, then `systemctl status oci-acme-renew.timer`. Validate config before re-enabling. |
| Public endpoint serves an old certificate | Listener/SNI association or OCI propagation is incomplete. | Check the operator-owned IaC association and run `oci-acme audit --config … --certificate-id …`. |
| Metrics show `oci_acme_state_available 0` | A new install has not run, or the querying user cannot read protected state. | Run as the service operator/root; treat it as expected only before the first successful run. |

For a support case, create a write-once redacted bundle:

```bash
sudo oci-acme diagnose --config /etc/oci-acme-publisher \
  --output /var/tmp/oci-acme-support.json
```

Review it before sharing. Never share private keys, ACME account material,
the state directory, or raw journal output.
