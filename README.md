# OCI ACME Publisher

OCI ACME Publisher is a systemd-managed Oracle Linux service that
obtains HTTP-01 certificates through a native Python ACME client, validates the certificate profile,
and publishes new versions to OCI Certificates.

It deliberately does **not** change DNS, firewalls, routing, Load Balancers,
listeners, backend sets, NSGs, or certificate/SNI associations. Those remain
operator-owned infrastructure.

Start with the [production quick start](docs/getting-started.md). It takes a
new administrator from signed RPM installation through a staging check and the
first safe renewal path.

Useful references:

- [CLI and configuration layout](docs/cli.md)
- [staging qualification](docs/staging-qualification.md)
- [observability and support](docs/observability.md)
- [operations runbook](docs/operations-runbook.md)
- [troubleshooting](docs/troubleshooting.md)
- [quality gates](docs/quality-gates.md)

## Development

```bash
uv sync --all-extras --locked
uv run oci-acme config validate --config config/config.example.yaml
uv run pytest
```

The compatibility evidence and its scope are retained separately in `docs/`.
