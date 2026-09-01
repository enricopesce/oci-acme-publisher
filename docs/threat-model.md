# Threat model

The responder is intentionally credential-free and cannot read ACME state or
private keys. It exposes only challenge, health and readiness paths, uses an
immutable host allowlist and descriptor-relative filesystem reads with symlink
rejection. The publisher runs separately, has the only OCI Instance Principal
access, redacts diagnostic output and stores no PEM or secret in SQLite.

Residual risks include CA multi-perspective validation, external DNS/routing
drift, OCI service behavior, host compromise and volumetric DDoS. The preflight
reduces routing risk but is not a substitute for CA validation. Network DDoS
protection remains the customer's responsibility.
