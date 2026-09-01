# Architecture

The deployment consists of a persistent, credential-free HTTP-01 responder and
a separate systemd-triggered publisher. The publisher owns the native Python
ACME protocol flow, atomic certificate generations, local validation, OCI
Certificates publication, state and notifications. Load Balancer configuration
is intentionally external to this product.
