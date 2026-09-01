# ADR 0001: OCI compatibility is a release gate

The OCI imported-certificate profile is treated as externally verified behavior.
The implementation validates documented constraints locally but never rewrites a
CA-signed certificate. A failing live probe blocks production qualification.

