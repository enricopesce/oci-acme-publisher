#!/usr/bin/env bash
# Execute the explicitly operator-authorized staging Gate 0 workflow.
set -euo pipefail

config_path=""
certificate_id=""
evidence_output=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config) config_path="$2"; shift 2 ;;
    --certificate-id) certificate_id="$2"; shift 2 ;;
    --evidence-output) evidence_output="$2"; shift 2 ;;
    *) echo "usage: $0 --config DIR --certificate-id ID --evidence-output PATH" >&2; exit 2 ;;
  esac
done
[ -n "$config_path" ] && [ -n "$certificate_id" ] && [ -n "$evidence_output" ] || {
  echo "--config, --certificate-id, and --evidence-output are required" >&2
  exit 2
}
command -v oci-acme >/dev/null || { echo "oci-acme is required" >&2; exit 127; }

# `check` is read-only. `staging verify` is deliberately the only mutation and
# the CLI independently enforces environment: staging and a test OCID.
oci-acme check --config "$config_path" --certificate-id "$certificate_id"
oci-acme staging verify --config "$config_path" --certificate-id "$certificate_id" \
  --evidence-output "$evidence_output"
