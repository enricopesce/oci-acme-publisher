#!/usr/bin/env bash
# Run the release gates on an Oracle Linux x86_64 build worker.
set -euo pipefail

command -v uv >/dev/null || { echo "uv is required" >&2; exit 127; }
uv sync --all-extras --locked
uv run pytest
uv run ruff check .
uv run mypy --strict src
uv run ruff format --check .
uv run pip-audit --local --ignore-vuln PYSEC-2026-3552

schema_output="$(mktemp)"
trap 'rm -f "$schema_output"' EXIT
uv run oci-acme generate-schema --output "$schema_output"
cmp -s "$schema_output" config/config.schema.json || {
  echo "config/config.schema.json is stale; regenerate it before release" >&2
  exit 1
}

rpm_output="$(mktemp -d)"
trap 'rm -f "$schema_output"; rm -rf "$rpm_output"' EXIT
scripts/build-rpm.sh --output-dir "$rpm_output"
rpm_package="$(find "$rpm_output" -maxdepth 1 -type f -name '*.x86_64.rpm' -print -quit)"
[ -n "$rpm_package" ] || { echo "RPM build produced no x86_64 package" >&2; exit 1; }
scripts/test-rpm-payload.sh --package "$rpm_package"
