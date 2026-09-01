#!/usr/bin/env bash
set -euo pipefail

[ "$#" -gt 0 ] || { echo "usage: $0 RPM..." >&2; exit 2; }
command -v rpmkeys >/dev/null || { echo "rpmkeys is required" >&2; exit 2; }
for package_path in "$@"; do
  [ -f "$package_path" ] || { echo "RPM does not exist: $package_path" >&2; exit 2; }
  verification="$(rpmkeys --checksig "$package_path")"
  printf '%s\n' "$verification"
  grep -Eqi 'pgp.*ok|signature.*ok' <<<"$verification" || {
    echo "RPM lacks a trusted signature: $package_path" >&2
    exit 1
  }
done
