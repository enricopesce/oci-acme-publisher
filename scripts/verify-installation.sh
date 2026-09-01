#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root to read the protected configuration and query systemd" >&2
  exit 2
fi

config_path="${1:-/etc/oci-acme-publisher}"
command -v systemd-analyze >/dev/null
systemd-analyze verify /etc/systemd/system/oci-acme-http01.service
systemd-analyze verify /etc/systemd/system/oci-acme-renew.service
/opt/oci-acme-publisher/venv/bin/oci-acme-publisher validate-config --config "$config_path"
systemctl is-active --quiet oci-acme-http01.service
systemctl is-enabled --quiet oci-acme-renew.timer
echo "OCI ACME Publisher installation verified."
