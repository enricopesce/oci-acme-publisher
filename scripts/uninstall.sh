#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root" >&2
  exit 2
fi

systemctl disable --now oci-acme-renew.timer oci-acme-http01.service || true
rm -f /etc/systemd/system/oci-acme-http01.service
rm -f /etc/systemd/system/oci-acme-renew.service
rm -f /etc/systemd/system/oci-acme-renew.timer
systemctl daemon-reload
echo "Preserved /var/lib/oci-acme-publisher, /var/lib/oci-acme-http01 and /etc/oci-acme-publisher for recovery."

