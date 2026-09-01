#!/usr/bin/env bash
set -euo pipefail

wheel_path=""
config_path=""
repository_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --wheel)
      wheel_path="$2"
      shift 2
      ;;
    --config)
      config_path="$2"
      shift 2
      ;;
    *)
      echo "usage: $0 --wheel /path/to/package.whl --config /path/to/config-directory" >&2
      exit 2
      ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root" >&2
  exit 2
fi
if [ -z "$wheel_path" ] || [ -z "$config_path" ] || [ ! -f "$wheel_path" ] || [ ! -d "$config_path" ] || [ ! -f "$config_path/settings.yaml" ]; then
  echo "wheel and config directory must exist, with settings.yaml" >&2
  exit 2
fi

dnf -y install python3
install -d -m 0755 /opt/oci-acme-publisher
python3 -m venv /opt/oci-acme-publisher/venv
/opt/oci-acme-publisher/venv/bin/pip install --require-hashes -r "$repository_root/requirements.lock"
/opt/oci-acme-publisher/venv/bin/pip install --no-deps "$wheel_path"
install -m 0644 deploy/sysusers.d/oci-acme-publisher.conf /usr/lib/sysusers.d/oci-acme-publisher.conf
install -m 0644 deploy/tmpfiles.d/oci-acme-publisher.conf /usr/lib/tmpfiles.d/oci-acme-publisher.conf
systemd-sysusers /usr/lib/sysusers.d/oci-acme-publisher.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/oci-acme-publisher.conf
# The responder is only in oci-acme-challenge: it can traverse (but not list)
# this directory and read the non-secret configuration. The publisher owns the
# file and remains the only non-root writer.
install -d -m 0751 -o root -g oci-acme-publisher /etc/oci-acme-publisher
install -m 0640 -o oci-acme-publisher -g oci-acme-challenge "$config_path/settings.yaml" /etc/oci-acme-publisher/settings.yaml
install -d -m 0750 -o oci-acme-publisher -g oci-acme-challenge /etc/oci-acme-publisher/certificates
for certificate_path in "$config_path"/certificates/*.yaml; do
  [ -f "$certificate_path" ] || continue
  install -m 0640 -o oci-acme-publisher -g oci-acme-challenge "$certificate_path" \
    "/etc/oci-acme-publisher/certificates/$(basename "$certificate_path")"
done
install -m 0644 deploy/systemd/oci-acme-http01.service /etc/systemd/system/oci-acme-http01.service
install -m 0644 deploy/systemd/oci-acme-renew.service /etc/systemd/system/oci-acme-renew.service
install -m 0644 deploy/systemd/oci-acme-renew.timer /etc/systemd/system/oci-acme-renew.timer
/opt/oci-acme-publisher/venv/bin/oci-acme-publisher validate-config --config /etc/oci-acme-publisher
systemctl daemon-reload
systemctl enable --now oci-acme-http01.service oci-acme-renew.timer
