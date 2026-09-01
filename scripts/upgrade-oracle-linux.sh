#!/usr/bin/env bash
set -euo pipefail

package_path=""
check_only=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --package) package_path="$2"; shift 2 ;;
    --check-only) check_only=true; shift ;;
    *) echo "usage: $0 --package PATH [--check-only]" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 2; }
[ -f "$package_path" ] || { echo "--package must name an existing RPM" >&2; exit 2; }
"$(dirname "$0")/verify-rpm.sh" "$package_path"
rpm -qp --quiet "$package_path" || { echo "invalid RPM" >&2; exit 2; }

if [ -x /opt/oci-acme-publisher/venv/bin/oci-acme ]; then
  /opt/oci-acme-publisher/venv/bin/oci-acme config validate --config /etc/oci-acme-publisher
fi
if "$check_only"; then
  echo "RPM and current configuration passed upgrade preflight."
  exit 0
fi

was_http_active=false
was_timer_enabled=false
systemctl is-active --quiet oci-acme-http01.service && was_http_active=true || :
systemctl is-enabled --quiet oci-acme-renew.timer && was_timer_enabled=true || :
restore_services() {
  "$was_http_active" && systemctl start oci-acme-http01.service || :
  "$was_timer_enabled" && systemctl enable --now oci-acme-renew.timer || :
}
trap restore_services ERR
systemctl stop oci-acme-renew.timer oci-acme-http01.service || :

dnf -y install "$package_path"
/opt/oci-acme-publisher/venv/bin/oci-acme config validate --config /etc/oci-acme-publisher
systemd-analyze verify /usr/lib/systemd/system/oci-acme-http01.service
systemd-analyze verify /usr/lib/systemd/system/oci-acme-renew.service
systemctl daemon-reload
"$was_http_active" && systemctl start oci-acme-http01.service || :
"$was_timer_enabled" && systemctl enable --now oci-acme-renew.timer || :
trap - ERR
echo "OCI ACME Publisher upgrade completed; configuration and certificate state were preserved."
