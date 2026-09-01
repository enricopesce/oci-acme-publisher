#!/usr/bin/env bash
# Verify a built RPM can be installed into an isolated RPM database without scripts.
set -euo pipefail

package_path=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --package) package_path="$2"; shift 2 ;;
    *) echo "usage: $0 --package PATH" >&2; exit 2 ;;
  esac
done
[ -f "$package_path" ] || { echo "--package must name an existing RPM" >&2; exit 2; }
command -v rpm >/dev/null || { echo "rpm is required" >&2; exit 2; }

rpm -K "$package_path" | grep -q 'digests OK'
rpm -qp --qf '%{ARCH}\n' "$package_path" | grep -qx 'x86_64'
rpm -qpR "$package_path" | grep -qx 'python3 >= 3.12'

test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
rpm --root "$test_root" --initdb
rpm --root "$test_root" --dbpath /var/lib/rpm -ivh --nodeps --noscripts "$package_path" >/dev/null
test -x "$test_root/usr/bin/oci-acme"
test -x "$test_root/usr/bin/oci-acme-upgrade"
test -x "$test_root/usr/libexec/oci-acme-publisher/bootstrap-runtime"
test -x "$test_root/usr/libexec/oci-acme-publisher/verify-rpm.sh"
test -x "$test_root/usr/libexec/oci-acme-publisher/upgrade-oracle-linux.sh"
test -f "$test_root/usr/lib/systemd/system/oci-acme-http01.service"
test -f "$test_root/usr/share/oci-acme-publisher/requirements.lock"
find "$test_root/usr/share/oci-acme-publisher/wheelhouse" -maxdepth 1 -type f \
  -name 'oci_acme_certificate_publisher-*.whl' -print -quit | grep -q .
test ! -e "$test_root/etc/oci-acme-publisher"
echo "RPM payload contract passed."
