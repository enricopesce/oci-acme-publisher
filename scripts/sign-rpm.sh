#!/usr/bin/env bash
set -euo pipefail

key_id=""
gnupg_home=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --key-id) key_id="$2"; shift 2 ;;
    --gnupg-home) gnupg_home="$2"; shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
[ -n "$key_id" ] && [ "$#" -gt 0 ] || {
  echo "usage: $0 --key-id KEY_ID [--gnupg-home DIRECTORY] RPM..." >&2
  exit 2
}
command -v rpmsign >/dev/null || { echo "rpmsign is required" >&2; exit 2; }
if [ -n "$gnupg_home" ]; then
  [ "${gnupg_home#/}" != "$gnupg_home" ] || {
    echo "--gnupg-home must be an absolute path" >&2
    exit 2
  }
  [ -d "$gnupg_home" ] || { echo "OpenPGP keyring does not exist" >&2; exit 2; }
  [ "$(stat -c '%a' "$gnupg_home")" = "700" ] || {
    echo "OpenPGP keyring must have mode 0700" >&2
    exit 2
  }
  export GNUPGHOME="$gnupg_home"
fi
for package_path in "$@"; do
  [ -f "$package_path" ] || { echo "RPM does not exist: $package_path" >&2; exit 2; }
  rpmsign --define "_gpg_name $key_id" --addsign "$package_path"
done
