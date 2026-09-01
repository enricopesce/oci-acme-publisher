#!/usr/bin/env bash
set -euo pipefail

keyring=""
identity=""
public_key=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --gnupg-home) keyring="$2"; shift 2 ;;
    --identity) identity="$2"; shift 2 ;;
    --public-key) public_key="$2"; shift 2 ;;
    *) echo "usage: $0 --gnupg-home DIR --identity TEXT --public-key PATH" >&2; exit 2 ;;
  esac
done

[ -n "$keyring" ] && [ -n "$identity" ] && [ -n "$public_key" ] || {
  echo "all options are required" >&2
  exit 2
}
for path in "$keyring" "$public_key"; do
  [ "${path#/}" != "$path" ] || { echo "key paths must be absolute" >&2; exit 2; }
done
[ ! -e "$public_key" ] || { echo "public key output already exists" >&2; exit 2; }
command -v gpg >/dev/null || { echo "gpg is required" >&2; exit 127; }

umask 077
install -d -m 0700 "$keyring"
echo "A pinentry prompt will protect the private release key. Do not use an empty passphrase."
gpg --homedir "$keyring" --quick-generate-key "$identity" rsa3072 sign 2y
fingerprint="$(
  gpg --homedir "$keyring" --batch --with-colons --list-secret-keys "$identity" |
    awk -F: '$1 == "fpr" { print $10; exit }'
)"
[ -n "$fingerprint" ] || { echo "unable to resolve generated key fingerprint" >&2; exit 1; }
gpg --homedir "$keyring" --armor --export "$fingerprint" > "$public_key"
chmod 0644 "$public_key"
printf 'release_key_fingerprint=%s\npublic_key=%s\n' "$fingerprint" "$public_key"
