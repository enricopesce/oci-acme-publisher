#!/usr/bin/env bash
set -euo pipefail

output_dir=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-dir) output_dir="$2"; shift 2 ;;
    *) echo "usage: $0 --output-dir DIRECTORY" >&2; exit 2 ;;
  esac
done
[ -n "$output_dir" ] || { echo "--output-dir is required" >&2; exit 2; }
command -v rpmbuild >/dev/null || { echo "rpmbuild is required" >&2; exit 2; }
command -v uv >/dev/null || { echo "uv is required" >&2; exit 2; }

release_version="$(awk -F'"' '/^version = / { print $2; exit }' pyproject.toml)"
[ -n "$release_version" ] || { echo "unable to determine package version" >&2; exit 2; }
release_root="$(mktemp -d)"
trap 'rm -rf "$release_root"' EXIT
mkdir -p "$release_root"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} "$release_root/wheelhouse"

uv build --wheel --out-dir "$release_root/project-dist"
python3 -m venv "$release_root/download-venv"
"$release_root/download-venv/bin/pip" download --require-hashes -r requirements.lock \
  --dest "$release_root/wheelhouse"
cp "$release_root/project-dist"/*.whl "$release_root/wheelhouse/"
tar --exclude-vcs --exclude='./dist' --exclude='./.venv' --exclude='./.pytest_cache' \
  -czf "$release_root/SOURCES/oci-acme-publisher-$release_version.tar.gz" \
  --transform "s,^.,oci-acme-publisher-$release_version," .
tar -C "$release_root/wheelhouse" -czf \
  "$release_root/SOURCES/oci-acme-publisher-$release_version-wheelhouse.tar.gz" .
cp packaging/rpm/oci-acme-publisher.spec "$release_root/SPECS/"
rpmbuild -bb --define "_topdir $release_root" --define "version $release_version" \
  "$release_root/SPECS/oci-acme-publisher.spec"
mkdir -p "$output_dir"
find "$release_root/RPMS" -type f -name '*.rpm' -exec cp {} "$output_dir"/ \;
find "$release_root/SRPMS" -type f -name '*.rpm' -exec cp {} "$output_dir"/ \;
