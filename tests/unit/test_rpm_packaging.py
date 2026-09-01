"""Contract tests for the offline and state-preserving RPM workflow."""

from __future__ import annotations

from pathlib import Path


def test_rpm_installs_an_offline_verified_python_runtime() -> None:
    bootstrap = Path("packaging/rpm/bootstrap-runtime").read_text(encoding="utf-8")
    spec = Path("packaging/rpm/oci-acme-publisher.spec").read_text(encoding="utf-8")
    assert "--no-index" in bootstrap
    assert "--require-hashes" in bootstrap
    assert '"$assets_dir/wheelhouse"' in bootstrap
    assert 'sed -i "1s|$new_runtime|$runtime_dir|"' in bootstrap
    assert "wheelhouse" in spec
    assert "python3 -m build" not in spec
    assert "%{_bindir}/oci-acme-upgrade" in spec
    assert "%doc README.md docs/*.md" in spec
    assert "native Python ACME protocol client" in spec
    assert "No external certificate client or subprocess is required" in spec
    assert "ExclusiveArch:   x86_64" in spec
    assert "python3 >= 3.12" in spec


def test_upgrade_requires_a_verified_rpm_and_restores_running_services() -> None:
    upgrade = Path("scripts/upgrade-oracle-linux.sh").read_text(encoding="utf-8")
    assert 'verify-rpm.sh" "$package_path"' in upgrade
    assert "trap restore_services ERR" in upgrade
    assert "config validate --config /etc/oci-acme-publisher" in upgrade
    assert "systemd-analyze verify" in upgrade


def test_release_signing_is_explicit_and_key_material_is_not_in_the_repository() -> None:
    signing = Path("scripts/sign-rpm.sh").read_text(encoding="utf-8")
    documentation = Path("packaging/rpm/README.md").read_text(encoding="utf-8")
    assert "--key-id" in signing
    assert "rpmsign" in signing
    assert "never accepted from" in documentation


def test_release_key_bootstrap_requires_a_protected_external_keyring() -> None:
    generator = Path("scripts/generate-release-signing-key.sh").read_text(encoding="utf-8")
    signer = Path("scripts/sign-rpm.sh").read_text(encoding="utf-8")
    assert "--gnupg-home" in generator
    assert "pinentry" in generator
    assert "empty passphrase" in generator
    assert "--passphrase ''" not in generator
    assert "GNUPGHOME" in signer
    assert "stat -c '%a'" in signer
