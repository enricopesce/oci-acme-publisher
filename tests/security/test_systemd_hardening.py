from __future__ import annotations

from configparser import ConfigParser
from pathlib import Path


def _unit(path: str) -> ConfigParser:
    parser = ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    parser.read(path, encoding="utf-8")
    return parser


def _assert_hardening(service: ConfigParser) -> None:
    expected = {
        "NoNewPrivileges": "true",
        "ProtectSystem": "strict",
        "ProtectHome": "true",
        "PrivateTmp": "true",
        "PrivateDevices": "true",
        "ProtectKernelTunables": "true",
        "ProtectKernelModules": "true",
        "ProtectKernelLogs": "true",
        "ProtectControlGroups": "true",
        "ProtectClock": "true",
        "ProtectHostname": "true",
        "RestrictSUIDSGID": "true",
        "RestrictRealtime": "true",
        "LockPersonality": "true",
        "MemoryDenyWriteExecute": "true",
        "CapabilityBoundingSet": "",
        "AmbientCapabilities": "",
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
        "LimitCORE": "0",
    }
    for key, value in expected.items():
        assert service["Service"][key] == value


def test_responder_unit_is_confined_and_cannot_read_acme_private_state() -> None:
    unit = _unit("deploy/systemd/oci-acme-http01.service")
    service = unit["Service"]
    assert service["User"] == "oci-acme-http"
    assert service["Group"] == "oci-acme-challenge"
    assert service["UMask"] == "0027"
    assert "SupplementaryGroups" not in service
    assert service["Type"] == "exec"
    assert service["Restart"] == "on-failure"
    assert service["ReadOnlyPaths"] == "/var/lib/oci-acme-http01"
    assert service["InaccessiblePaths"] == (
        "/var/lib/oci-acme-publisher/acme /var/lib/oci-acme-publisher/certificates"
    )
    _assert_hardening(unit)


def test_publisher_unit_has_only_the_required_write_paths_and_dependencies() -> None:
    unit = _unit("deploy/systemd/oci-acme-renew.service")
    service = unit["Service"]
    assert unit["Unit"]["Wants"] == "network-online.target time-sync.target"
    assert unit["Unit"]["After"] == "network-online.target time-sync.target"
    assert service["Type"] == "oneshot"
    assert service["User"] == "oci-acme-publisher"
    assert service["Group"] == "oci-acme-publisher"
    assert service["SupplementaryGroups"] == "oci-acme-challenge"
    assert service["UMask"] == "0027"
    assert service["TimeoutStartSec"] == "35min"
    assert service["RestartPreventExitStatus"] == "75"
    assert service["ReadWritePaths"].split() == [
        "/var/lib/oci-acme-publisher",
        "/var/lib/oci-acme-http01",
        "/var/log/oci-acme-publisher",
        "/run/oci-acme-publisher",
    ]
    _assert_hardening(unit)


def test_timer_and_account_definitions_remain_safe() -> None:
    timer = Path("deploy/systemd/oci-acme-renew.timer").read_text(encoding="utf-8")
    assert timer.count("OnCalendar=*-*-*") == 2
    assert "RandomizedDelaySec=30min" in timer
    assert "Persistent=true" in timer

    sysusers = Path("deploy/sysusers.d/oci-acme-publisher.conf").read_text(encoding="utf-8")
    assert "u oci-acme-publisher" in sysusers
    assert "u oci-acme-http" in sysusers
    assert "g oci-acme-challenge" in sysusers

    tmpfiles = Path("deploy/tmpfiles.d/oci-acme-publisher.conf").read_text(encoding="utf-8")
    assert "d /var/lib/oci-acme-publisher 0700 oci-acme-publisher oci-acme-publisher" in tmpfiles
    assert "d /var/lib/oci-acme-http01 0750 oci-acme-publisher oci-acme-challenge" in tmpfiles
    assert (
        "d /var/lib/oci-acme-http01/webroots 2750 oci-acme-publisher oci-acme-challenge" in tmpfiles
    )


def test_installer_keeps_responder_access_separate_from_acme_private_state() -> None:
    installer = Path("scripts/install-oracle-linux.sh").read_text(encoding="utf-8")
    assert "install -d -m 0751 -o root -g oci-acme-publisher /etc/oci-acme-publisher" in installer
    assert (
        'install -m 0640 -o oci-acme-publisher -g oci-acme-challenge "$config_path/settings.yaml" '
        "/etc/oci-acme-publisher/settings.yaml"
    ) in installer


def test_installation_verifier_requires_root_for_the_protected_configuration() -> None:
    verifier = Path("scripts/verify-installation.sh").read_text(encoding="utf-8")
    assert 'if [ "$(id -u)" -ne 0 ]; then' in verifier
    assert "must run as root to read the protected configuration and query systemd" in verifier
    assert 'config_path="${1:-/etc/oci-acme-publisher}"' in verifier
