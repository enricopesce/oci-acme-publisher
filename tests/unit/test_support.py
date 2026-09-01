"""Tests for redacted support material and read-only service observation."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from oci_acme_publisher import support
from oci_acme_publisher.config import load_config
from oci_acme_publisher.errors import ConfigurationError
from oci_acme_publisher.metrics import collect_read_only_metrics


def test_metrics_collection_does_not_create_missing_state(tmp_path: Path) -> None:
    base = load_config("config/config.example.yaml")
    config = base.model_copy(
        update={"global_": base.global_.model_copy(update={"state_dir": str(tmp_path)})}
    )
    rendered = "".join(metric.render() for metric in collect_read_only_metrics(config))
    assert "oci_acme_state_available 0" in rendered
    assert not (tmp_path / "state.sqlite3").exists()


def test_service_status_is_bounded_and_handles_missing_systemd() -> None:
    def runner(arguments: list[str], **_: object) -> object:
        assert arguments[:2] == ["systemctl", "show"]
        return SimpleNamespace(
            returncode=0,
            stdout="ActiveState=active\nSubState=running\nUnitFileState=enabled\nResult=success\n",
        )

    states = support.service_status(runner)
    assert len(states) == 3
    assert all(state["active_state"] == "active" for state in states)

    unavailable = support.service_status(lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()))
    assert all(state["state"] == "UNAVAILABLE" for state in unavailable)


def test_support_bundle_excludes_sensitive_sources_and_is_write_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = load_config("config/config.example.yaml")
    monkeypatch.setattr(support, "service_status", lambda: ({"unit": "test", "state": "ok"},))
    bundle = support.support_bundle("config/config.example.yaml", config)
    assert "private keys" in bundle["exclusions"]
    assert "journal entries" in bundle["exclusions"]
    output = tmp_path / "support.json"
    support.write_support_bundle(str(output), bundle)
    assert '"SUPPORT_BUNDLE_CREATED"' in output.read_text(encoding="utf-8")
    with pytest.raises(ConfigurationError):
        support.write_support_bundle(str(output), bundle)
