"""Tests for the deliberately narrow OCI authentication boundary."""

from __future__ import annotations

import pytest

from oci_acme_publisher import oci_auth
from oci_acme_publisher.config import OciConfig
from oci_acme_publisher.oci_auth import OciAuthenticationError, instance_principal_signer


def test_instance_principal_signer_uses_only_the_oci_instance_signer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = object()
    monkeypatch.setattr(oci_auth, "InstancePrincipalsSecurityTokenSigner", lambda: signer)
    assert instance_principal_signer(OciConfig(authentication="instance_principal")) is signer


def test_instance_principal_signer_wraps_credential_availability_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable() -> object:
        raise OSError("metadata service unavailable")

    monkeypatch.setattr(oci_auth, "InstancePrincipalsSecurityTokenSigner", unavailable)
    with pytest.raises(OciAuthenticationError):
        instance_principal_signer(OciConfig(authentication="instance_principal"))
