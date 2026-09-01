"""OCI authentication restricted to instance principals."""

from __future__ import annotations

from typing import Any

from oci.auth.signers import InstancePrincipalsSecurityTokenSigner

from .config import OciConfig


class OciAuthenticationError(RuntimeError):
    """Instance-principal authentication could not be initialized."""


def instance_principal_signer(configuration: OciConfig) -> Any:
    """Create the sole supported OCI signer; no user config or static secret is read."""
    if configuration.authentication != "instance_principal":
        raise OciAuthenticationError("only instance_principal authentication is supported")
    try:
        return InstancePrincipalsSecurityTokenSigner()
    except OSError as error:
        raise OciAuthenticationError("instance-principal credentials are unavailable") from error
