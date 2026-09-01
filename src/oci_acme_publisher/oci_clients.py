"""Regional OCI Certificates clients executed in a deliberately bounded thread pool."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import partial
from typing import Any, TypeVar

from oci.certificates import CertificatesClient
from oci.certificates_management import CertificatesManagementClient

from .config import OciConfig
from .oci_auth import instance_principal_signer
from .oci_certificates import CertificatesManagementAdapter, CertificatesRetrievalAdapter
from .oci_retry import ReadRetryPolicy

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class OciCertificatesAdapters:
    """The two explicitly permitted OCI Certificates API surfaces."""

    management: CertificatesManagementAdapter
    retrieval: CertificatesRetrievalAdapter


def create_certificates_adapters(region: str, configuration: OciConfig) -> OciCertificatesAdapters:
    """Build regional clients with the instance-principal signer and explicit timeouts."""
    signer = instance_principal_signer(configuration)
    client_config: dict[str, object] = {
        "region": region,
        "timeout": (configuration.connect_timeout_seconds, configuration.read_timeout_seconds),
    }
    management: Any = CertificatesManagementClient(client_config, signer=signer)
    retrieval: Any = CertificatesClient(client_config, signer=signer)
    return OciCertificatesAdapters(
        management=CertificatesManagementAdapter(
            management, read_retry_policy=ReadRetryPolicy(configuration.max_read_attempts)
        ),
        retrieval=CertificatesRetrievalAdapter(
            retrieval, read_retry_policy=ReadRetryPolicy(configuration.max_read_attempts)
        ),
    )


class OciExecutor:
    """Run synchronous OCI SDK calls outside the event loop with bounded concurrency."""

    def __init__(self, workers: int = 4) -> None:
        self._executor = ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="oci-certificates"
        )

    async def run(self, function: Callable[..., T], /, *arguments: object, **keywords: object) -> T:
        """Execute a callable in the dedicated bounded executor."""
        loop = asyncio.get_running_loop()
        call = partial(function, *arguments, **keywords)
        return await loop.run_in_executor(self._executor, call)

    def close(self) -> None:
        """Stop workers after the one-shot publisher operation has completed."""
        self._executor.shutdown(wait=True, cancel_futures=True)
