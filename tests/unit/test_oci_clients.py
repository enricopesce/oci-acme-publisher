from __future__ import annotations

import pytest

from oci_acme_publisher import oci_clients
from oci_acme_publisher.config import OciConfig
from oci_acme_publisher.oci_clients import OciExecutor, create_certificates_adapters


async def test_oci_executor_runs_sync_function_off_event_loop() -> None:
    executor = OciExecutor(workers=1)
    try:
        assert await executor.run(lambda value: value + 1, 41) == 42
    finally:
        executor.close()


def test_adapter_factory_uses_instance_signer_region_and_explicit_timeouts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = object()
    clients: list[tuple[dict[str, object], object]] = []

    class ManagementClient:
        def __init__(self, configuration: dict[str, object], *, signer: object) -> None:
            clients.append((configuration, signer))

    class RetrievalClient:
        def __init__(self, configuration: dict[str, object], *, signer: object) -> None:
            clients.append((configuration, signer))

    monkeypatch.setattr(oci_clients, "instance_principal_signer", lambda _: signer)
    monkeypatch.setattr(oci_clients, "CertificatesManagementClient", ManagementClient)
    monkeypatch.setattr(oci_clients, "CertificatesClient", RetrievalClient)
    configuration = OciConfig(
        authentication="instance_principal", connect_timeout_seconds=4, read_timeout_seconds=12
    )

    adapters = create_certificates_adapters("eu-frankfurt-1", configuration)

    assert adapters.management is not None
    assert adapters.retrieval is not None
    assert clients == [
        ({"region": "eu-frankfurt-1", "timeout": (4, 12)}, signer),
        ({"region": "eu-frankfurt-1", "timeout": (4, 12)}, signer),
    ]
