from __future__ import annotations

import pytest
from oci.exceptions import ServiceError

from oci_acme_publisher import oci_retry
from oci_acme_publisher.oci_retry import (
    ReadRetryPolicy,
    RetryableOciError,
    retry_read,
    retry_read_sync,
    retry_read_until_sync,
)


async def test_read_retry_retries_transient_error_then_returns() -> None:
    attempts = 0

    async def operation() -> object:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RetryableOciError(429, retry_after_seconds=0)
        return "ok"

    result = await retry_read(operation, ReadRetryPolicy(max_attempts=2))
    assert result == "ok"
    assert attempts == 2


def test_retry_delay_prefers_bounded_retry_after() -> None:
    policy = ReadRetryPolicy(max_attempts=2, maximum_delay_seconds=3)
    assert policy.delay(0, 10) == 3
    assert policy.delay(0, 0.5) == 0.5


async def test_retry_reraises_final_transient_error_and_rejects_zero_attempts() -> None:
    async def always_fails() -> object:
        raise RetryableOciError(503)

    with pytest.raises(RetryableOciError):
        await retry_read(always_fails, ReadRetryPolicy(max_attempts=1))
    with pytest.raises(RuntimeError, match="no attempts"):
        await retry_read(always_fails, ReadRetryPolicy(max_attempts=0))


def test_sync_retry_retries_transport_timeout_without_sleeping_in_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    monkeypatch.setattr(oci_retry.time, "sleep", lambda _: None)

    def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TimeoutError("transient")
        return "ok"

    assert retry_read_sync(operation, ReadRetryPolicy(max_attempts=2)) == "ok"
    assert attempts == 2


def test_sync_retry_handles_oci_retry_after_and_preserves_non_retryable_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    delays: list[float] = []
    monkeypatch.setattr(oci_retry.time, "sleep", delays.append)

    def transient_then_ok() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ServiceError(429, "TooManyRequests", {"retry-after": "0"}, "busy")
        return "ok"

    assert retry_read_sync(transient_then_ok, ReadRetryPolicy(max_attempts=2)) == "ok"
    assert delays == [0.0]

    def bad_request() -> object:
        raise ServiceError(400, "BadRequest", {}, "bad")

    with pytest.raises(ServiceError):
        retry_read_sync(bad_request, ReadRetryPolicy(max_attempts=2))
    with pytest.raises(RuntimeError, match="no attempts"):
        retry_read_sync(lambda: "unused", ReadRetryPolicy(max_attempts=0))


def test_sync_retry_handles_eventual_consistency_bundle_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    monkeypatch.setattr(oci_retry.time, "sleep", lambda _: None)

    def eventually_visible() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ServiceError(404, "NotAuthorizedOrNotFound", {}, "not visible yet")
        return "bundle"

    assert retry_read_sync(eventually_visible, ReadRetryPolicy(max_attempts=2)) == "bundle"
    assert attempts == 2


def test_sync_retry_waits_for_an_eventually_consistent_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = iter((1, 2))
    monkeypatch.setattr(oci_retry.time, "sleep", lambda _: None)

    result = retry_read_until_sync(
        lambda: next(values), lambda value: value == 2, ReadRetryPolicy(2)
    )

    assert result == 2
