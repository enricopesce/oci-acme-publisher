"""Bounded retry policy for idempotent OCI read operations only."""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TypeVar

from oci.exceptions import ServiceError

T = TypeVar("T")
_MISSING = object()


class RetryableOciError(RuntimeError):
    """A read-only OCI response is eligible for bounded retry."""

    def __init__(self, status_code: int, retry_after_seconds: float | None = None) -> None:
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"retryable OCI read error: {status_code}")


@dataclass(frozen=True, slots=True)
class ReadRetryPolicy:
    """Full-jitter retry limits for bounded, idempotent OCI read operations."""

    max_attempts: int
    base_delay_seconds: float = 0.25
    maximum_delay_seconds: float = 10.0

    def delay(self, attempt: int, retry_after_seconds: float | None) -> float:
        """Choose server Retry-After first, otherwise full jitter under exponential cap."""
        if retry_after_seconds is not None and retry_after_seconds >= 0:
            return min(retry_after_seconds, self.maximum_delay_seconds)
        ceiling = min(self.maximum_delay_seconds, self.base_delay_seconds * (2**attempt))
        return secrets.SystemRandom().uniform(0, ceiling)


async def retry_read(operation: Callable[[], Awaitable[object]], policy: ReadRetryPolicy) -> object:
    """Retry only known transient read errors; final failure preserves its cause."""
    for attempt in range(policy.max_attempts):
        try:
            return await operation()
        except RetryableOciError as error:
            if attempt + 1 >= policy.max_attempts:
                raise
            await asyncio.sleep(policy.delay(attempt, error.retry_after_seconds))
    raise RuntimeError("read retry policy has no attempts")


def _retryable_exception(error: ServiceError | TimeoutError | OSError) -> RetryableOciError | None:
    """Translate only SDK transient responses and transport timeouts."""
    if isinstance(error, ServiceError):
        eventually_consistent_not_found = (
            error.status == 404 and error.code == "NotAuthorizedOrNotFound"
        )
        if error.status not in (429, 500, 502, 503, 504) and not eventually_consistent_not_found:
            return None
        retry_after: float | None = None
        header = error.headers.get("retry-after") if error.headers else None
        if isinstance(header, str):
            try:
                retry_after = float(header)
            except ValueError:
                retry_after = None
        return RetryableOciError(error.status, retry_after)
    return RetryableOciError(0)


def retry_read_sync(operation: Callable[[], T], policy: ReadRetryPolicy) -> T:
    """Bounded synchronous retry for OCI read adapters running in an executor."""
    for attempt in range(policy.max_attempts):
        try:
            return operation()
        except (ServiceError, TimeoutError, OSError) as error:
            retryable = _retryable_exception(error)
            if retryable is None or attempt + 1 >= policy.max_attempts:
                raise
            time.sleep(policy.delay(attempt, retryable.retry_after_seconds))
    raise RuntimeError("read retry policy has no attempts")


def retry_read_until_sync(
    operation: Callable[[], T], accepted: Callable[[T], bool], policy: ReadRetryPolicy
) -> T:
    """Repeat a read until an expected eventually-consistent state becomes visible."""
    result: object = _MISSING
    for attempt in range(policy.max_attempts):
        try:
            result = operation()
        except (ServiceError, TimeoutError, OSError) as error:
            retryable = _retryable_exception(error)
            if retryable is None or attempt + 1 >= policy.max_attempts:
                raise
            time.sleep(policy.delay(attempt, retryable.retry_after_seconds))
            continue
        typed_result = result
        if accepted(typed_result) or attempt + 1 >= policy.max_attempts:
            return typed_result
        time.sleep(policy.delay(attempt, None))
    raise RuntimeError("read retry policy has no attempts")
