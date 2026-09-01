"""Host-local advisory locking for one-shot publisher invocations."""

from __future__ import annotations

import fcntl
import os
from dataclasses import dataclass
from pathlib import Path

from .errors import PublisherError
from .exit_codes import ExitCode


class LockUnavailableError(PublisherError):
    """The host-local publisher lock is already held."""

    def __init__(self) -> None:
        super().__init__(ExitCode.LOCKED_OR_TEMPORARY_FAILURE, "publisher lock is already held")


@dataclass(slots=True)
class AdvisoryLock:
    """An open descriptor keeps the flock alive for the complete operation."""

    path: Path
    _fd: int | None = None

    def acquire(self) -> None:
        """Acquire the non-blocking exclusive lock or raise a stable error."""
        self.path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o640)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(descriptor)
            raise LockUnavailableError() from error
        self._fd = descriptor

    def release(self) -> None:
        """Release and close the descriptor if this instance owns it."""
        if self._fd is None:
            return
        fcntl.flock(self._fd, fcntl.LOCK_UN)
        os.close(self._fd)
        self._fd = None

    def __enter__(self) -> AdvisoryLock:
        self.acquire()
        return self

    def __exit__(self, *_: object) -> None:
        self.release()
