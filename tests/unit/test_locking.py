from __future__ import annotations

from pathlib import Path

import pytest

from oci_acme_publisher.locking import AdvisoryLock, LockUnavailableError


def test_second_host_local_lock_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "renew.lock"
    first = AdvisoryLock(path)
    second = AdvisoryLock(path)
    first.acquire()
    try:
        with pytest.raises(LockUnavailableError):
            second.acquire()
    finally:
        first.release()
