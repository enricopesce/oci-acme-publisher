"""Filesystem confinement for HTTP-01 challenge files."""

from __future__ import annotations

import os
import pwd
import stat
from dataclasses import dataclass
from pathlib import Path


class ChallengeFileError(Exception):
    """A challenge file is absent or fails the responder safety policy."""


def publisher_uid() -> int:
    """Resolve the configured system publisher account without falling back."""
    try:
        return pwd.getpwnam("oci-acme-publisher").pw_uid
    except KeyError as error:
        raise ChallengeFileError("publisher account is not available") from error


@dataclass(frozen=True, slots=True)
class ChallengeFileReader:
    """Read a single token using descriptor-relative, symlink-safe traversal."""

    webroot_base: Path
    max_file_bytes: int
    expected_owner_uid: int

    def read(self, webroot_id: str, token: str) -> bytes:
        """Read a bounded regular file, never resolving input as a path."""
        parent_fd = self._open_challenge_directory(webroot_id)
        try:
            return self._read_token(parent_fd, token)
        finally:
            os.close(parent_fd)

    def _open_challenge_directory(self, webroot_id: str) -> int:
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        current_fd = os.open(self.webroot_base, flags | nofollow)
        try:
            for component in (webroot_id, ".well-known", "acme-challenge"):
                next_fd = os.open(component, flags | nofollow, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
            return current_fd
        except OSError as error:
            os.close(current_fd)
            raise ChallengeFileError("challenge directory is unavailable") from error

    def _read_token(self, parent_fd: int, token: str) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            file_fd = os.open(token, flags, dir_fd=parent_fd)
        except OSError as error:
            raise ChallengeFileError("challenge file is unavailable") from error
        try:
            metadata = os.fstat(file_fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ChallengeFileError("challenge file is not regular")
            if metadata.st_uid != self.expected_owner_uid:
                raise ChallengeFileError("challenge file ownership is invalid")
            if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ChallengeFileError("challenge file permissions are unsafe")
            if metadata.st_size > self.max_file_bytes:
                raise ChallengeFileError("challenge file exceeds maximum size")
            content = os.read(file_fd, self.max_file_bytes + 1)
            if len(content) > self.max_file_bytes:
                raise ChallengeFileError("challenge file exceeds maximum size")
            return content
        finally:
            os.close(file_fd)
