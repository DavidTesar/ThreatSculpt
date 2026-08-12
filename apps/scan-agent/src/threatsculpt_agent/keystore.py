"""Persistence for the permanent agent API key.

The key lives in a single file with mode 0600. Writes are atomic (temp file in the same
directory, created 0600 from the start, then os.replace) so a crash mid-write can never
leave a truncated key behind, and the key is never briefly world-readable.

Reads refuse a file whose mode grants group or other any access. Failing loudly beats
running for months with a customer's credential readable by every account on the box.
"""

from __future__ import annotations

import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .errors import InsecureKeyPermissionsError, KeyStoreError

KEY_FILE_MODE = 0o600
_FORBIDDEN_MODE_BITS = stat.S_IRWXG | stat.S_IRWXO


@dataclass(frozen=True, slots=True)
class KeyStore:
    """Reads/writes one 0600 key file. Immutable handle; all state is on disk."""

    path: Path

    def exists(self) -> bool:
        return self.path.is_file()

    def read(self) -> str | None:
        """Return the stored key, or None when no key file exists."""
        if not self.path.is_file():
            return None
        self._assert_secure_mode()
        try:
            content = self.path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise KeyStoreError(f"cannot read key file {self.path}: {exc}") from exc
        return content or None

    def write(self, api_key: str) -> None:
        """Atomically persist ``api_key`` at mode 0600."""
        if not api_key or not api_key.strip():
            raise KeyStoreError("refusing to persist an empty API key")
        directory = self.path.parent
        try:
            directory.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=".agent.key.")
            tmp_path = Path(tmp_name)
            try:
                os.fchmod(fd, KEY_FILE_MODE)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(api_key.strip())
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_path, self.path)
            except BaseException:
                tmp_path.unlink(missing_ok=True)
                raise
            self._fsync_directory(directory)
        except OSError as exc:
            raise KeyStoreError(f"cannot write key file {self.path}: {exc}") from exc

    def wipe(self) -> None:
        """Remove the stored key. Idempotent — a missing file is success."""
        try:
            self.path.unlink(missing_ok=True)
        except OSError as exc:
            raise KeyStoreError(f"cannot remove key file {self.path}: {exc}") from exc

    def _assert_secure_mode(self) -> None:
        mode = self.path.stat().st_mode
        if mode & _FORBIDDEN_MODE_BITS:
            raise InsecureKeyPermissionsError(
                f"{self.path} has mode {stat.filemode(mode)}; "
                f"it must not be accessible to group or other. Run: chmod 600 {self.path}"
            )

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def read_secret_file(path: Path) -> str:
    """Read a one-line secret (e.g. an enrollment token) from a 0600-ish file."""
    if not path.is_file():
        raise KeyStoreError(f"secret file not found: {path}")
    mode = path.stat().st_mode
    if mode & _FORBIDDEN_MODE_BITS:
        raise InsecureKeyPermissionsError(
            f"{path} has mode {stat.filemode(mode)}; run: chmod 600 {path}"
        )
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise KeyStoreError(f"cannot read secret file {path}: {exc}") from exc
    if not value:
        raise KeyStoreError(f"secret file is empty: {path}")
    return value
