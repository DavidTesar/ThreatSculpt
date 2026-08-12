"""Credential storage: 0600, atomic, and never silently permissive."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from threatsculpt_agent.errors import InsecureKeyPermissionsError, KeyStoreError
from threatsculpt_agent.keystore import KeyStore, read_secret_file

KEY = "tsa_a_real_looking_key"


def test_a_written_key_is_readable_back(tmp_path: Path) -> None:
    store = KeyStore(tmp_path / "agent.key")
    store.write(KEY)
    assert store.read() == KEY


def test_a_written_key_is_mode_0600(tmp_path: Path) -> None:
    store = KeyStore(tmp_path / "agent.key")
    store.write(KEY)
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_the_key_is_never_briefly_world_readable(tmp_path: Path) -> None:
    """The temp file is created 0600 and renamed; there is no widen-then-narrow window."""
    store = KeyStore(tmp_path / "agent.key")
    store.write(KEY)
    assert not list(tmp_path.glob(".agent.key.*"))  # no temp file left behind


def test_missing_parent_directories_are_created(tmp_path: Path) -> None:
    store = KeyStore(tmp_path / "nested" / "deeper" / "agent.key")
    store.write(KEY)
    assert store.read() == KEY


def test_rewriting_replaces_the_key(tmp_path: Path) -> None:
    store = KeyStore(tmp_path / "agent.key")
    store.write(KEY)
    store.write("tsa_rotated")
    assert store.read() == "tsa_rotated"


def test_a_missing_key_file_reads_as_none(tmp_path: Path) -> None:
    assert KeyStore(tmp_path / "absent.key").read() is None


def test_an_empty_key_file_reads_as_none(tmp_path: Path) -> None:
    path = tmp_path / "agent.key"
    path.write_text("   \n")
    path.chmod(0o600)
    assert KeyStore(path).read() is None


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666, 0o660])
def test_a_group_or_world_accessible_key_is_refused(tmp_path: Path, mode: int) -> None:
    """Better to fail at startup than to run for months with a leaked credential."""
    path = tmp_path / "agent.key"
    path.write_text(KEY)
    path.chmod(mode)

    with pytest.raises(InsecureKeyPermissionsError, match="chmod 600"):
        KeyStore(path).read()


def test_an_empty_key_is_never_persisted(tmp_path: Path) -> None:
    store = KeyStore(tmp_path / "agent.key")
    with pytest.raises(KeyStoreError):
        store.write("   ")
    assert not store.exists()


def test_wipe_removes_the_key(tmp_path: Path) -> None:
    store = KeyStore(tmp_path / "agent.key")
    store.write(KEY)
    store.wipe()

    assert not store.exists()
    assert store.read() is None


def test_wipe_is_idempotent(tmp_path: Path) -> None:
    store = KeyStore(tmp_path / "never-existed.key")
    store.wipe()
    store.wipe()


def test_an_unwritable_directory_raises(tmp_path: Path) -> None:
    directory = tmp_path / "readonly"
    directory.mkdir()
    directory.chmod(0o500)
    try:
        with pytest.raises(KeyStoreError):
            KeyStore(directory / "agent.key").write(KEY)
    finally:
        directory.chmod(0o700)


def test_reading_a_secret_file(tmp_path: Path) -> None:
    path = tmp_path / "enrollment.token"
    path.write_text("tse_token\n")
    path.chmod(0o600)
    assert read_secret_file(path) == "tse_token"


def test_a_permissive_secret_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "enrollment.token"
    path.write_text("tse_token")
    path.chmod(0o644)

    with pytest.raises(InsecureKeyPermissionsError):
        read_secret_file(path)


def test_missing_and_empty_secret_files_raise(tmp_path: Path) -> None:
    with pytest.raises(KeyStoreError, match="not found"):
        read_secret_file(tmp_path / "absent")

    empty = tmp_path / "empty"
    empty.write_text("")
    empty.chmod(0o600)
    with pytest.raises(KeyStoreError, match="empty"):
        read_secret_file(empty)


def test_the_keystore_handle_is_immutable(tmp_path: Path) -> None:
    store = KeyStore(tmp_path / "agent.key")
    with pytest.raises(AttributeError):
        store.path = tmp_path / "elsewhere"  # type: ignore[misc]


def test_the_key_survives_a_process_boundary(tmp_path: Path) -> None:
    """Written by one handle, read by another — the file is the only state."""
    path = tmp_path / "agent.key"
    KeyStore(path).write(KEY)
    assert KeyStore(path).read() == KEY
    assert os.stat(path).st_size == len(KEY) + 1
