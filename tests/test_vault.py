"""Unit tests for vault concurrency handling and attach-password verification."""

from __future__ import annotations

import fcntl
import multiprocessing
import os
import time

import pytest

from project_wrap import vault
from project_wrap.vault import _check_password, _password_verifier


@pytest.fixture
def runtime_dir(tmp_path, monkeypatch):
    """Redirect vault runtime dir (lockfiles, sockets) to a pytest tmp dir."""
    monkeypatch.setattr(vault, "_runtime_dir", lambda: tmp_path)
    return tmp_path


def _hold_lock(lock_path: str, ready_fd: int, release_fd: int) -> None:
    """Child helper: acquire LOCK_EX, signal ready, wait for release."""
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    os.write(ready_fd, b"x")
    os.close(ready_fd)
    os.read(release_fd, 1)
    os.close(release_fd)
    os.close(fd)


def test_check_concurrent_does_not_deadlock_on_consent(runtime_dir, monkeypatch):
    """After user confirms, _check_concurrent must return without blocking.

    Regression: previously the consent branch called flock(LOCK_SH) which
    blocks forever because the primary holds LOCK_EX.
    """
    project = "deadlock-probe"
    lock_path = str(runtime_dir / f"{project}.lock")

    ready_r, ready_w = os.pipe()
    release_r, release_w = os.pipe()

    ctx = multiprocessing.get_context("fork")
    holder = ctx.Process(target=_hold_lock, args=(lock_path, ready_w, release_r))
    holder.start()
    os.close(ready_w)
    os.close(release_r)

    try:
        # Wait for the child to acquire LOCK_EX.
        assert os.read(ready_r, 1) == b"x"
        os.close(ready_r)

        monkeypatch.setattr("builtins.input", lambda _prompt="": "")

        start = time.monotonic()
        fd = vault._check_concurrent(project)
        elapsed = time.monotonic() - start

        assert fd is not None
        assert elapsed < 1.0, f"_check_concurrent blocked for {elapsed:.2f}s"
        os.close(fd)
    finally:
        os.write(release_w, b"x")
        os.close(release_w)
        holder.join(timeout=2)
        if holder.is_alive():
            holder.terminate()
            holder.join()


def test_check_concurrent_returns_fd_when_uncontended(runtime_dir):
    """Uncontested path still returns an fd holding LOCK_EX."""
    fd = vault._check_concurrent("uncontested")
    try:
        assert fd is not None
        # LOCK_EX held — LOCK_EX | LOCK_NB from another fd must fail.
        other = os.open(
            str(runtime_dir / "uncontested.lock"),
            os.O_CREAT | os.O_RDWR,
            0o600,
        )
        try:
            with pytest.raises(OSError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(other)
    finally:
        if fd is not None:
            os.close(fd)


def test_check_concurrent_abort_returns_none(runtime_dir, monkeypatch):
    """Ctrl-C at the prompt aborts without returning an fd."""
    project = "abort-probe"
    lock_path = str(runtime_dir / f"{project}.lock")

    ready_r, ready_w = os.pipe()
    release_r, release_w = os.pipe()

    ctx = multiprocessing.get_context("fork")
    holder = ctx.Process(target=_hold_lock, args=(lock_path, ready_w, release_r))
    holder.start()
    os.close(ready_w)
    os.close(release_r)

    try:
        assert os.read(ready_r, 1) == b"x"
        os.close(ready_r)

        def _raise(_prompt: str = "") -> str:
            raise KeyboardInterrupt

        monkeypatch.setattr("builtins.input", _raise)

        assert vault._check_concurrent(project) is None
    finally:
        os.write(release_w, b"x")
        os.close(release_w)
        holder.join(timeout=2)
        if holder.is_alive():
            holder.terminate()
            holder.join()


class TestPasswordVerifier:
    """Tests for the per-session scrypt verifier used by shared vaults."""

    def test_correct_password_accepted(self):
        salt, digest = _password_verifier("hunter2")
        assert _check_password("hunter2", salt, digest)

    def test_wrong_password_rejected(self):
        salt, digest = _password_verifier("hunter2")
        assert not _check_password("hunter3", salt, digest)

    def test_empty_password_round_trips(self):
        salt, digest = _password_verifier("")
        assert _check_password("", salt, digest)
        assert not _check_password("x", salt, digest)

    def test_verifier_is_salted_per_session(self):
        salt_a, digest_a = _password_verifier("same-password")
        salt_b, digest_b = _password_verifier("same-password")
        assert salt_a != salt_b
        assert digest_a != digest_b

    def test_unicode_password_round_trips(self):
        salt, digest = _password_verifier("pässwörd- секрет")
        assert _check_password("pässwörd- секрет", salt, digest)

    def test_lone_surrogate_rejected_not_raised(self):
        # A lone surrogate cannot be encoded to UTF-8; the check must reject
        # it instead of raising into the serve accept loop.
        salt, digest = _password_verifier("hunter2")
        assert not _check_password("\ud800", salt, digest)

    def test_plaintext_not_derivable_from_verifier(self):
        # The verifier must not contain the password itself.
        salt, digest = _password_verifier("hunter2")
        assert b"hunter2" not in salt + digest
