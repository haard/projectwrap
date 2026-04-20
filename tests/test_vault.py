"""Unit tests for vault concurrency handling."""

from __future__ import annotations

import fcntl
import multiprocessing
import os
import time

import pytest
from project_wrap import vault


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
