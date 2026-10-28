"""End-to-end integration tests for the vault uid-drop chain.

Exercises vault.py:_inject_uid for real: mount a gocryptfs volume inside an
unprivileged user namespace, launch bwrap with a nested user ns, and verify
that (a) processes inside the sandbox see the real uid (not 0), and (b)
files written through the encrypted mount round-trip correctly under the
nested mapping.

Also covers the single-mode teardown: after a session exits (normally or
SIGKILLed), the gocryptfs daemon must be reaped and the project lock
released. The chain is built from the real vault._vault_watcher_script, so
the production teardown logic is what gets tested.

Skipped unless bwrap/gocryptfs/unshare/fusermount are all available and the
bwrap feature probe passes. Opt-in: `pytest -m integration`.
"""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from project_wrap import deps as deps_module
from project_wrap import vault

pytestmark = [pytest.mark.integration, pytest.mark.real_probe]

VAULT_PASSWORD = "test-vault-password"


def _require_tool(name: str) -> None:
    if not shutil.which(name):
        pytest.skip(f"{name} not on PATH")


@pytest.fixture
def tools_available():
    for tool in ("bwrap", "gocryptfs", "unshare", "fusermount", "flock", "lsns"):
        _require_tool(tool)

    deps_module._bwrap_probe_cache = None
    ok, reason = deps_module._probe_bwrap(shutil.which("bwrap") or "bwrap")
    if not ok:
        pytest.skip(f"bwrap feature probe failed: {reason}")


@pytest.fixture
def cipherdir(tmp_path: Path) -> Path:
    """Initialize a throwaway gocryptfs cipherdir with a known password."""
    cipher = tmp_path / "cipher"
    cipher.mkdir()

    result = subprocess.run(
        ["gocryptfs", "-init", "-q", "-passfile", "/dev/stdin", str(cipher)],
        input=VAULT_PASSWORD,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip(f"gocryptfs -init failed: {result.stderr}")
    return cipher


def _build_single_inner(
    cipherdir: Path,
    mountpoint: Path,
    inner_cmd: str,
    lockfile: Path,
) -> tuple[str, str]:
    """Build the production single-mode inner script (vault._run_single).

    Uses the real vault._vault_watcher_script so the teardown logic is
    exercised end-to-end. gocryptfs -passfile replaces the interactive
    password prompt. Returns (prefix, inner): the prefix opens and flocks
    fd 3, mirroring _run_single's inheritable lock fd.
    """
    uid = os.getuid()
    gid = os.getgid()

    bwrap_argv = [
        "bwrap",
        "--unshare-user", "--uid", str(uid), "--gid", str(gid),
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--bind", str(mountpoint), str(mountpoint),
        "--chdir", str(mountpoint),
        "sh", "-c", inner_cmd,
    ]
    bwrap_cmd = " ".join(shlex.quote(a) for a in bwrap_argv)

    prefix = f"exec 3>{shlex.quote(str(lockfile))}; flock -x 3; "
    inner = (
        f"gocryptfs -passfile /dev/stdin "
        f"{shlex.quote(str(cipherdir))} {shlex.quote(str(mountpoint))} && {{\n"
        f"{vault._vault_watcher_script(str(mountpoint), 3)}"
        f"exec {bwrap_cmd}\n"
        f"}}"
    )
    return prefix, inner


def _run_single_vault_inline(
    cipherdir: Path,
    mountpoint: Path,
    inner_cmd: str,
    lockfile: Path,
    password: str = VAULT_PASSWORD,
) -> subprocess.CompletedProcess[str]:
    """Run the production single-mode chain and collect output."""
    prefix, inner = _build_single_inner(cipherdir, mountpoint, inner_cmd, lockfile)
    argv = [
        "unshare", "--user", "--mount", "--map-root-user",
        "--", "sh", "-c", prefix + inner,
    ]
    return subprocess.run(
        argv,
        input=password,
        text=True,
        capture_output=True,
        timeout=30,
    )


def _gocryptfs_daemons_for(cipherdir: Path) -> list[str]:
    """Live gocryptfs daemon cmdlines referencing the cipherdir."""
    daemons = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "comm").read_text().strip() != "gocryptfs":
                continue
            cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode()
        except OSError:
            continue
        if str(cipherdir) in cmdline:
            daemons.append(cmdline)
    return daemons


def _mount_ns_holds_cipherdir(cipherdir: Path) -> bool:
    """True if any mount namespace still shows a process for the cipherdir."""
    result = subprocess.run(
        ["lsns", "-t", "mnt", "-o", "NS,COMMAND", "-n"],
        capture_output=True,
        text=True,
    )
    return str(cipherdir) in result.stdout


def _lock_is_free(lockfile: Path) -> bool:
    result = subprocess.run(
        ["flock", "-n", str(lockfile), "-c", "true"],
        capture_output=True,
    )
    return result.returncode == 0


def _wait_for(
    cond: Callable[[], bool], timeout: float = 10.0, interval: float = 0.2
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(interval)
    return cond()


def _kill_sandbox_orphans(mountpoint: Path) -> None:
    """Kill leftover sandbox processes whose cwd is the mountpoint.

    Killing bwrap orphans the sandbox shell (pre-existing behavior); it
    keeps the mount namespace alive until it exits. Tests clean up after
    themselves so they do not leak namespaces.
    """
    target = str(mountpoint)
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if os.readlink(entry / "cwd") == target:
                os.kill(int(entry.name), signal.SIGKILL)
        except (OSError, ValueError):
            continue


def test_vault_drops_to_real_uid(tools_available, tmp_path, cipherdir):
    """Inside the sandbox, id -u should report the real uid, not 0."""
    mountpoint = tmp_path / "mnt"
    mountpoint.mkdir()
    lockfile = tmp_path / "project.lock"

    real_uid = os.getuid()
    result = _run_single_vault_inline(cipherdir, mountpoint, "id -u", lockfile)

    assert result.returncode == 0, (
        f"vault chain failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    # stdout contains the id -u output from inside the sandbox
    assert str(real_uid) in result.stdout, (
        f"expected uid {real_uid} inside sandbox, got:\n{result.stdout}"
    )
    assert "\n0\n" not in result.stdout and not result.stdout.startswith("0\n"), (
        f"sandbox reported uid 0 — nested user-ns mapping not applied:\n"
        f"{result.stdout}"
    )


def test_vault_file_roundtrip_under_nested_mapping(
    tools_available, tmp_path, cipherdir
):
    """A file written inside the sandbox is readable on remount.

    Confirms that FUSE permissions survive the outer→nested user-ns hop: the
    file's on-host owner is the real uid, the outer ns sees it as uid 0, and
    the nested ns sees it as REAL_UID again.
    """
    mountpoint = tmp_path / "mnt"
    mountpoint.mkdir()
    lockfile = tmp_path / "project.lock"

    # Write a file inside the sandbox. The watcher unmounts and reaps the
    # daemon when the session exits, releasing the mountpoint.
    write_cmd = f"echo hello-from-sandbox > {mountpoint}/marker && cat {mountpoint}/marker"
    result = _run_single_vault_inline(cipherdir, mountpoint, write_cmd, lockfile)
    assert result.returncode == 0, (
        f"write failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    assert "hello-from-sandbox" in result.stdout

    # Remount and verify the file is still there with the expected content.
    # Mountpoint has to be empty before remount; the watcher teardown should
    # have released it, but check.
    if any(mountpoint.iterdir()):
        # Unmount leftover FUSE mount if any.
        subprocess.run(["fusermount", "-u", str(mountpoint)], capture_output=True)

    read_cmd = f"cat {mountpoint}/marker"
    result2 = _run_single_vault_inline(cipherdir, mountpoint, read_cmd, lockfile)
    assert result2.returncode == 0, (
        f"remount/read failed:\nstdout={result2.stdout}\nstderr={result2.stderr}"
    )
    assert "hello-from-sandbox" in result2.stdout


def test_single_vault_teardown_on_normal_exit(tools_available, tmp_path, cipherdir):
    """After a single-mode session exits, the gocryptfs daemon is reaped,
    its mount namespace is gone, and the project lock is released."""
    mountpoint = tmp_path / "mnt"
    mountpoint.mkdir()
    lockfile = tmp_path / "project.lock"

    result = _run_single_vault_inline(cipherdir, mountpoint, "echo done", lockfile)
    assert result.returncode == 0, (
        f"vault chain failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )

    assert _wait_for(lambda: not _gocryptfs_daemons_for(cipherdir)), (
        "gocryptfs daemon still running after session exit: "
        f"{_gocryptfs_daemons_for(cipherdir)}"
    )
    assert _wait_for(lambda: not _mount_ns_holds_cipherdir(cipherdir)), (
        "mount namespace still alive after session exit"
    )
    assert _lock_is_free(lockfile), "project lock still held after session exit"


def test_single_vault_teardown_after_sigkill(tools_available, tmp_path, cipherdir):
    """Even a SIGKILLed session reaps the daemon and releases the lock —
    the watcher is a separate process and survives the main process's death."""
    mountpoint = tmp_path / "mnt"
    mountpoint.mkdir()
    lockfile = tmp_path / "project.lock"

    prefix, inner = _build_single_inner(cipherdir, mountpoint, "sleep 30", lockfile)
    argv = [
        "unshare", "--user", "--mount", "--map-root-user",
        "--", "sh", "-c", prefix + inner,
    ]
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert proc.stdin is not None
        proc.stdin.write(VAULT_PASSWORD + "\n")
        proc.stdin.flush()
        proc.stdin.close()
        assert _wait_for(lambda: bool(_gocryptfs_daemons_for(cipherdir))), (
            "gocryptfs daemon did not start"
        )
        assert not _lock_is_free(lockfile), "lock not held mid-session"

        proc.kill()  # SIGKILL the main process (unshare/sh/bwrap)
        proc.wait(timeout=10)

        assert _wait_for(lambda: not _gocryptfs_daemons_for(cipherdir)), (
            "gocryptfs daemon still running after SIGKILL of the session: "
            f"{_gocryptfs_daemons_for(cipherdir)}"
        )
        assert _lock_is_free(lockfile), "project lock still held after SIGKILL"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        _kill_sandbox_orphans(mountpoint)


def test_single_vault_wrong_password_fails_closed(
    tools_available, tmp_path, cipherdir
):
    """A wrong password must abort before bwrap starts — the sandbox must
    never launch with the vault unmounted."""
    mountpoint = tmp_path / "mnt"
    mountpoint.mkdir()
    lockfile = tmp_path / "project.lock"

    result = _run_single_vault_inline(
        cipherdir,
        mountpoint,
        "echo SHOULD_NOT_RUN",
        lockfile,
        password="wrong-password",
    )
    assert result.returncode != 0
    assert "SHOULD_NOT_RUN" not in result.stdout
    assert _wait_for(lambda: not _gocryptfs_daemons_for(cipherdir))
    assert _lock_is_free(lockfile)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "-m", "integration"]))
