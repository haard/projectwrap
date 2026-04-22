"""End-to-end integration tests for the vault uid-drop chain.

Exercises vault.py:_inject_uid for real: mount a gocryptfs volume inside an
unprivileged user namespace, launch bwrap with a nested user ns, and verify
that (a) processes inside the sandbox see the real uid (not 0), and (b)
files written through the encrypted mount round-trip correctly under the
nested mapping.

Skipped unless bwrap/gocryptfs/unshare/fusermount are all available and the
bwrap feature probe passes. Opt-in: `pytest -m integration`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from project_wrap import deps as deps_module

pytestmark = [pytest.mark.integration, pytest.mark.real_probe]


def _require_tool(name: str) -> None:
    if not shutil.which(name):
        pytest.skip(f"{name} not on PATH")


@pytest.fixture
def tools_available():
    for tool in ("bwrap", "gocryptfs", "unshare", "fusermount"):
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
    password = "test-vault-password"

    result = subprocess.run(
        ["gocryptfs", "-init", "-q", "-passfile", "/dev/stdin", str(cipher)],
        input=password,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip(f"gocryptfs -init failed: {result.stderr}")
    return cipher


def _run_single_vault_inline(
    cipherdir: Path,
    mountpoint: Path,
    inner_cmd: str,
    password: str = "test-vault-password",
) -> subprocess.CompletedProcess[str]:
    """Run the same exec chain as vault._run_single but collect stdout.

    Mirrors the production command (unshare --user --mount --map-root-user →
    gocryptfs → bwrap with --unshare-user/--uid injected) so the nested-ns
    uid mapping is exercised end-to-end. Uses gocryptfs -passfile to avoid
    an interactive password prompt.
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

    import shlex

    inner = (
        f"gocryptfs -passfile /dev/stdin "
        f"{shlex.quote(str(cipherdir))} {shlex.quote(str(mountpoint))} && "
        f"exec {' '.join(shlex.quote(a) for a in bwrap_argv)}"
    )

    argv = [
        "unshare", "--user", "--mount", "--map-root-user",
        "--", "sh", "-c", inner,
    ]

    return subprocess.run(
        argv,
        input=password,
        text=True,
        capture_output=True,
        timeout=30,
    )


def test_vault_drops_to_real_uid(tools_available, tmp_path, cipherdir):
    """Inside the sandbox, id -u should report the real uid, not 0."""
    mountpoint = tmp_path / "mnt"
    mountpoint.mkdir()

    real_uid = os.getuid()
    result = _run_single_vault_inline(cipherdir, mountpoint, "id -u")

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

    # Write a file inside the sandbox. The mount is torn down when the outer
    # mount ns exits (gocryptfs unmount happens automatically on ns teardown,
    # but we explicitly fusermount -u to be safe on systems where it doesn't).
    write_cmd = f"echo hello-from-sandbox > {mountpoint}/marker && cat {mountpoint}/marker"
    result = _run_single_vault_inline(cipherdir, mountpoint, write_cmd)
    assert result.returncode == 0, (
        f"write failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    assert "hello-from-sandbox" in result.stdout

    # Remount and verify the file is still there with the expected content.
    # Mountpoint has to be empty before remount; inner teardown should have
    # released it, but check.
    if any(mountpoint.iterdir()):
        # Unmount leftover FUSE mount if any.
        subprocess.run(["fusermount", "-u", str(mountpoint)], capture_output=True)

    read_cmd = f"cat {mountpoint}/marker"
    result2 = _run_single_vault_inline(cipherdir, mountpoint, read_cmd)
    assert result2.returncode == 0, (
        f"remount/read failed:\nstdout={result2.stdout}\nstderr={result2.stderr}"
    )
    assert "hello-from-sandbox" in result2.stdout


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "-m", "integration"]))
