"""End-to-end tests for running a command in a sandboxed project.

Runs the real CLI in a subprocess so bwrap, the init script and the stdio
plumbing are all exercised. Skipped unless bwrap is available.
Opt-in: `pytest -m integration`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.real_probe]


@pytest.fixture
def project(tmp_path: Path) -> tuple[dict[str, str], Path, Path]:
    """A sandboxed project config under a private XDG_CONFIG_HOME."""
    if not shutil.which("bwrap"):
        pytest.skip("bwrap not on PATH")

    xdg = tmp_path / "xdg"
    conf_dir = xdg / "pwrap" / "runproj"
    conf_dir.mkdir(parents=True)
    for path in (xdg / "pwrap", conf_dir):
        path.chmod(0o700)
    work = tmp_path / "work"
    work.mkdir()
    config = conf_dir / "project.toml"
    config.write_text(
        f'[project]\ndir = "{work}"\nshell = "/bin/bash"\n\n[sandbox]\nenabled = true\n'
    )
    config.chmod(0o600)

    env = {**os.environ, "XDG_CONFIG_HOME": str(xdg)}
    return env, conf_dir, work


def _pwrap(env: dict[str, str], *args: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "project_wrap.cli", *args],
        input=stdin, capture_output=True, text=True, env=env, timeout=30,
    )


def test_stdio_and_exit_code_pass_through(project):
    env, conf_dir, work = project
    (conf_dir / "init.sh").write_text("echo from-init\n")

    result = _pwrap(env, "runproj", "--", "sh", "-c", 'cat; echo "$PWD"; exit 7', stdin="abc\n")

    assert result.returncode == 7
    # stdout is the command's alone: no banner, no init output
    assert result.stdout == f"abc\n{work}\n"
    assert "Loading" in result.stderr
    assert "from-init" in result.stderr


def test_verbose_output_stays_off_stdout(project):
    env, _, _ = project

    result = _pwrap(env, "-v", "runproj", "--", "echo", "ran")

    assert result.returncode == 0
    assert result.stdout == "ran\n"
    assert "bwrap" in result.stderr


def test_failing_init_stops_the_command(project):
    env, conf_dir, _ = project
    (conf_dir / "init.sh").write_text("echo init-ran >&2\nfalse\n")

    result = _pwrap(env, "runproj", "--", "echo", "ran")

    # init's own status, not a sandbox setup failure
    assert result.returncode == 1
    assert "init-ran" in result.stderr
    assert result.stdout == ""
