"""Tests for the pty front-end (pty_runner) and its wiring in run_project.

The unit tests spawn a "driver" process on a pty pair that mimics the host
terminal: the driver becomes a session leader on the slave and calls
run_on_pty, which execs the child on a second (inner) pty. The test then
drives the outer master — writing input and resizing via TIOCSWINSZ — and
asserts what the inner child observes.

The integration tests run the real `pwrap <project>` CLI under a pty with a
real bwrap sandbox and assert that `stty size` inside the sandbox tracks
resizes of the controlling pty.
"""

from __future__ import annotations

import fcntl
import os
import pty
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

import pytest

from project_wrap import core
from project_wrap.core import ProjectExec, run_project
from project_wrap.pty_runner import run_on_pty
from project_wrap.vault import VaultConfig

# Probe run inside the inner pty: prints its window size, reports SIGWINCH,
# and confirms it runs on a controlling tty.
PROBE = """
import fcntl, os, signal, struct, termios, time
def g():
    return struct.unpack('hhhh', fcntl.ioctl(0, termios.TIOCGWINSZ, bytes(8)))[:2]
print('SIZE', *g(), flush=True)
print('CTTY', os.isatty(0), os.getsid(0) == os.getpid(), flush=True)
n = []
def h(s, f):
    n.append(1)
    print('WINCH', *g(), flush=True)
signal.signal(signal.SIGWINCH, h)
t = time.time() + 8
while time.time() < t and len(n) < 1:
    time.sleep(0.1)
print('DONE', *g(), flush=True)
"""


def _set_winsz(fd: int, rows: int, cols: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("hhhh", rows, cols, 0, 0))


def _read_until(master: int, pattern: bytes, buf: bytes = b"", timeout: float = 15.0) -> bytes:
    """Read from master until pattern matches the accumulated output."""
    if re.search(pattern, buf):
        return buf
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rfds, _, _ = select.select([master], [], [], 0.2)
        if master in rfds:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            buf += data
            if re.search(pattern, buf):
                return buf
    raise AssertionError(f"pattern {pattern!r} not seen within {timeout}s; got: {buf!r}")


def _wait_exit(pid: int, timeout: float = 15.0) -> int:
    """Wait for pid to exit; return its wait status. Kill on timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            return status
        time.sleep(0.05)
    os.kill(pid, signal.SIGKILL)
    _, status = os.waitpid(pid, 0)
    raise AssertionError(f"process {pid} did not exit within {timeout}s")


def _wait_host_raw(master: int, timeout: float = 5.0) -> None:
    """Wait until the driver has put the host tty into raw mode (ECHO off)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not (termios.tcgetattr(master)[3] & termios.ECHO):
            return
        time.sleep(0.05)
    raise AssertionError("driver did not put the host tty into raw mode")


def _spawn_pty_driver(host_master: int, host_slave: int, argv: list[str]) -> int:
    """Fork a driver: session leader on host_slave, runs run_on_pty(argv).

    Mirrors production: pwrap's stdin is the host tty (here host_slave), and
    run_on_pty execs argv on an inner pty. Returns the driver pid.
    """
    pid = os.fork()
    if pid == 0:
        try:
            os.close(host_master)
            os.setsid()
            fcntl.ioctl(host_slave, termios.TIOCSCTTY, 0)
            os.dup2(host_slave, 0)
            os.dup2(host_slave, 1)
            os.dup2(host_slave, 2)
            if host_slave > 2:
                os.close(host_slave)
            code = run_on_pty(lambda: os.execvp(argv[0], argv))
            os._exit(code)
        except BaseException:
            os._exit(127)
    os.close(host_slave)
    return pid


def _cleanup(pid: int, master: int) -> None:
    try:
        os.close(master)
    except OSError:
        pass
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


class TestRunOnPty:
    """Unit tests for run_on_pty (no bwrap needed)."""

    def test_resize_propagates_to_child(self):
        host_master, host_slave = pty.openpty()
        _set_winsz(host_master, 24, 80)
        pid = _spawn_pty_driver(host_master, host_slave, [sys.executable, "-c", PROBE])
        try:
            # Initial size is copied onto the inner pty before spawning.
            out = _read_until(host_master, rb"SIZE 24 80")
            # Child runs on a controlling tty in its own session.
            out = _read_until(host_master, rb"CTTY True True", out)
            # Resize the "host terminal": SIGWINCH -> TIOCSWINSZ on the
            # inner master -> SIGWINCH inside the child.
            _set_winsz(host_master, 40, 120)
            out = _read_until(host_master, rb"WINCH 40 120", out)
            _read_until(host_master, rb"DONE 40 120", out)
            status = _wait_exit(pid)
            assert os.WIFEXITED(status)
            assert os.WEXITSTATUS(status) == 0
        finally:
            _cleanup(pid, host_master)

    def test_resize_with_interactive_shell_no_bwrap(self):
        host_master, host_slave = pty.openpty()
        _set_winsz(host_master, 24, 80)
        pid = _spawn_pty_driver(host_master, host_slave, ["/bin/sh"])
        try:
            _wait_host_raw(host_master)
            os.write(host_master, b"stty size\n")
            out = _read_until(host_master, rb"24 80")
            _set_winsz(host_master, 40, 120)
            os.write(host_master, b"stty size\n")
            out = _read_until(host_master, rb"40 120", out)
            os.write(host_master, b"exit 7\n")
            status = _wait_exit(pid)
            assert os.WIFEXITED(status)
            assert os.WEXITSTATUS(status) == 7, f"out={out!r}"
        finally:
            _cleanup(pid, host_master)

    def test_relays_io_and_tty_signals(self):
        host_master, host_slave = pty.openpty()
        pid = _spawn_pty_driver(host_master, host_slave, ["cat"])
        try:
            _wait_host_raw(host_master)  # driver is in the relay loop now
            os.write(host_master, b"hello pwrap\n")
            out = _read_until(host_master, rb"hello pwrap")
            # Let both the pty echo and cat's output arrive, then count:
            # echoed once by the pty line discipline, once by cat — not
            # double-echoed by the host tty (which is in raw mode).
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline:
                rfds, _, _ = select.select([host_master], [], [], 0.2)
                if host_master in rfds:
                    try:
                        out += os.read(host_master, 65536)
                    except OSError:
                        break
            assert out.count(b"hello pwrap") == 2
            # Ctrl-C byte flows through the relay; the pty slave's ISIG
            # delivers SIGINT to the child's foreground process group.
            os.write(host_master, b"\x03")
            status = _wait_exit(pid)
            assert os.WIFEXITED(status)
            assert os.WEXITSTATUS(status) == 128 + signal.SIGINT
        finally:
            _cleanup(pid, host_master)

    def test_exit_status_propagates(self):
        host_master, host_slave = pty.openpty()
        pid = _spawn_pty_driver(host_master, host_slave, ["sh", "-c", "exit 42"])
        try:
            status = _wait_exit(pid)
            assert os.WIFEXITED(status)
            assert os.WEXITSTATUS(status) == 42
        finally:
            _cleanup(pid, host_master)

    def test_forwards_sigterm_to_child_process_group(self):
        host_master, host_slave = pty.openpty()
        pid = _spawn_pty_driver(host_master, host_slave, ["sleep", "60"])
        try:
            time.sleep(0.5)  # let the child exec
            os.kill(pid, signal.SIGTERM)
            status = _wait_exit(pid)
            assert os.WIFEXITED(status)
            assert os.WEXITSTATUS(status) == 128 + signal.SIGTERM
        finally:
            _cleanup(pid, host_master)

    def test_restores_host_tty_state(self):
        host_master, host_slave = pty.openpty()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(host_master)
                os.setsid()
                fcntl.ioctl(host_slave, termios.TIOCSCTTY, 0)
                os.dup2(host_slave, 0)
                os.dup2(host_slave, 1)
                os.dup2(host_slave, 2)
                if host_slave > 2:
                    os.close(host_slave)
                before = termios.tcgetattr(0)
                code = run_on_pty(lambda: os.execvp("true", ["true"]))
                after = termios.tcgetattr(0)
                os._exit(0 if (code == 0 and before == after) else 1)
            except BaseException:
                os._exit(127)
        os.close(host_slave)
        try:
            status = _wait_exit(pid)
            assert os.WIFEXITED(status)
            assert os.WEXITSTATUS(status) == 0, "host tty attrs not restored"
        finally:
            _cleanup(pid, host_master)


class TestRunProjectDispatch:
    """run_project picks the pty front-end iff stdin is a tty."""

    def _fake_result(self, vault: bool = False) -> ProjectExec:
        return ProjectExec(
            display_name="disp",
            program="/bin/echo",
            argv=["/bin/echo", "hi"],
            is_sandboxed=True,
            vault_config=(
                VaultConfig(
                    cipherdir=Path("/tmp/x"), mountpoint=Path("/tmp/y"),
                    project_name="p",
                )
                if vault
                else None
            ),
        )

    def test_tty_stdin_uses_pty_front_end(self, monkeypatch):
        captured = {}

        def fake_run_on_pty(child_fn, host_fd=0, host_out_fd=1):
            captured["child_fn"] = child_fn
            return 7

        monkeypatch.setattr("project_wrap.pty_runner.run_on_pty", fake_run_on_pty)
        monkeypatch.setattr(os, "isatty", lambda fd: True)
        monkeypatch.setattr(
            core, "prepare_project", lambda name, verbose=False, command=None: self._fake_result()
        )

        def fake_execvp(program, argv):
            raise RuntimeError(f"execvp {program}")

        monkeypatch.setattr(os, "execvp", fake_execvp)

        with pytest.raises(SystemExit) as exc_info:
            run_project("proj")
        assert exc_info.value.code == 7
        # The captured child runs the plain exec chain unchanged.
        with pytest.raises(RuntimeError, match="execvp /bin/echo"):
            captured["child_fn"]()

    def test_tty_stdin_vault_path_goes_through_pty(self, monkeypatch):
        captured = {}

        def fake_run_on_pty(child_fn, host_fd=0, host_out_fd=1):
            captured["child_fn"] = child_fn
            return 0

        monkeypatch.setattr("project_wrap.pty_runner.run_on_pty", fake_run_on_pty)
        monkeypatch.setattr(os, "isatty", lambda fd: True)
        monkeypatch.setattr(
            core,
            "prepare_project",
            lambda name, verbose=False, command=None: self._fake_result(vault=True),
        )
        seen = {}

        def fake_run_vault(config, argv):
            seen["argv"] = argv
            return 5

        monkeypatch.setattr("project_wrap.vault.run_vault", fake_run_vault)

        with pytest.raises(SystemExit) as exc_info:
            run_project("proj")
        assert exc_info.value.code == 0
        with pytest.raises(SystemExit) as child_exc:
            captured["child_fn"]()
        assert child_exc.value.code == 5
        assert seen["argv"] == ["/bin/echo", "hi"]

    def test_non_tty_stdin_keeps_plain_exec(self, monkeypatch):
        called = []

        def fake_run_on_pty(child_fn, host_fd=0, host_out_fd=1):
            called.append(child_fn)
            return 7

        monkeypatch.setattr("project_wrap.pty_runner.run_on_pty", fake_run_on_pty)
        monkeypatch.setattr(os, "isatty", lambda fd: False)
        monkeypatch.setattr(
            core, "prepare_project", lambda name, verbose=False, command=None: self._fake_result()
        )

        def fake_execvp(program, argv):
            raise RuntimeError(f"execvp {program}")

        monkeypatch.setattr(os, "execvp", fake_execvp)

        with pytest.raises(RuntimeError, match="execvp /bin/echo"):
            run_project("proj")
        assert called == []

    def test_command_with_redirected_stdout_keeps_plain_exec(self, monkeypatch):
        """`pwrap p -- cmd > file` from a terminal: no pty, so stderr stays out of stdout."""
        called = []

        def fake_run_on_pty(child_fn, host_fd=0, host_out_fd=1):
            called.append(child_fn)
            return 7

        monkeypatch.setattr("project_wrap.pty_runner.run_on_pty", fake_run_on_pty)
        monkeypatch.setattr(os, "isatty", lambda fd: fd == 0)
        monkeypatch.setattr(
            core, "prepare_project", lambda name, verbose=False, command=None: self._fake_result()
        )

        def fake_execvp(program, argv):
            raise RuntimeError(f"execvp {program}")

        monkeypatch.setattr(os, "execvp", fake_execvp)

        with pytest.raises(RuntimeError, match="execvp /bin/echo"):
            run_project("proj", command=["/bin/echo", "hi"])
        assert called == []

    def test_command_on_a_terminal_uses_pty(self, monkeypatch):
        called = []

        def fake_run_on_pty(child_fn, host_fd=0, host_out_fd=1):
            called.append(child_fn)
            return 0

        monkeypatch.setattr("project_wrap.pty_runner.run_on_pty", fake_run_on_pty)
        monkeypatch.setattr(os, "isatty", lambda fd: True)
        monkeypatch.setattr(
            core, "prepare_project", lambda name, verbose=False, command=None: self._fake_result()
        )
        with pytest.raises(SystemExit):
            run_project("proj", command=["/bin/echo", "hi"])
        assert len(called) == 1


def _write_project(xdg_root: Path, name: str, work: Path, sandboxed: bool,
                   extra_sandbox: str = "") -> None:
    # get_config_dir() is $XDG_CONFIG_HOME/pwrap
    proj_conf = xdg_root / "pwrap" / name
    proj_conf.mkdir(parents=True)
    (proj_conf / "project.toml").write_text(
        f'[project]\nname = "{name}"\ndir = "{work}"\nshell = "/bin/sh"\n'
        f"\n[sandbox]\nenabled = {'true' if sandboxed else 'false'}\n{extra_sandbox}"
    )


def _cli_env(xdg_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["XDG_CONFIG_HOME"] = str(xdg_root)
    env.pop("TMUX", None)  # never rename the developer's tmux window from tests
    return env


def test_noninteractive_fallback_piped_stdio(tmp_path):
    """Piped stdin/stdout: plain exec, no pty, exit status propagates."""
    xdg_root = tmp_path / "xdg"
    work = tmp_path / "work"
    work.mkdir()
    _write_project(xdg_root, "pipeproj", work, sandboxed=False)

    proc = subprocess.run(
        [sys.executable, "-m", "project_wrap.cli", "pipeproj"],
        input=b"echo MARKER-$((6*7)); test -t 0 && echo IS_TTY || echo NOT_TTY; exit 3\n",
        capture_output=True,
        env=_cli_env(xdg_root),
        timeout=30,
    )
    out = proc.stdout.decode()
    assert "MARKER-42" in out
    assert "NOT_TTY" in out
    assert "IS_TTY" not in out
    assert proc.returncode == 3


@pytest.mark.integration
def test_sandboxed_shell_observes_pty_resize(tmp_path):
    """End-to-end: pwrap project under a pty; resize the controlling pty via
    ioctl and assert `stty size` inside the bwrap sandbox reports the new
    size."""
    if shutil.which("bwrap") is None:
        pytest.skip("bwrap not available")
    xdg_root = tmp_path / "xdg"
    work = tmp_path / "work"
    work.mkdir()
    # unshare_pid = false: dash as PID 1 in the pid ns exits after one command
    # (pre-existing bwrap/dash behavior, unrelated to the pty front-end).
    _write_project(xdg_root, "ptyproj", work, sandboxed=True, extra_sandbox="unshare_pid = false\n")
    env = _cli_env(xdg_root)

    host_master, host_slave = pty.openpty()
    _set_winsz(host_master, 24, 80)
    pid = os.fork()
    if pid == 0:
        try:
            os.close(host_master)
            os.setsid()
            fcntl.ioctl(host_slave, termios.TIOCSCTTY, 0)
            os.dup2(host_slave, 0)
            os.dup2(host_slave, 1)
            os.dup2(host_slave, 2)
            if host_slave > 2:
                os.close(host_slave)
            os.execvpe(
                sys.executable,
                [sys.executable, "-m", "project_wrap.cli", "ptyproj"],
                env,
            )
        except BaseException:
            os._exit(127)
    os.close(host_slave)
    try:
        _read_until(host_master, rb"Loading ptyproj", timeout=30)
        _wait_host_raw(host_master)
        os.write(host_master, b"echo HELLO; stty size\n")
        out = _read_until(host_master, rb"24 80")

        # Resize the controlling pty — this is what tmux does on window resize.
        _set_winsz(host_master, 40, 120)
        os.write(host_master, b"stty size\n")
        out = _read_until(host_master, rb"40 120", out)

        os.write(host_master, b"exit\n")
        status = _wait_exit(pid, timeout=30)
        assert os.WIFEXITED(status)
        assert os.WEXITSTATUS(status) == 0, f"session output: {out!r}"
    finally:
        _cleanup(pid, host_master)


@pytest.mark.integration
def test_sandboxed_noninteractive_fallback(tmp_path):
    """Sandboxed project with piped stdio: no pty is allocated inside the
    sandbox and the plain exec path is used unchanged."""
    if shutil.which("bwrap") is None:
        pytest.skip("bwrap not available")
    xdg_root = tmp_path / "xdg"
    work = tmp_path / "work"
    work.mkdir()
    _write_project(xdg_root, "pipeproj", work, sandboxed=True)

    proc = subprocess.run(
        [sys.executable, "-m", "project_wrap.cli", "pipeproj"],
        input=b"test -t 0 && echo IS_TTY || echo NOT_TTY; exit 5\n",
        capture_output=True,
        env=_cli_env(xdg_root),
        timeout=60,
    )
    assert b"NOT_TTY" in proc.stdout
    assert b"IS_TTY" not in proc.stdout
    assert proc.returncode == 5
