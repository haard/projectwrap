"""PTY front-end for interactive project launches.

When pwrap starts a project shell on a terminal (stdin is a tty), the sandbox
exec chain runs on a pty allocated by pwrap itself instead of inheriting the
host tty directly. The parent relays I/O between the host tty and the pty
master and, on every SIGWINCH, copies the host window size onto the master
(TIOCSWINSZ), which delivers SIGWINCH to the sandbox's foreground process
group. Terminal resizes (e.g. a tmux window resize) therefore show up
immediately inside the sandbox — `stty size` and full-screen TUIs no longer
freeze at the size the sandbox was entered with.

The sandbox only ever sees pwrap's own pty slave: the host /dev and /dev/pts
are never bound in, so host pty nodes (TIOCSTI injection targets) and host
/dev/shm stay unreachable from inside the sandbox.

Non-interactive launches (piped stdin) do not use this module; they keep the
plain exec behaviour.
"""

from __future__ import annotations

import fcntl
import os
import pty
import select
import signal
import termios
import tty
from collections.abc import Callable
from typing import Any

_WINSZ = b"\x00" * 8  # struct winsize: rows, cols, xpixel, ypixel


def _get_winsz(fd: int) -> bytes:
    """Read the window size of a tty fd (TIOCGWINSZ)."""
    return fcntl.ioctl(fd, termios.TIOCGWINSZ, _WINSZ)


def _set_winsz(fd: int, winsz: bytes) -> None:
    """Set the window size of a pty master (TIOCSWINSZ).

    On a pty master this also delivers SIGWINCH to the foreground process
    group of the slave's session — i.e. to the sandbox shell.
    """
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsz)


def _write_all(fd: int, data: bytes) -> None:
    """Write all of data to fd, retrying on partial writes."""
    while data:
        data = data[os.write(fd, data):]


def run_on_pty(child_fn: Callable[[], None], host_fd: int = 0, host_out_fd: int = 1) -> int:
    """Run child_fn on a fresh pty wired to the host terminal.

    child_fn must not return — it should exec the sandbox chain (plain or
    vault path). The child becomes a session leader with the pty slave as
    its controlling terminal and stdio dup2'd onto it, so tty-generated
    signals (Ctrl-C, Ctrl-\\, ...) reach it through the pty line discipline.

    The parent puts the host tty (host_fd) into raw mode (single echo, no
    double signal generation — the pty slave carries the copied line
    discipline), relays input from host_fd and output to host_out_fd, keeps
    the master's window size in sync with the host tty on every SIGWINCH,
    forwards SIGINT/SIGTERM/SIGHUP to the child's process group, restores
    the host tty state on exit, and reaps the child.

    Returns the child's exit status: the exit code, or 128+signo if the
    child was killed by a signal.
    """
    master, slave = pty.openpty()

    # The sandbox must start with the host terminal's line discipline and
    # size; the parent keeps the size in sync on every SIGWINCH.
    try:
        host_attrs: list[Any] | None = termios.tcgetattr(host_fd)
    except termios.error:
        host_attrs = None
    if host_attrs is not None:
        termios.tcsetattr(slave, termios.TCSANOW, host_attrs)
    try:
        _set_winsz(master, _get_winsz(host_fd))
    except OSError:
        pass

    pid = os.fork()
    if pid == 0:
        # Child: new session, pty slave as controlling terminal, stdio on
        # the slave, then run the exec chain unchanged. Other inherited fds
        # are deliberately left alone — the vault path passes its lock fd
        # through exec (bwrap does not close inherited fds).
        try:
            os.close(master)
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            os.dup2(slave, 0)
            os.dup2(slave, 1)
            os.dup2(slave, 2)
            if slave > 2:
                os.close(slave)
            child_fn()
        except SystemExit as e:
            os._exit(e.code if isinstance(e.code, int) else 1)
        except BaseException as e:
            try:
                os.write(2, f"pwrap: pty child failed: {e}\n".encode())
            except OSError:
                pass
        os._exit(127)

    # Parent: relay between the host tty and the pty master.
    os.close(slave)

    def _propagate_winsz(_signum: int, _frame: object) -> None:
        try:
            _set_winsz(master, _get_winsz(host_fd))
        except OSError:
            pass

    def _forward(signum: int, _frame: object) -> None:
        # The child is a session leader (setsid above), so its process group
        # id is its pid; killpg covers the whole exec chain (bwrap, shell).
        try:
            os.killpg(pid, signum)
        except (ProcessLookupError, PermissionError):
            pass

    prev_handlers: dict[int, Any] = {}
    for sig, handler in (
        (signal.SIGWINCH, _propagate_winsz),
        (signal.SIGINT, _forward),
        (signal.SIGTERM, _forward),
        (signal.SIGHUP, _forward),
    ):
        prev_handlers[sig] = signal.signal(sig, handler)

    status: int | None = None
    reaped = False
    try:
        if host_attrs is not None:
            tty.setraw(host_fd)
        while True:
            try:
                rfds, _, _ = select.select([host_fd, master], [], [], 0.2)
                if master in rfds:
                    data = os.read(master, 65536)
                    if not data:
                        break
                    _write_all(host_out_fd, data)
                if host_fd in rfds:
                    data = os.read(host_fd, 65536)
                    if not data:
                        break
                    _write_all(master, data)
            except OSError:
                break  # EIO: either side of the pty pair is closed
            if not reaped:
                try:
                    wpid, wstatus = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    reaped, status = True, 1
                else:
                    if wpid == pid:
                        reaped, status = True, wstatus
            elif not rfds:
                # Child reaped and the pty has gone quiet: drain complete.
                # (A stray sandbox process holding the slave open must not
                # keep pwrap alive after the shell exited.)
                break
    finally:
        for prev_sig, prev_handler in prev_handlers.items():
            signal.signal(prev_sig, prev_handler)
        if host_attrs is not None:
            try:
                termios.tcsetattr(host_fd, termios.TCSADRAIN, host_attrs)
            except termios.error:
                pass
        try:
            os.close(master)  # hangs up the child's session if still alive
        except OSError:
            pass

    if status is None:
        try:
            _, status = os.waitpid(pid, 0)
        except ChildProcessError:
            return 1
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 1
