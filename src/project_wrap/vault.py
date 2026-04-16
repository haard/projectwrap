"""Encrypted volume management using gocryptfs in isolated mount namespaces.

Two modes, both driven by `run_vault`:

- shared=False: unshare + gocryptfs + bwrap in one exec chain. A flock on the
  project lockfile detects concurrent sessions and prompts before joining.
- shared=True: the first terminal acquires the flock and re-execs into `serve`,
  which mounts gocryptfs, forks the primary bwrap via `_pty_proxy`, and listens
  on a unix socket for additional terminals to attach. When the primary exits,
  all attached clients are torn down and the mount is released. No background
  daemon — the serve process stays in the foreground of the terminal that
  launched it.
"""

from __future__ import annotations

import fcntl
import getpass
import hmac
import json
import os
import secrets
import shlex
import signal
import socket
import struct
import subprocess
import sys
import time
from array import array
from dataclasses import dataclass
from pathlib import Path


@dataclass
class VaultConfig:
    """Configuration for an encrypted volume."""

    cipherdir: Path
    mountpoint: Path
    project_name: str
    shared: bool = False


def _runtime_dir() -> Path:
    """Runtime directory for sockets and lock files."""
    d = Path(f"/tmp/pwrap-{os.getuid()}")
    d.mkdir(mode=0o700, exist_ok=True)
    return d


def _lock_path(project: str) -> Path:
    return _runtime_dir() / f"{project}.lock"


def _sock_path(project: str) -> Path:
    return _runtime_dir() / f"{project}.sock"


def _try_lock(project: str) -> int | None:
    """Try to acquire an exclusive flock. Returns fd if acquired, None if held."""
    lock = _lock_path(project)
    fd = os.open(str(lock), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except OSError:
        os.close(fd)
        return None


def _check_concurrent(project: str) -> int | None:
    """Check if another non-shared session is active.

    Returns a lock fd (exclusive or shared). None if the user aborted.
    """
    fd = _try_lock(project)
    if fd is not None:
        return fd

    print(
        f"Warning: another session for '{project}' is active.\n"
        "Changes to encrypted files may not be visible across sessions,\n"
        "and concurrent writes to the same file may cause lost updates.\n"
    )
    try:
        input("Press Enter to continue, Ctrl-C to abort: ")
    except (KeyboardInterrupt, EOFError):
        print()
        return None

    fd = os.open(str(_lock_path(project)), os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_SH)
    return fd


# --- fd passing helpers ---


def _send_fds(sock: socket.socket, fds: list[int], data: bytes) -> None:
    """Send file descriptors and data over a unix socket."""
    fds_array = array("i", fds)
    sock.sendmsg(
        [data],
        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds_array)],
    )


def _recv_fds(sock: socket.socket, maxfds: int = 3) -> tuple[bytes, list[int]]:
    """Receive file descriptors and data from a unix socket."""
    fds_array = array("i", [0] * maxfds)
    msg, ancdata, _flags, _addr = sock.recvmsg(
        4096,
        socket.CMSG_SPACE(maxfds * fds_array.itemsize),
    )
    fds: list[int] = []
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
            n = len(cmsg_data) // fds_array.itemsize
            received = array("i")
            received.frombytes(cmsg_data[: n * fds_array.itemsize])
            fds.extend(received)
    return msg, fds


# --- pty proxy ---


def _pty_proxy(bwrap_argv: list[str], client_fds: list[int]) -> None:
    """Run bwrap inside a pty and proxy I/O to client fds.

    Gives the shell a proper controlling terminal (needed for fish job control).
    Runs in a forked child of serve — does not return; exits with bwrap's status.
    """
    import pty
    import select
    import termios
    import tty

    client_in, client_out = client_fds[0], client_fds[1]

    try:
        old_attrs = termios.tcgetattr(client_in)
    except termios.error:
        old_attrs = None

    try:
        winsize = fcntl.ioctl(client_in, termios.TIOCGWINSZ, b"\x00" * 8)
    except OSError:
        winsize = None

    bwrap_pid, pty_fd = pty.fork()
    if bwrap_pid == 0:
        os.execvp(bwrap_argv[0], bwrap_argv)
        sys.exit(1)

    if winsize:
        fcntl.ioctl(pty_fd, termios.TIOCSWINSZ, winsize)

    if old_attrs:
        tty.setraw(client_in)

    try:
        while True:
            rfds, _, _ = select.select([pty_fd, client_in], [], [], 1.0)
            if pty_fd in rfds:
                try:
                    data = os.read(pty_fd, 4096)
                    if not data:
                        break
                    os.write(client_out, data)
                except OSError:
                    break
            if client_in in rfds:
                try:
                    data = os.read(client_in, 4096)
                    if not data:
                        break
                    os.write(pty_fd, data)
                except OSError:
                    break
    except Exception:
        pass
    finally:
        if old_attrs:
            try:
                termios.tcsetattr(client_in, termios.TCSAFLUSH, old_attrs)
            except termios.error:
                pass
        try:
            os.close(pty_fd)
        except OSError:
            pass
        for fd in client_fds:
            try:
                os.close(fd)
            except OSError:
                pass

    try:
        _, status = os.waitpid(bwrap_pid, 0)
        code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1
    except ChildProcessError:
        code = 1
    sys.exit(code)


# --- entry point ---


def run_vault(config: VaultConfig, bwrap_argv: list[str]) -> int:
    """Unified vault entry. Does not return on success for the primary path."""
    if not config.shared:
        return _run_single(config, bwrap_argv)

    lock_fd = _try_lock(config.project_name)
    if lock_fd is not None:
        _exec_primary_serve(config, bwrap_argv, lock_fd)
        return 1  # unreachable

    return _attach_to_primary(config, bwrap_argv)


def _run_single(config: VaultConfig, bwrap_argv: list[str]) -> int:
    """shared=False path: one unshare + gocryptfs + bwrap exec chain."""
    lock_fd = _check_concurrent(config.project_name)
    if lock_fd is None:
        return 130
    os.set_inheritable(lock_fd, True)

    # Capture real uid/gid before entering --map-root-user namespace; inject
    # into bwrap so the sandbox shell drops back to the real user identity.
    bwrap_with_uid = _inject_uid(bwrap_argv, os.getuid(), os.getgid())
    bwrap_cmd = " ".join(shlex.quote(a) for a in bwrap_with_uid)
    inner = (
        f"gocryptfs {shlex.quote(str(config.cipherdir))} "
        f"{shlex.quote(str(config.mountpoint))} && "
        f"exec {bwrap_cmd}"
    )
    argv = [
        "unshare", "--user", "--mount", "--map-root-user",
        "--", "sh", "-c", inner,
    ]
    os.execvp("unshare", argv)
    return 1  # unreachable


def _inject_uid(bwrap_argv: list[str], uid: int, gid: int) -> list[str]:
    """Inject --unshare-user --uid --gid so bwrap drops back to the real uid.

    User-namespace mapping chain for the vault path:

      1. Outer: `unshare --user --map-root-user` maps real uid -> 0 so we can
         mount gocryptfs (FUSE requires "root" in the user ns).
      2. gocryptfs mounts; files inside it are owned by uid 0 in the outer ns
         (= the real uid on the host kernel).
      3. bwrap creates a nested user ns via `--unshare-user` and writes a
         uid_map of {outer 0 -> nested REAL_UID}. We can only do this because
         we are "root" in the outer ns, which can write arbitrary mappings
         for a child ns.
      4. Processes inside the sandbox see files owned by REAL_UID and
         `id -u` / `whoami` report the real user — not root.

    Requires bwrap >= 0.4 with --unshare-user and --uid support; this is
    verified at startup by deps._probe_bwrap. The end-to-end chain is
    exercised by tests/test_vault_integration.py.
    """
    argv = list(bwrap_argv)
    argv[1:1] = ["--unshare-user", "--uid", str(uid), "--gid", str(gid)]
    return argv


def _exec_primary_serve(
    config: VaultConfig, bwrap_argv: list[str], lock_fd: int
) -> None:
    """Re-exec into `unshare ... python -m project_wrap.vault serve ...`.

    The flock fd is kept inheritable so the lock persists across the exec chain
    for the entire lifetime of the primary session.
    """
    os.set_inheritable(lock_fd, True)
    sock = _sock_path(config.project_name)
    argv = [
        "unshare", "--user", "--mount", "--map-root-user",
        "--", sys.executable, "-m", "project_wrap.vault", "serve",
        "--cipherdir", str(config.cipherdir),
        "--mountpoint", str(config.mountpoint),
        "--project", config.project_name,
        "--sock-path", str(sock),
        "--real-uid", str(os.getuid()),
        "--real-gid", str(os.getgid()),
        "--bwrap-argv", json.dumps(bwrap_argv),
    ]
    os.execvp("unshare", argv)


def _attach_to_primary(config: VaultConfig, bwrap_argv: list[str]) -> int:
    """Non-primary path: connect to the primary's socket and run as a child."""
    sock_path = _sock_path(config.project_name)

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connected = False
    for _ in range(10):
        try:
            client.connect(str(sock_path))
            connected = True
            break
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.2)
    if not connected:
        print(
            f"Primary vault session for '{config.project_name}' exists but is "
            "not accepting connections. Try again in a moment.",
            file=sys.stderr,
        )
        return 1

    token = getpass.getpass("Vault token: ")
    data = json.dumps({
        "token": token,
        "argv": bwrap_argv,
    }).encode()
    _send_fds(client, [0, 1, 2], data)

    chunks: list[bytes] = []
    while True:
        chunk = client.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
    client.close()
    response = b"".join(chunks)

    if len(response) >= 4:
        if len(response) > 4:
            try:
                msg = json.loads(response)
                if "error" in msg:
                    print(f"Error: {msg['error']}", file=sys.stderr)
                    return 1
            except (json.JSONDecodeError, ValueError):
                pass
        return struct.unpack("!i", response[:4])[0]

    return 1


# --- serve (primary, runs inside unshare namespace) ---


def _inject_token(bwrap_argv: list[str], token: str) -> list[str]:
    """Inject PWRAP_VAULT_TOKEN via bwrap --setenv."""
    argv = list(bwrap_argv)
    argv[1:1] = ["--setenv", "PWRAP_VAULT_TOKEN", token]
    return argv


def serve(
    config: VaultConfig,
    sock_path: Path,
    bwrap_argv: list[str],
    real_uid: int,
    real_gid: int,
) -> None:
    """Primary session: mount, fork primary bwrap, accept attached clients.

    Called via `python -m project_wrap.vault serve ...` after unshare. Runs in
    the foreground of the launching terminal. Exits with the primary bwrap's
    exit status after tearing down any attached clients and unmounting.
    """
    # Mount gocryptfs (password prompt goes to the primary's tty)
    result = subprocess.run(
        ["gocryptfs", str(config.cipherdir), str(config.mountpoint)]
    )
    if result.returncode != 0:
        raise SystemExit(f"Failed to mount encrypted volume: {config.cipherdir}")

    token = secrets.token_hex(16)
    print(f"Vault token: {token}", flush=True)

    sock_path.unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock_path))
    os.chmod(str(sock_path), 0o600)
    server.listen(5)
    server.settimeout(0.2)

    shutting_down = False

    def handle_signal(_signum: int, _frame: object) -> None:
        nonlocal shutting_down
        shutting_down = True

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGHUP, handle_signal)
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)

    primary_argv = _inject_uid(_inject_token(bwrap_argv, token), real_uid, real_gid)

    primary_pid = os.fork()
    if primary_pid == 0:
        server.close()
        _pty_proxy(primary_argv, [0, 1, 2])
        sys.exit(1)  # unreachable

    # Parent: redirect stdio so we don't fight the pty-proxied primary for the tty
    devnull = os.open("/dev/null", os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(devnull, fd)
    os.close(devnull)

    children: dict[int, socket.socket] = {}
    primary_exit_status = 1
    primary_reaped = False

    def reap_once() -> None:
        nonlocal primary_exit_status, primary_reaped
        while True:
            try:
                wpid, wstatus = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            if wpid == 0:
                return
            status = os.WEXITSTATUS(wstatus) if os.WIFEXITED(wstatus) else 1
            if wpid == primary_pid:
                primary_exit_status = status
                primary_reaped = True
            elif wpid in children:
                client = children.pop(wpid)
                try:
                    client.sendall(struct.pack("!i", status))
                except OSError:
                    pass
                finally:
                    client.close()

    try:
        while not shutting_down and not primary_reaped:
            reap_once()
            if primary_reaped or shutting_down:
                break

            try:
                client, _ = server.accept()
            except TimeoutError:
                continue
            except OSError:
                break

            try:
                data, fds = _recv_fds(client, maxfds=3)
            except OSError:
                client.close()
                continue

            if len(fds) < 3 or not data:
                client.close()
                for fd in fds:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                continue

            try:
                msg = json.loads(data)
            except (json.JSONDecodeError, ValueError):
                client.close()
                for fd in fds:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                continue

            if not hmac.compare_digest(msg.get("token", ""), token):
                time.sleep(1)
                try:
                    client.sendall(json.dumps({"error": "invalid token"}).encode())
                except OSError:
                    pass
                client.close()
                for fd in fds:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                continue

            child_argv = _inject_uid(
                _inject_token(msg["argv"], token), real_uid, real_gid
            )

            proxy_pid = os.fork()
            if proxy_pid == 0:
                server.close()
                _pty_proxy(child_argv, fds)
                sys.exit(1)  # unreachable

            for fd in fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
            children[proxy_pid] = client
    finally:
        try:
            server.close()
        except OSError:
            pass
        sock_path.unlink(missing_ok=True)

        for pid in list(children):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

        deadline = time.monotonic() + 0.5
        while children and time.monotonic() < deadline:
            for pid in list(children):
                try:
                    wpid, wstatus = os.waitpid(pid, os.WNOHANG)
                except (ChildProcessError, OSError):
                    children.pop(pid, None)
                    continue
                if wpid == pid:
                    status = (
                        os.WEXITSTATUS(wstatus) if os.WIFEXITED(wstatus) else 1
                    )
                    client = children.pop(pid)
                    try:
                        client.sendall(struct.pack("!i", status))
                    except OSError:
                        pass
                    client.close()
            time.sleep(0.05)

        for pid in list(children):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except (ChildProcessError, OSError):
                pass
            client = children.pop(pid, None)
            if client is not None:
                try:
                    client.sendall(struct.pack("!i", 137))
                except OSError:
                    pass
                client.close()

        if not primary_reaped:
            try:
                wpid, wstatus = os.waitpid(primary_pid, 0)
                if wpid == primary_pid:
                    primary_exit_status = (
                        os.WEXITSTATUS(wstatus) if os.WIFEXITED(wstatus) else 1
                    )
            except (ChildProcessError, OSError):
                pass

        subprocess.run(
            ["fusermount", "-u", str(config.mountpoint)], capture_output=True
        )

    sys.exit(primary_exit_status)


# --- CLI entry point for serve re-exec ---


def main() -> None:
    """Entry point when invoked as `python -m project_wrap.vault serve ...`."""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["serve"])
    parser.add_argument("--cipherdir", required=True)
    parser.add_argument("--mountpoint", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--sock-path", required=True)
    parser.add_argument("--real-uid", type=int, required=True)
    parser.add_argument("--real-gid", type=int, required=True)
    parser.add_argument("--bwrap-argv", required=True)
    args = parser.parse_args()

    config = VaultConfig(
        cipherdir=Path(args.cipherdir),
        mountpoint=Path(args.mountpoint),
        project_name=args.project,
        shared=True,
    )
    bwrap_argv = json.loads(args.bwrap_argv)
    serve(config, Path(args.sock_path), bwrap_argv, args.real_uid, args.real_gid)


if __name__ == "__main__":
    main()
