"""Encrypted volume management using gocryptfs in isolated mount namespaces.

Two modes:
- Single session (shared=False): unshare + gocryptfs + bwrap in one process chain.
  Lockfile warns concurrent sessions about potential lost updates.
- Shared session (shared=True): daemon holds the mount, spawns bwrap children via
  unix socket with fd passing. Multiple terminals share the same mount.
"""

from __future__ import annotations

import getpass
import json
import os
import secrets
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
    """Runtime directory for sockets and lock/pid files."""
    d = Path(f"/tmp/pwrap-{os.getuid()}")
    d.mkdir(mode=0o700, exist_ok=True)
    return d


def _lock_path(project: str) -> Path:
    return _runtime_dir() / f"{project}.lock"


def _sock_path(project: str) -> Path:
    return _runtime_dir() / f"{project}.sock"


def _pid_path(project: str) -> Path:
    return _runtime_dir() / f"{project}.pid"


def _is_process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _check_concurrent(project: str) -> bool:
    """Check if another session is active. Returns True if user confirms to proceed."""
    lock = _lock_path(project)
    if not lock.exists():
        return True

    try:
        pid = int(lock.read_text().strip())
    except (ValueError, OSError):
        return True

    if not _is_process_alive(pid):
        lock.unlink(missing_ok=True)
        return True

    print(
        f"Warning: another session for '{project}' is active (PID {pid}).\n"
        "Changes to encrypted files may not be visible across sessions,\n"
        "and concurrent writes to the same file may cause lost updates.\n"
    )
    try:
        response = input("Press Enter to continue, Ctrl-C to abort: ")  # noqa: F841
        return True
    except (KeyboardInterrupt, EOFError):
        print()
        return False


def _acquire_lock(project: str) -> None:
    _lock_path(project).write_text(str(os.getpid()))


def _release_lock(project: str) -> None:
    lock = _lock_path(project)
    try:
        pid = int(lock.read_text().strip())
        if pid == os.getpid():
            lock.unlink(missing_ok=True)
    except (ValueError, OSError):
        lock.unlink(missing_ok=True)


# --- Single session mode (shared=False) ---


def run_single(config: VaultConfig, bwrap_argv: list[str]) -> int:
    """Run bwrap inside an isolated unshare+gocryptfs namespace.

    Does not return on success (execs into unshare).
    """
    if not _check_concurrent(config.project_name):
        return 130  # same as KeyboardInterrupt

    _acquire_lock(config.project_name)

    # Build the inner command: mount gocryptfs, then exec bwrap
    bwrap_cmd = " ".join(f"'{a}'" for a in bwrap_argv)
    inner = (
        f"gocryptfs '{config.cipherdir}' '{config.mountpoint}' && "
        f"exec {bwrap_cmd}"
    )

    argv = [
        "unshare", "--user", "--mount", "--map-root-user",
        "--", "sh", "-c", inner,
    ]

    try:
        os.execvp("unshare", argv)
    finally:
        _release_lock(config.project_name)

    return 1  # unreachable after exec


# --- Shared session mode (shared=True, daemon) ---


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


def daemon_serve(
    config: VaultConfig,
    token_write_fd: int,
    sock_path: Path,
    pid_path: Path,
) -> None:
    """Daemon: hold gocryptfs mount, accept bwrap spawn requests via unix socket.

    This function is called inside an unshare namespace (re-exec'd).
    Paths are passed explicitly because uid remaps to 0 inside unshare.
    """

    # Generate auth token and send to first client via pipe
    token = secrets.token_hex(16)
    if token_write_fd >= 0:
        os.write(token_write_fd, token.encode())
        os.close(token_write_fd)

    # Clean up stale socket
    sock_path.unlink(missing_ok=True)

    # Mount gocryptfs (password prompt goes to current terminal)
    result = subprocess.run(["gocryptfs", str(config.cipherdir), str(config.mountpoint)])
    if result.returncode != 0:
        raise SystemExit(f"Failed to mount encrypted volume: {config.cipherdir}")

    # Write PID and create socket
    pid_path.write_text(str(os.getpid()))

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock_path))
    server.listen(5)
    server.settimeout(1.0)

    children: dict[int, socket.socket] = {}  # pid -> client socket

    def reap_children() -> None:
        for pid in list(children):
            result = os.waitpid(pid, os.WNOHANG)
            if result[0] != 0:
                status = os.WEXITSTATUS(result[1]) if os.WIFEXITED(result[1]) else 1
                client = children.pop(pid)
                try:
                    client.sendall(struct.pack("!i", status))
                except OSError:
                    pass
                finally:
                    client.close()

    # Ignore SIGCHLD — we poll with WNOHANG
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)

    try:
        while True:
            reap_children()

            try:
                client, _ = server.accept()
            except TimeoutError:
                # If no children and no pending connections, exit
                if not children:
                    # Give a grace period for new connections
                    time.sleep(2)
                    reap_children()
                    if not children:
                        break
                continue

            # Receive auth token + bwrap argv + terminal fds
            data, fds = _recv_fds(client, maxfds=3)
            if len(fds) < 3 or not data:
                client.close()
                for fd in fds:
                    os.close(fd)
                continue

            msg = json.loads(data)

            # Verify token
            if msg.get("token") != token:
                time.sleep(1)
                try:
                    client.sendall(json.dumps({"error": "invalid token"}).encode())
                except OSError:
                    pass
                client.close()
                for fd in fds:
                    os.close(fd)
                continue

            # Inject uid/gid remapping + token into bwrap argv (after "bwrap")
            bwrap_argv = msg["argv"]
            extra = [
                "--unshare-user",
                "--uid", str(msg["uid"]),
                "--gid", str(msg["gid"]),
                "--setenv", "PWRAP_VAULT_TOKEN", token,
            ]
            bwrap_argv[1:1] = extra

            pid = os.fork()
            if pid == 0:
                # Child: dup fds to stdin/stdout/stderr, exec bwrap
                server.close()
                os.dup2(fds[0], 0)
                os.dup2(fds[1], 1)
                os.dup2(fds[2], 2)
                for fd in fds:
                    os.close(fd)
                os.execvp(bwrap_argv[0], bwrap_argv)
                sys.exit(1)  # unreachable
            else:
                # Parent: track child, close passed fds
                for fd in fds:
                    os.close(fd)
                children[pid] = client

    finally:
        # Unmount and clean up
        subprocess.run(["fusermount", "-u", str(config.mountpoint)], capture_output=True)
        sock_path.unlink(missing_ok=True)
        pid_path.unlink(missing_ok=True)
        server.close()


def _start_daemon(config: VaultConfig) -> str:
    """Start the vault daemon in the background. Returns the auth token."""
    sock = _sock_path(config.project_name)

    # Pipe for token handshake: daemon writes token, parent reads it
    r_fd, w_fd = os.pipe()

    # Fork: parent waits for token + socket, child execs into unshare+daemon
    pid = os.fork()
    if pid == 0:
        # Child: exec into unshare + daemon
        os.close(r_fd)
        # Clear close-on-exec so the fd survives through unshare → python exec chain
        os.set_inheritable(w_fd, True)
        argv = [
            "unshare", "--user", "--mount", "--map-root-user",
            "--", sys.executable, "-m", "project_wrap.vault",
            "serve",
            "--cipherdir", str(config.cipherdir),
            "--mountpoint", str(config.mountpoint),
            "--project", config.project_name,
            "--token-fd", str(w_fd),
            "--sock-path", str(_sock_path(config.project_name)),
            "--pid-path", str(_pid_path(config.project_name)),
        ]
        os.execvp("unshare", argv)
        sys.exit(1)

    # Parent: read token from pipe, then wait for socket
    os.close(w_fd)
    token = os.read(r_fd, 256).decode().strip()
    os.close(r_fd)

    if not token:
        raise SystemExit("Failed to receive vault token from daemon")

    for _ in range(60):  # 60 seconds timeout (gocryptfs password prompt)
        if sock.exists():
            return token
        time.sleep(1)

    raise SystemExit("Timeout waiting for vault daemon to start")


def run_shared(config: VaultConfig, bwrap_argv: list[str]) -> int:
    """Connect to (or start) daemon, spawn bwrap, wait for exit."""
    sock_path = _sock_path(config.project_name)
    pid_path = _pid_path(config.project_name)

    # Check if daemon is alive
    daemon_alive = False
    if pid_path.exists():
        try:
            pid = int(pid_path.read_text().strip())
            daemon_alive = _is_process_alive(pid)
        except (ValueError, OSError):
            pass

    if not daemon_alive:
        sock_path.unlink(missing_ok=True)
        pid_path.unlink(missing_ok=True)
        token = _start_daemon(config)
        print(f"Vault token: {token}")
    else:
        token = getpass.getpass("Vault token: ")

    # Connect and send authenticated request + terminal fds
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(sock_path))

    data = json.dumps({
        "token": token, "argv": bwrap_argv,
        "uid": os.getuid(), "gid": os.getgid(),
    }).encode()
    _send_fds(client, [0, 1, 2], data)

    # Wait for exit status (4 bytes int) or error response (JSON)
    # Read until the daemon closes the connection
    chunks: list[bytes] = []
    while True:
        chunk = client.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
    client.close()
    response = b"".join(chunks)

    if len(response) >= 4:
        # Check for JSON error first (longer than 4 bytes)
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


# --- CLI entry point for daemon re-exec ---


def main() -> None:
    """Entry point when invoked as `python -m project_wrap.vault serve ...`."""
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["serve"])
    parser.add_argument("--cipherdir", required=True)
    parser.add_argument("--mountpoint", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--token-fd", type=int, required=True)
    parser.add_argument("--sock-path", required=True)
    parser.add_argument("--pid-path", required=True)
    args = parser.parse_args()

    config = VaultConfig(
        cipherdir=Path(args.cipherdir),
        mountpoint=Path(args.mountpoint),
        project_name=args.project,
        shared=True,
    )
    daemon_serve(
        config,
        token_write_fd=args.token_fd,
        sock_path=Path(args.sock_path),
        pid_path=Path(args.pid_path),
    )


if __name__ == "__main__":
    main()
