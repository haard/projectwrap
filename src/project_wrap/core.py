"""Core functionality for project-wrap."""

from __future__ import annotations

import os
import shlex
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .deps import require_dep

ETC_SHELLS = Path("/etc/shells")


@dataclass
class ProjectExec:
    """Everything needed to exec into a project environment."""

    display_name: str
    program: str
    argv: list[str]
    env_updates: dict[str, str] = field(default_factory=dict)
    is_sandboxed: bool = False
    is_legacy: bool = False
    verbose_info: str | None = None


def get_config_dir() -> Path:
    """Get the project configuration directory."""
    # Support XDG, fall back to ~/.config
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config:
        base = Path(xdg_config)
    else:
        base = Path.home() / ".config"
    return base / "project"


def expand_path(path: str) -> Path:
    """Expand ~ and environment variables in path."""
    return Path(os.path.expandvars(os.path.expanduser(path)))


def validate_project_name(name: str) -> None:
    """Validate project name to prevent path traversal and injection."""
    if not name or not name.strip():
        raise SystemExit("Invalid project name: name cannot be empty")
    if name == ".":
        raise SystemExit("Invalid project name: '.'")
    if "/" in name:
        raise SystemExit(f"Invalid project name: {name!r} (contains '/')")
    if ".." in name:
        raise SystemExit(f"Invalid project name: {name!r} (contains '..')")
    if "\x00" in name:
        raise SystemExit("Invalid project name: name contains null byte")
    if name.startswith("-"):
        raise SystemExit(f"Invalid project name: {name!r} (starts with '-')")


def validate_shell(shell: str) -> None:
    """Validate that shell is a known, existing shell."""
    shell_path = Path(shell)
    if not shell_path.is_absolute():
        raise SystemExit(f"Shell must be an absolute path: {shell!r}")
    if not shell_path.is_file():
        raise SystemExit(f"Shell does not exist: {shell}")
    if ETC_SHELLS.exists():
        allowed = {
            line.strip()
            for line in ETC_SHELLS.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        }
        if shell not in allowed:
            raise SystemExit(f"Shell not in /etc/shells: {shell}")


def check_config_permissions(config_file: Path) -> None:
    """Check config file permissions and refuse insecure files."""
    mode = config_file.stat().st_mode
    if mode & 0o002:
        raise SystemExit(f"Config file is world-writable, refusing to load: {config_file}")
    if mode & 0o020:
        raise SystemExit(f"Config file is group-writable, refusing to load: {config_file}")


def _tiocsti_vulnerable() -> bool:
    """Check if the kernel is vulnerable to TIOCSTI injection.

    Kernels 6.2+ disable TIOCSTI by default (CONFIG_LEGACY_TIOCSTI).
    On older kernels, check the sysctl override.
    """
    sysctl = Path("/proc/sys/dev/tty/legacy_tiocsti")
    if sysctl.exists():
        return sysctl.read_text().strip() != "0"
    # No sysctl means pre-6.2 kernel — TIOCSTI is enabled
    release = os.uname().release
    parts = release.split(".")
    try:
        major, minor = int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return True  # assume vulnerable if we can't parse
    return major < 6 or (major == 6 and minor < 2)


_SCHEMA: dict[str, dict[str, type] | None] = {
    "project": {"name": str, "dir": str, "shell": str},
    "sandbox": {
        "enabled": bool,
        "blacklist": list,
        "whitelist": list,
        "unshare_net": bool,
        "unshare_pid": bool,
        "new_session": bool,
        "writable": list,
    },
    "env": None,
    "encrypted": None,
    "venv": {"path": str},
}


def validate_config(config: dict[str, Any]) -> None:
    """Validate config schema, rejecting unknown keys and wrong types."""
    user_keys = {k for k in config if not k.startswith("_")}
    unknown_top = user_keys - _SCHEMA.keys()
    if unknown_top:
        raise SystemExit(
            f"Unknown config sections: {sorted(unknown_top)}\n"
            f"Allowed: {sorted(_SCHEMA.keys())}"
        )

    for section, rules in _SCHEMA.items():
        if section not in config:
            continue
        value = config[section]
        if not isinstance(value, dict):
            raise SystemExit(f"[{section}] must be a table, got {type(value).__name__}")

        if rules is None:
            for k, v in value.items():
                if not isinstance(v, str):
                    raise SystemExit(
                        f"[{section}].{k}: expected string, got {type(v).__name__}"
                    )
        else:
            unknown_keys = set(value.keys()) - rules.keys()
            if unknown_keys:
                raise SystemExit(
                    f"[{section}] unknown keys: {sorted(unknown_keys)}\n"
                    f"Allowed: {sorted(rules.keys())}"
                )
            for k, v in value.items():
                expected = rules[k]
                if expected is list:
                    if not isinstance(v, list):
                        raise SystemExit(
                            f"[{section}].{k}: expected list, got {type(v).__name__}"
                        )
                    if not all(isinstance(item, str) for item in v):
                        raise SystemExit(f"[{section}].{k}: all items must be strings")
                elif not isinstance(v, expected):
                    raise SystemExit(
                        f"[{section}].{k}: expected {expected.__name__}, "
                        f"got {type(v).__name__}"
                    )


def load_config(name: str) -> dict[str, Any]:
    """Load project configuration.

    Supports both legacy flat files and new directory-based configs.
    """
    validate_project_name(name)
    config_dir = get_config_dir()
    project_path = config_dir / name

    # Legacy flat file support
    if project_path.is_file():
        return {"_legacy": True, "_path": project_path}

    # New directory-based config
    if not project_path.is_dir():
        raise SystemExit(f"Unknown project: {name}")

    config_file = project_path / "project.toml"
    if not config_file.exists():
        raise SystemExit(f"Missing config: {config_file}")

    check_config_permissions(config_file)

    with open(config_file, "rb") as f:
        config: dict[str, Any] = tomllib.load(f)

    validate_config(config)
    config["_config_dir"] = project_path
    return config


def mount_encrypted(encrypted: dict[str, str], verbose: bool = False) -> list[Path]:
    """Mount gocryptfs volumes.

    Args:
        encrypted: Mapping of source (encrypted) to destination (mount point)
        verbose: Print mount operations

    Returns:
        List of newly mounted paths (for tracking what to unmount)
    """
    require_dep("gocryptfs")

    mounted: list[Path] = []

    for src, dst in encrypted.items():
        src_path = expand_path(src)
        dst_path = expand_path(dst)

        # Check if already mounted
        result = subprocess.run(
            ["mountpoint", "-q", str(dst_path)],
            capture_output=True,
        )

        if result.returncode != 0:
            # Not mounted, mount it
            dst_path.mkdir(parents=True, exist_ok=True)

            if verbose:
                print(f"Mounting encrypted: {src_path} → {dst_path}")

            # gocryptfs will prompt for password
            result = subprocess.run(["gocryptfs", str(src_path), str(dst_path)])
            if result.returncode != 0:
                raise SystemExit(f"Failed to mount encrypted volume: {src_path}")

            mounted.append(dst_path)
        elif verbose:
            print(f"Already mounted: {dst_path}")

    return mounted


def build_bwrap_args(
    sandbox: dict[str, Any],
    env: dict[str, str],
    project_dir: Path,
    init_script: Path | None = None,
) -> list[str]:
    """Build bubblewrap command arguments.

    Args:
        sandbox: Sandbox configuration dict
        env: Environment variables to set
        project_dir: Project working directory
        init_script: Optional init script to bind-mount read-only into sandbox

    Returns:
        List of bwrap arguments
    """
    args = [
        "bwrap",
        # Base filesystem (read-only root, read-only home, writable project dir)
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--ro-bind",
        str(Path.home()),
        str(Path.home()),
        # Hardening
        "--die-with-parent",
        "--unshare-ipc",
    ]

    # Isolate XDG runtime dir (D-Bus, Wayland, SSH/GPG agent sockets)
    uid = os.getuid()
    args.extend(["--tmpfs", f"/run/user/{uid}"])

    # Blacklist paths by overlaying with tmpfs
    blacklist_paths: list[Path] = []
    for path in sandbox.get("blacklist", []):
        p = expand_path(path)
        if not p.exists():
            raise SystemExit(
                f"Blacklist path does not exist: {p}\n"
                f"Fix your config or remove this entry."
            )
        # bwrap can't mount tmpfs over symlinks — resolve to the real path
        mount_path = p.resolve()
        args.extend(["--tmpfs", str(mount_path)])
        blacklist_paths.append(mount_path)

    # Whitelist paths by binding them back (must be under a blacklisted path)
    for path in sandbox.get("whitelist", []):
        p = expand_path(path)
        resolved_p = p.resolve()
        if not any(resolved_p == bl or bl in resolved_p.parents for bl in blacklist_paths):
            raise SystemExit(
                f"Whitelist path {p} is not under any blacklisted path. "
                f"Blacklisted: {[str(bl) for bl in blacklist_paths]}"
            )
        if p.exists():
            resolved_bind = p.resolve()
            args.extend(["--bind", str(resolved_bind), str(resolved_bind)])

    # Extra writable paths (e.g. ~/.pyenv/shims, ~/.keychain)
    for path in sandbox.get("writable", []):
        p = expand_path(path)
        if not p.exists():
            raise SystemExit(
                f"Writable path does not exist: {p}\n"
                f"Fix your config or remove this entry."
            )
        mount_path = p.resolve()
        args.extend(["--bind", str(mount_path), str(mount_path)])

    # Project dir writable (after blacklist/whitelist so it's not overwritten)
    args.extend(["--bind", str(project_dir), str(project_dir)])

    # Bind-mount init script read-only (config dir may be blacklisted)
    if init_script is not None:
        args.extend(["--ro-bind", str(init_script), str(init_script)])

    # TIOCSTI protection (--new-session breaks fish TTY, so only enable when needed)
    vulnerable = _tiocsti_vulnerable()
    new_session_cfg = sandbox.get("new_session")
    if new_session_cfg is True:
        args.append("--new-session")
    elif new_session_cfg is None and vulnerable:
        # Default: auto-enable on vulnerable kernels
        args.append("--new-session")
    elif new_session_cfg is False and vulnerable:
        import sys

        print(
            "Warning: new_session disabled but kernel is vulnerable to TIOCSTI "
            f"(Linux {os.uname().release}). Upgrade to 6.2+ or set "
            "new_session = true.",
            file=sys.stderr,
        )

    # Network isolation
    if sandbox.get("unshare_net", False):
        args.append("--unshare-net")

    # PID namespace isolation (default: on)
    if sandbox.get("unshare_pid", True):
        args.append("--unshare-pid")

    # Set environment variables
    args.extend(["--setenv", "PROJECT_WRAP", "1"])
    for key, value in env.items():
        expanded = os.path.expanduser(value)
        args.extend(["--setenv", key, expanded])

    # Set working directory
    args.extend(["--chdir", str(project_dir)])

    return args


def get_init_script(config_dir: Path, shell: str) -> Path | None:
    """Find shell-specific init script.

    Looks for init.{shell} (e.g., init.fish) then falls back to init.sh.
    """
    shell_name = Path(shell).name

    candidates = [
        config_dir / f"init.{shell_name}",
        config_dir / "init.sh",
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return None


def _build_init_commands(
    project_dir: Path,
    config_dir: Path,
    shell: str,
    venv_cfg: dict[str, Any],
) -> list[str]:
    """Build setup commands (cd, venv activation, init script sourcing).

    Returns list of shell commands — does NOT include the final exec/shell launch.
    """
    commands = [f"cd {shlex.quote(str(project_dir))}"]
    shell_name = Path(shell).name

    # Virtual environment activation
    if venv_path := venv_cfg.get("path"):
        venv_full = project_dir / venv_path

        if shell_name == "fish":
            activate = venv_full / "bin" / "activate.fish"
        else:
            activate = venv_full / "bin" / "activate"

        if activate.exists():
            commands.append(f"source {shlex.quote(str(activate))}")

    # Custom init script
    if init_script := get_init_script(config_dir, shell):
        commands.append(f"source {shlex.quote(str(init_script))}")

    return commands


def build_shell_argv(
    project_dir: Path,
    config_dir: Path,
    shell: str,
    venv_cfg: dict[str, Any],
) -> list[str]:
    """Build the full argv to launch an interactive shell with project setup.

    Uses shell-specific mechanisms so setup runs inside the interactive shell:
    - fish: --init-command (runs after config.fish, before prompt)
    - bash: --rcfile with a temp file that sources .bashrc then runs setup
    - fallback: -c "setup; exec shell" (legacy behavior)
    """
    commands = _build_init_commands(project_dir, config_dir, shell, venv_cfg)
    init_string = "; ".join(commands)
    shell_name = Path(shell).name

    if shell_name == "fish":
        return [shell, "--init-command", init_string]

    if shell_name == "bash":
        import tempfile

        # --rcfile replaces normal .bashrc sourcing, so we source it explicitly
        rcfile = tempfile.NamedTemporaryFile(
            mode="w", prefix="projectwrap-init-", suffix=".sh", delete=False
        )
        bashrc = Path.home() / ".bashrc"
        lines = []
        if bashrc.exists():
            lines.append(f"source {shlex.quote(str(bashrc))}")
        lines.append(init_string)
        # Clean up the temp file after sourcing
        lines.append(f"rm -f {shlex.quote(rcfile.name)}")
        rcfile.write("\n".join(lines) + "\n")
        rcfile.close()
        return [shell, "--rcfile", rcfile.name]

    # zsh and other shells: fall back to exec-based approach
    commands.append(f"exec {shlex.quote(shell)}")
    return [shell, "-c", "; ".join(commands)]


def redact_bwrap_args(args: list[str]) -> list[str]:
    """Redact --setenv values from bwrap args for display."""
    redacted = list(args)
    i = 0
    while i < len(redacted):
        if redacted[i] == "--setenv" and i + 2 < len(redacted):
            redacted[i + 2] = "***"
            i += 3
        else:
            i += 1
    return redacted


def rename_tmux_window(name: str) -> None:
    """Rename current tmux window if in tmux session."""
    if os.environ.get("TMUX"):
        subprocess.run(
            ["tmux", "rename-window", name],
            capture_output=True,
        )


def prepare_project(name: str, verbose: bool = False) -> ProjectExec:
    """Prepare a project environment for execution.

    Loads config, mounts encrypted volumes, renames tmux window,
    and returns everything needed to exec into the project shell.
    """
    config = load_config(name)

    # Handle legacy flat file projects
    if config.get("_legacy"):
        legacy_path = config["_path"]
        shell = os.environ.get("SHELL", "/bin/bash")
        rename_tmux_window(name)
        cmd = f"source {shlex.quote(str(legacy_path))}; exec {shlex.quote(shell)}"
        return ProjectExec(
            display_name=name,
            program=shell,
            argv=[shell, "-c", cmd],
            is_legacy=True,
        )

    # Extract config sections
    project_cfg = config.get("project", {})
    sandbox_cfg = config.get("sandbox", {})
    env_cfg = config.get("env", {})
    encrypted_cfg = config.get("encrypted", {})
    venv_cfg = config.get("venv", {})
    config_dir: Path = config["_config_dir"]

    # Resolve settings
    display_name = project_cfg.get("name", name)
    project_dir = expand_path(project_cfg.get("dir", f"~/projects/{name}"))
    shell = project_cfg.get("shell", os.environ.get("SHELL", "/bin/bash"))
    validate_shell(shell)
    sandbox_enabled = sandbox_cfg.get("enabled", False)

    # Verify project directory exists
    if not project_dir.exists():
        raise SystemExit(f"Project directory does not exist: {project_dir}")

    # Rename tmux window
    rename_tmux_window(display_name)

    # Mount encrypted volumes (outside sandbox, before anything else)
    if encrypted_cfg:
        mount_encrypted(encrypted_cfg, verbose=verbose)

    # Resolve init script and build shell argv
    init_script = get_init_script(config_dir, shell)
    shell_argv = build_shell_argv(project_dir, config_dir, shell, venv_cfg)

    # Non-sandboxed execution
    if not sandbox_enabled:
        return ProjectExec(
            display_name=display_name,
            program=shell,
            argv=shell_argv,
            env_updates=env_cfg,
        )

    # Sandboxed execution - verify bwrap is available
    require_dep("bwrap")

    bwrap_args = build_bwrap_args(sandbox_cfg, env_cfg, project_dir, init_script=init_script)
    bwrap_args.extend(shell_argv)

    verbose_info = None
    if verbose:
        verbose_info = f"Exec: {' '.join(redact_bwrap_args(bwrap_args))}"

    return ProjectExec(
        display_name=display_name,
        program="bwrap",
        argv=bwrap_args,
        is_sandboxed=True,
        verbose_info=verbose_info,
    )


def run_project(name: str, verbose: bool = False) -> None:
    """Load and run a project environment.

    This function does not return on success (execs into new shell).
    """
    result = prepare_project(name, verbose)

    label = result.display_name
    if result.is_legacy:
        label += " (legacy)"
    elif result.is_sandboxed:
        label += " (sandboxed)"
    print(f"Loading {label}")

    if result.verbose_info:
        print(result.verbose_info)

    for key, value in result.env_updates.items():
        os.environ[key] = os.path.expanduser(value)

    os.execvp(result.program, result.argv)


def create_project(name: str, project_dir: str, sandbox: bool = True) -> Path:
    """Create a new project config directory with a default project.toml.

    Returns the path to the created config directory.
    """
    validate_project_name(name)
    config_dir = get_config_dir() / name

    if config_dir.exists():
        raise SystemExit(f"Project already exists: {config_dir}")

    resolved_dir = expand_path(project_dir).resolve()
    if not resolved_dir.is_dir():
        raise SystemExit(f"Project directory does not exist: {resolved_dir}")

    sandbox_enabled = "true" if sandbox else "false"

    toml = f"""\
[project]
name = "{name}"
dir = "{resolved_dir}"
# shell = "/usr/bin/fish"         # Defaults to $SHELL

[sandbox]
enabled = {sandbox_enabled}
# blacklist = [                   # Paths to hide (overlaid with tmpfs)
#     "~/.config/project",
#     "~/.kube",
#     "~/.aws",
#     "~/.ssh",
# ]
# whitelist = [                   # Exceptions to blacklist (bound back)
#     "~/.kube/{name}",
# ]
# writable = [                    # Extra writable paths (home is read-only)
#     "~/.pyenv/shims",
# ]
# unshare_net = false             # Isolate network namespace
# unshare_pid = true              # Isolate PID namespace (default: true)
# new_session = true              # TIOCSTI protection (auto on kernels < 6.2)

# [env]                           # Environment variables
# KUBECONFIG = "~/.kube/{name}/config"

# [encrypted]                     # gocryptfs volumes (source = mountpoint)
# "~/.secrets-encrypted/{name}" = "~/.secrets/{name}"

# [venv]
# path = ".venv"                  # Relative to project dir, auto-activated
"""

    config_dir.mkdir(parents=True)
    (config_dir / "project.toml").write_text(toml)

    return config_dir


def list_projects() -> None:
    """List all available projects."""
    config_dir = get_config_dir()

    if not config_dir.exists():
        print(f"No projects configured. Create configs in: {config_dir}")
        return

    print("Projects:")

    items = sorted(config_dir.iterdir())
    if not items:
        print("  (none)")
        return

    for item in items:
        if item.name.startswith("."):
            continue

        if item.is_dir():
            # Check for valid config
            config_file = item / "project.toml"
            if config_file.exists():
                # Try to load to show name
                try:
                    with open(config_file, "rb") as f:
                        cfg = tomllib.load(f)
                    display_name = cfg.get("project", {}).get("name", item.name)
                    sandboxed = cfg.get("sandbox", {}).get("enabled", False)
                    marker = " [sandboxed]" if sandboxed else ""
                    print(f"  {item.name}/{marker}")
                    if display_name != item.name:
                        print(f"      → {display_name}")
                except Exception:
                    print(f"  {item.name}/ (invalid config)")
            else:
                print(f"  {item.name}/ (missing project.toml)")
        else:
            print(f"  {item.name} (legacy)")


def unmount_project(name: str) -> None:
    """Unmount encrypted volumes for a project."""
    config = load_config(name)

    if config.get("_legacy"):
        print("Legacy projects don't have encrypted volumes")
        return

    encrypted_cfg = config.get("encrypted", {})

    if not encrypted_cfg:
        print(f"No encrypted volumes configured for {name}")
        return

    require_dep("fusermount")

    for dst in encrypted_cfg.values():
        dst_path = expand_path(dst)

        result = subprocess.run(
            ["mountpoint", "-q", str(dst_path)],
            capture_output=True,
        )

        if result.returncode == 0:
            print(f"Unmounting: {dst_path}")
            subprocess.run(["fusermount", "-u", str(dst_path)])
        else:
            print(f"Not mounted: {dst_path}")
