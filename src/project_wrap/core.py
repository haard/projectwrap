"""Core functionality for project-wrap."""

from __future__ import annotations

import os
import shlex
import subprocess
import tomllib
from dataclasses import dataclass
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
    is_sandboxed: bool = False
    verbose_info: str | None = None


def get_config_dir() -> Path:
    """Get the project configuration directory."""
    # Support XDG, fall back to ~/.config
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config:
        base = Path(xdg_config)
    else:
        base = Path.home() / ".config"
    return base / "pwrap"


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


_SCHEMA: dict[str, dict[str, type]] = {
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
    "secrets": {"archive": str, "identity": str, "dest": str, "writeback": bool},
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
    """Load project configuration."""
    validate_project_name(name)
    config_dir = get_config_dir()
    project_path = config_dir / name

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



def build_bwrap_args(
    sandbox: dict[str, Any],
    project_dir: Path,
    init_script: Path | None = None,
    ro_bind_extra: list[Path] | None = None,
    rw_bind_extra: list[Path] | None = None,
    setenv_extra: dict[str, str] | None = None,
) -> list[str]:
    """Build bubblewrap command arguments.

    Args:
        sandbox: Sandbox configuration dict
        project_dir: Project working directory
        init_script: Optional init script to bind-mount read-only into sandbox
        ro_bind_extra: Additional paths to bind-mount read-only (e.g. secrets files)
        rw_bind_extra: Additional paths to bind-mount read-write (e.g. writeback archive)
        setenv_extra: Additional environment variables to set inside sandbox

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

    # Always blacklist the config directory (prevents reading other project configs
    # or modifying sandbox rules from inside the sandbox)
    config_dir_resolved = get_config_dir().resolve()
    if config_dir_resolved.exists():
        args.extend(["--tmpfs", str(config_dir_resolved)])

    # Blacklist paths by overlaying with tmpfs
    blacklist_paths: list[Path] = [config_dir_resolved]
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

    # Bind-mount extra read-only paths (e.g. secrets identity file)
    for path in ro_bind_extra or []:
        args.extend(["--ro-bind", str(path), str(path)])

    # Bind-mount extra read-write paths (e.g. writeback archive)
    for path in rw_bind_extra or []:
        args.extend(["--bind", str(path), str(path)])

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
    for key, value in (setenv_extra or {}).items():
        args.extend(["--setenv", key, value])

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


@dataclass
class ResolvedSecrets:
    """Resolved secrets config with absolute paths."""

    archive: Path
    identity: Path
    dest: str
    writeback: bool = False


def _build_init_commands(
    project_dir: Path,
    config_dir: Path,
    shell: str,
    secrets: ResolvedSecrets | None = None,
) -> list[str]:
    """Build setup commands (cd, secrets decryption, init script sourcing).

    Returns list of shell commands — does NOT include the final exec/shell launch.
    """
    commands: list[str] = []

    # Decrypt secrets archive into sandbox tmpfs (before cd so dest can be absolute)
    if secrets is not None:
        dest = shlex.quote(secrets.dest)
        archive = shlex.quote(str(secrets.archive))
        identity = shlex.quote(str(secrets.identity))
        commands.append(f"mkdir -p {dest}")
        commands.append(f"age -d -i {identity} {archive} | tar x -C {dest}")

        # Writeback: re-encrypt on shell exit
        if secrets.writeback:
            shell_name = Path(shell).name
            wb_cmd = (
                'tar c -C "$PWRAP_SECRETS_DEST" . | '
                'age -e -i "$PWRAP_SECRETS_IDENTITY" -o "$PWRAP_SECRETS_ARCHIVE"'
            )
            if shell_name == "fish":
                commands.append(
                    f"function __pwrap_writeback --on-event fish_exit; {wb_cmd}; end"
                )
            else:
                commands.append(f"trap '{wb_cmd}' EXIT")

    commands.append(f"cd {shlex.quote(str(project_dir))}")

    # Custom init script
    if init_script := get_init_script(config_dir, shell):
        commands.append(f"source {shlex.quote(str(init_script))}")

    return commands


def build_shell_argv(
    project_dir: Path,
    config_dir: Path,
    shell: str,
    secrets: ResolvedSecrets | None = None,
) -> list[str]:
    """Build the full argv to launch an interactive shell with project setup.

    Uses shell-specific mechanisms so setup runs inside the interactive shell:
    - fish: --init-command (runs after config.fish, before prompt)
    - other shells: -c "setup; exec shell"
    """
    commands = _build_init_commands(project_dir, config_dir, shell, secrets)
    shell_name = Path(shell).name

    if shell_name == "fish":
        return [shell, "--init-command", "; ".join(commands)]

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

    Loads config, renames tmux window, and returns everything needed
    to exec into the project shell.
    """
    config = load_config(name)

    # Extract config sections
    project_cfg = config.get("project", {})
    sandbox_cfg = config.get("sandbox", {})
    secrets_cfg = config.get("secrets", {})
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

    # Secrets require sandbox (decrypted into sandbox tmpfs)
    if secrets_cfg and not sandbox_enabled:
        raise SystemExit(
            "[secrets] requires sandbox to be enabled "
            "(secrets are decrypted into sandbox tmpfs)"
        )

    # Resolve secrets paths
    resolved_secrets: ResolvedSecrets | None = None
    ro_bind_extra: list[Path] = []
    rw_bind_extra: list[Path] = []
    setenv_extra: dict[str, str] = {}
    if secrets_cfg:
        require_dep("age")

        archive_raw = secrets_cfg["archive"]
        archive_path = expand_path(archive_raw)
        if not archive_path.is_absolute():
            archive_path = config_dir / archive_raw
        if not archive_path.is_file():
            raise SystemExit(f"Secrets archive not found: {archive_path}")

        identity_path = expand_path(secrets_cfg["identity"])
        if not identity_path.is_file():
            raise SystemExit(f"Secrets identity file not found: {identity_path}")

        dest = secrets_cfg.get("dest", "/tmp/pwrap-secrets")
        writeback = secrets_cfg.get("writeback", False)

        ro_bind_extra = [identity_path.resolve()]
        if writeback:
            rw_bind_extra = [archive_path.resolve()]
            setenv_extra = {
                "PWRAP_SECRETS_DEST": dest,
                "PWRAP_SECRETS_ARCHIVE": str(archive_path.resolve()),
                "PWRAP_SECRETS_IDENTITY": str(identity_path.resolve()),
            }
        else:
            ro_bind_extra.append(archive_path.resolve())

        resolved_secrets = ResolvedSecrets(
            archive=archive_path.resolve(),
            identity=identity_path.resolve(),
            dest=dest,
            writeback=writeback,
        )

    # Rename tmux window
    rename_tmux_window(display_name)

    # Resolve init script and build shell argv
    init_script = get_init_script(config_dir, shell)
    shell_argv = build_shell_argv(
        project_dir, config_dir, shell, secrets=resolved_secrets
    )

    # Non-sandboxed execution
    if not sandbox_enabled:
        return ProjectExec(
            display_name=display_name,
            program=shell,
            argv=shell_argv,
        )

    # Sandboxed execution - verify bwrap is available
    require_dep("bwrap")

    bwrap_args = build_bwrap_args(
        sandbox_cfg, project_dir,
        init_script=init_script, ro_bind_extra=ro_bind_extra,
        rw_bind_extra=rw_bind_extra, setenv_extra=setenv_extra,
    )
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
    if result.is_sandboxed:
        label += " (sandboxed)"
    print(f"Loading {label}")

    if result.verbose_info:
        print(result.verbose_info)

    os.execvp(result.program, result.argv)


def writeback_secrets() -> None:
    """Re-encrypt secrets dest back to the archive. Runs inside the sandbox."""
    dest = os.environ.get("PWRAP_SECRETS_DEST")
    archive = os.environ.get("PWRAP_SECRETS_ARCHIVE")
    identity = os.environ.get("PWRAP_SECRETS_IDENTITY")

    if not all([dest, archive, identity]):
        raise SystemExit(
            "Not in a writeback-enabled sandbox "
            "(PWRAP_SECRETS_* environment variables not set)"
        )

    result = subprocess.run(
        f'tar c -C {shlex.quote(dest)} . | '  # type: ignore[arg-type]
        f'age -e -i {shlex.quote(identity)} -o {shlex.quote(archive)}',  # type: ignore[arg-type]
        shell=True,
    )
    if result.returncode != 0:
        raise SystemExit("Writeback failed")
    print(f"Secrets written back to {archive}")


TEMPLATE_NAMES = ["project.tpl.toml", "init.tpl.fish", "init.tpl.sh"]


def _load_package_template(name: str) -> str:
    """Load a template file from the package templates directory."""
    from importlib.resources import files

    # Package templates use plain names (project.toml), user templates use .tpl. names
    return (files("project_wrap") / "templates" / name).read_text()


def ensure_templates() -> bool:
    """Ensure user-editable templates exist in the config directory.

    On first run, copies package templates to ~/.config/pwrap/ with .tpl. names.
    Returns True if templates were just created (caller should pause for editing).
    """
    config_dir = get_config_dir()
    marker = config_dir / "project.tpl.toml"

    if marker.exists():
        return False

    config_dir.mkdir(parents=True, exist_ok=True)

    # Map .tpl. names to package template names
    pkg_names = {"project.tpl.toml": "project.toml", "init.tpl.fish": "init.fish",
                 "init.tpl.sh": "init.sh"}
    for tpl_name, pkg_name in pkg_names.items():
        (config_dir / tpl_name).write_text(_load_package_template(pkg_name))

    return True


def _load_template(name: str) -> str:
    """Load a template, preferring user-editable version over package default.

    Maps template names: project.toml -> project.tpl.toml, init.fish -> init.tpl.fish
    """
    tpl_name = name.replace(".", ".tpl.", 1)  # project.toml -> project.tpl.toml
    user_tpl = get_config_dir() / tpl_name
    if user_tpl.exists():
        return user_tpl.read_text()
    return _load_package_template(name)


def create_project(
    project_dir: str,
    name: str | None = None,
    sandbox: bool = True,
    shell: str | None = None,
) -> Path:
    """Create a new project config directory with templates.

    Args:
        project_dir: Path to the project working directory.
        name: Project name. Defaults to the directory basename.
        sandbox: Whether to enable sandbox in the generated config.
        shell: Shell path. Defaults to $SHELL.

    Returns the path to the created config directory.
    """
    resolved_dir = expand_path(project_dir).resolve()
    if not resolved_dir.is_dir():
        raise SystemExit(f"Project directory does not exist: {resolved_dir}")

    if name is None:
        name = resolved_dir.name

    if shell is None:
        shell = os.environ.get("SHELL", "/bin/bash")

    validate_project_name(name)
    config_dir = get_config_dir() / name

    if config_dir.exists():
        raise SystemExit(f"Project already exists: {config_dir}")

    sandbox_enabled = "true" if sandbox else "false"

    toml = _load_template("project.toml").format(
        name=name, dir=resolved_dir, sandbox_enabled=sandbox_enabled, shell=shell
    )

    config_dir.mkdir(parents=True)
    (config_dir / "project.toml").write_text(toml)

    # Copy matching init template
    shell_name = Path(shell).name
    if shell_name == "fish":
        (config_dir / "init.fish").write_text(_load_template("init.fish"))
    else:
        (config_dir / "init.sh").write_text(_load_template("init.sh"))

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


