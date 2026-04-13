"""Validation functions for project-wrap configuration and inputs."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

ETC_SHELLS = Path("/etc/shells")


def tiocsti_vulnerable() -> bool:
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
    """Check config file and parent directory permissions, refuse insecure files."""
    # Check parent directory
    parent = config_file.parent
    parent_mode = parent.stat().st_mode
    if parent_mode & 0o002:
        raise SystemExit(f"Config directory is world-writable, refusing to load: {parent}")
    if parent_mode & 0o020:
        raise SystemExit(f"Config directory is group-writable, refusing to load: {parent}")

    # Check file
    mode = config_file.stat().st_mode
    if mode & 0o002:
        raise SystemExit(f"Config file is world-writable, refusing to load: {config_file}")
    if mode & 0o020:
        raise SystemExit(f"Config file is group-writable, refusing to load: {config_file}")


_SCHEMA: dict[str, dict[str, type]] = {
    "project": {"name": str, "dir": str, "shell": str},
    "sandbox": {
        "enabled": bool,
        "blacklist": list,
        "whitelist": list,
        "unshare_net": bool,
        "unshare_pid": bool,
        "new_session": bool,
        "clean_env": bool,
        "writable": list,
    },
    "encrypted": {"cipherdir": str, "mountpoint": str, "shared": bool},
    "env": None,  # free-form str→str table, validated separately
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
            # Free-form str→str table (e.g. [env])
            for k, v in value.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    raise SystemExit(
                        f"[{section}].{k}: expected string value, "
                        f"got {type(v).__name__}"
                    )
            continue

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
