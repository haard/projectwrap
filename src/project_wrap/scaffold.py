"""Project scaffolding: user-editable templates and new-project creation."""

from __future__ import annotations

import os
import re
from pathlib import Path

from . import core
from .validate import validate_project_name

_SCANNED_LIST_KEYS = {"blacklist", "whitelist", "writable"}
_LIST_START_RE = re.compile(r"^\s*(\w+)\s*=\s*\[")
_STRING_ENTRY_RE = re.compile(r'^\s*"([^"]*)"')


def _comment_missing_paths(toml_text: str) -> str:
    """Comment out blacklist/whitelist/writable entries whose paths don't exist.

    Line-based so template comments and formatting survive. Only uncommented
    string entries are considered; already-commented lines are left as-is.
    """
    out: list[str] = []
    in_scanned_list = False
    for line in toml_text.splitlines():
        stripped = line.lstrip()
        if not in_scanned_list:
            m = _LIST_START_RE.match(line)
            if m and m.group(1) in _SCANNED_LIST_KEYS:
                in_scanned_list = True
            out.append(line)
            continue
        if stripped.startswith("]"):
            in_scanned_list = False
            out.append(line)
            continue
        if not stripped or stripped.startswith("#"):
            out.append(line)
            continue
        entry = _STRING_ENTRY_RE.match(line)
        if entry and not core.expand_path(entry.group(1)).exists():
            indent = line[: len(line) - len(stripped)]
            out.append(f"{indent}# {stripped}  # path not found on host")
            continue
        out.append(line)
    result = "\n".join(out)
    if toml_text.endswith("\n"):
        result += "\n"
    return result


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
    config_dir = core.get_config_dir()
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
    user_tpl = core.get_config_dir() / tpl_name
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
    resolved_dir = core.expand_path(project_dir).resolve()
    if not resolved_dir.is_dir():
        raise SystemExit(f"Project directory does not exist: {resolved_dir}")

    if name is None:
        name = resolved_dir.name

    if shell is None:
        shell = os.environ.get("SHELL", "/bin/bash")

    validate_project_name(name)
    config_dir = core.get_config_dir() / name

    if config_dir.exists():
        raise SystemExit(f"Project already exists: {config_dir}")

    sandbox_enabled = "true" if sandbox else "false"

    toml = _load_template("project.toml").format(
        name=name, dir=resolved_dir, sandbox_enabled=sandbox_enabled, shell=shell
    )
    toml = _comment_missing_paths(toml)

    config_dir.mkdir(parents=True)
    config_dir.chmod(0o700)
    project_toml = config_dir / "project.toml"
    project_toml.write_text(toml)
    project_toml.chmod(0o600)

    # Copy matching init template
    shell_name = Path(shell).name
    if shell_name == "fish":
        init_path = config_dir / "init.fish"
        init_path.write_text(_load_template("init.fish"))
    else:
        init_path = config_dir / "init.sh"
        init_path.write_text(_load_template("init.sh"))
    init_path.chmod(0o600)

    return config_dir
