"""Guided mode: interactively convert an existing folder into a pwrap config.

Asks targeted questions with auto-detected defaults, then generates a
customized project.toml and init script. Optionally initializes a gocryptfs
encrypted vault for secrets.
"""

from __future__ import annotations

import glob
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from . import core
from .validate import validate_project_name

# ---------------------------------------------------------------------------
# Prompter abstraction (injectable for testing)
# ---------------------------------------------------------------------------


class Prompter(Protocol):
    """Interactive prompt interface."""

    def ask(self, prompt: str, default: str | None = None) -> str:
        """Ask for a string. Returns default if empty input."""
        ...

    def confirm(self, prompt: str, default: bool = True) -> bool:
        """Ask a yes/no question."""
        ...

    def multi_select(
        self,
        prompt: str,
        options: list[tuple[str, str]],
        defaults: set[str] | None = None,
    ) -> set[str]:
        """Multi-select from options. Each option is (value, description).

        Returns the set of selected values.
        """
        ...


class ConsolePrompter:
    """Prompter that reads from stdin."""

    def ask(self, prompt: str, default: str | None = None) -> str:
        if default is not None:
            full = f"{prompt} [{default}]: "
        else:
            full = f"{prompt}: "
        answer = input(full).strip()
        return answer if answer else (default or "")

    def confirm(self, prompt: str, default: bool = True) -> bool:
        hint = "Y/n" if default else "y/N"
        answer = input(f"{prompt} [{hint}]: ").strip().lower()
        if not answer:
            return default
        return answer in ("y", "yes")

    def multi_select(
        self,
        prompt: str,
        options: list[tuple[str, str]],
        defaults: set[str] | None = None,
    ) -> set[str]:
        defaults = defaults or set()
        print(f"\n{prompt}")
        print("  Enter numbers separated by spaces, or 'all' / 'none':")
        for i, (value, desc) in enumerate(options, 1):
            marker = "x" if value in defaults else " "
            print(f"  [{marker}] {i}. {desc}")
        print()

        raw = input("  Selection: ").strip().lower()
        if raw in ("", "none"):
            return set()
        if raw == "all":
            return {v for v, _ in options}

        selected: set[str] = set()
        for part in raw.replace(",", " ").split():
            try:
                idx = int(part) - 1
            except ValueError:
                continue
            if 0 <= idx < len(options):
                selected.add(options[idx][0])
        return selected


class ScriptedPrompter:
    """Prompter that returns pre-programmed answers. For testing."""

    def __init__(
        self,
        answers: list[str] | None = None,
        confirms: list[bool] | None = None,
        multi_selects: list[set[str]] | None = None,
    ):
        self._answers = list(answers or [])
        self._confirms = list(confirms or [])
        self._multi_selects = list(multi_selects or [])

    def ask(self, prompt: str, default: str | None = None) -> str:
        if self._answers:
            return self._answers.pop(0)
        return default or ""

    def confirm(self, prompt: str, default: bool = True) -> bool:
        if self._confirms:
            return self._confirms.pop(0)
        return default

    def multi_select(
        self,
        prompt: str,
        options: list[tuple[str, str]],
        defaults: set[str] | None = None,
    ) -> set[str]:
        if self._multi_selects:
            return self._multi_selects.pop(0)
        return defaults or set()


# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------


@dataclass
class ProjectFeatures:
    """Features auto-detected from the project directory."""

    has_venv: bool = False
    has_docker: bool = False
    has_git: bool = False
    env_files: list[str] = field(default_factory=list)
    language: str | None = None
    has_node_modules: bool = False
    has_python_version_file: bool = False


_DOCKER_FILES = {
    "docker-compose.yml",
    "docker-compose.yaml",
    "Dockerfile",
    ".dockerignore",
    "compose.yml",
    "compose.yaml",
}

_LANGUAGE_MARKERS = {
    "pyproject.toml": "python",
    "requirements.txt": "python",
    "setup.py": "python",
    "package.json": "node",
    "Cargo.toml": "rust",
    "go.mod": "go",
    "Gemfile": "ruby",
    "pom.xml": "java",
    "build.gradle": "java",
    "Makefile": "c",
}


def detect_features(project_dir: Path) -> ProjectFeatures:
    """Scan a project directory and detect relevant features."""
    features = ProjectFeatures()

    # Venv
    features.has_venv = (project_dir / ".venv").is_dir()

    # Docker
    for name in _DOCKER_FILES:
        if (project_dir / name).exists():
            features.has_docker = True
            break

    # Git
    features.has_git = (project_dir / ".git").exists()

    # .env files (top-level only)
    for path in sorted(project_dir.glob(".env*")):
        if path.is_file():
            features.env_files.append(path.name)

    # Language detection (first match wins, ordered by specificity)
    for marker, lang in _LANGUAGE_MARKERS.items():
        if (project_dir / marker).exists():
            features.language = lang
            break

    # Node modules
    features.has_node_modules = (project_dir / "node_modules").is_dir()

    # Python version pinning
    features.has_python_version_file = any(
        (project_dir / f).exists()
        for f in (".python-version", ".tool-versions")
    )

    return features


def find_docker_socket() -> str | None:
    """Find an existing docker socket on this host.

    Returns the path as it should appear in the config (with ~ for home),
    or None if no docker socket is found.
    """
    from .core import _DOCKER_SOCKET_CANDIDATES

    home = str(Path.home())
    for candidate in _DOCKER_SOCKET_CANDIDATES:
        pattern = str(core.expand_path(candidate))
        for match in glob.glob(pattern):
            real = os.path.realpath(match)
            if os.path.exists(real):
                # Convert back to ~ form if under home
                if real.startswith(home):
                    return "~/" + real[len(home) + 1:]
                return real
    return None


def find_wsl_docker_socket_path() -> str | None:
    """Construct the expected WSL Docker Desktop socket path.

    On WSL2 with Docker Desktop integration, the socket lives at
    /mnt/wsl/docker-desktop-bind-mounts/<distro>/docker.sock. It only exists
    when Docker Desktop is running, so this returns the expected path even
    if the socket is not currently present.

    Returns None if the WSL distro name cannot be determined.
    """
    distro = os.environ.get("WSL_DISTRO_NAME")
    if distro:
        return f"/mnt/wsl/docker-desktop-bind-mounts/{distro}/docker.sock"
    return None


def wsl_needs_resolv_whitelist() -> bool:
    """Check if WSL DNS requires whitelisting /mnt/wsl/resolv.conf.

    On WSL, /etc/resolv.conf is a symlink into /mnt/wsl. If /mnt is
    blacklisted, DNS breaks unless resolv.conf is whitelisted.
    """
    resolv = Path("/mnt/wsl/resolv.conf")
    return resolv.exists() or Path("/etc/resolv.conf").is_symlink()


_XDG_VARS = (
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
)


def find_host_xdg_vars() -> list[str]:
    """Return XDG environment variables that are set on the host.

    These override HOME-relative defaults, so if HOME is inside the vault
    and clean_env is off, host XDG vars would point tools at host paths
    (which are blacklisted in the sandbox).
    """
    return [v for v in _XDG_VARS if os.environ.get(v)]


_wsl_cache: bool | None = None


def is_wsl() -> bool:
    """Detect if running on WSL (Windows Subsystem for Linux)."""
    global _wsl_cache
    if _wsl_cache is not None:
        return _wsl_cache

    # Check /proc/sys/kernel/osrelease for Microsoft/WSL markers
    osrelease = Path("/proc/sys/kernel/osrelease")
    if osrelease.exists():
        content = osrelease.read_text().lower()
        if "microsoft" in content or "wsl" in content:
            _wsl_cache = True
            return True

    # Fallback: /mnt/wsl exists and is a directory
    if Path("/mnt/wsl").is_dir():
        _wsl_cache = True
        return True

    _wsl_cache = False
    return False


def find_whitelist_candidates(shell: str) -> list[tuple[str, str]]:
    """Return common home paths that exist on this host, for whitelist selection.

    Each entry is (config_path, description). config_path uses ~ notation.
    """
    shell_name = Path(shell).name

    candidates: list[tuple[str, str]] = []

    # Shell config (auto-suggested based on shell)
    shell_configs = {
        "fish": ("~/.config/fish", "Fish shell config + completions"),
        "bash": ("~/.bashrc", "Bash config"),
        "zsh": ("~/.zshrc", "Zsh config"),
        "sh": ("~/.profile", "POSIX shell config"),
    }
    if shell_name in shell_configs:
        path, desc = shell_configs[shell_name]
        expanded = core.expand_path(path)
        if expanded.exists():
            candidates.append((path, desc))

    # Common credential/config paths
    common = [
        ("~/.gitconfig", "Git config (user, signing, aliases)"),
        ("~/.ssh", "SSH keys and config"),
        ("~/.kube", "Kubernetes configs"),
        ("~/.aws", "AWS credentials and config"),
        ("~/.gnupg", "GPG keys"),
        ("~/.config/gh", "GitHub CLI config"),
        ("~/.docker/config.json", "Docker registry auth"),
        ("~/.netrc", "Machine credentials (curl, ftp)"),
    ]
    for path, desc in common:
        expanded = core.expand_path(path)
        if expanded.exists():
            candidates.append((path, desc))

    return candidates


# ---------------------------------------------------------------------------
# Config generation
# ---------------------------------------------------------------------------


def _toml_str(value: str) -> str:
    """Quote a string for TOML output."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _toml_str_list(values: list[str]) -> str:
    """Format a list of strings as a TOML array."""
    if not values:
        return "[]"
    items = ", ".join(_toml_str(v) for v in values)
    return f"[{items}]"


def generate_config_toml(
    name: str,
    project_dir: Path,
    shell: str,
    *,
    sandbox_enabled: bool,
    whitelist: list[str],
    writable: list[str],
    unshare_net: bool,
    clean_env: bool,
    env_vars: dict[str, str] | None = None,
    vault_mountpoint: str | None = None,
    vault_shared: bool = False,
    blacklist_mnt: bool = True,
) -> str:
    """Generate a project.toml string from guided-mode answers."""
    lines: list[str] = []

    # [project]
    lines.append("[project]")
    lines.append(f"name = {_toml_str(name)}")
    lines.append(f"dir = {_toml_str(str(project_dir))}")
    lines.append(f"shell = {_toml_str(shell)}")
    lines.append("")

    # [sandbox]
    lines.append("[sandbox]")
    lines.append(f"enabled = {'true' if sandbox_enabled else 'false'}")
    if sandbox_enabled:
        lines.append("")
        lines.append("# Paths hidden from the sandbox (overlaid with tmpfs)")
        lines.append("blacklist = [")
        lines.append('    "~",       # Deny-by-default home')
        if blacklist_mnt:
            lines.append('    "/mnt",    # WSL: Windows drives')
        lines.append("]")
        lines.append("")
        lines.append("# Read-only exceptions to the blacklist")
        if whitelist:
            lines.append("whitelist = [")
            for w in whitelist:
                lines.append(f"    {_toml_str(w)},")
            lines.append("]")
        else:
            lines.append("whitelist = []")
        lines.append("")
        if writable:
            lines.append("# Extra writable paths")
            lines.append("writable = [")
            for w in writable:
                lines.append(f"    {_toml_str(w)},")
            lines.append("]")
            lines.append("")
        if unshare_net:
            lines.append("unshare_net = true    # No network access in sandbox")
            lines.append("")
        lines.append(f"clean_env = {'true' if clean_env else 'false'}"
                     "    # Clear env, pass through only essentials")
    lines.append("")

    # [env]
    if env_vars:
        lines.append("[env]")
        for k, v in env_vars.items():
            lines.append(f"{k} = {_toml_str(v)}")
        lines.append("")

    # [encrypted]
    if vault_mountpoint:
        lines.append("[encrypted]")
        lines.append('cipherdir = "encrypted"')
        lines.append(f"mountpoint = {_toml_str(vault_mountpoint)}")
        lines.append(f"shared = {'true' if vault_shared else 'false'}")
        lines.append("")

    return "\n".join(lines)


def generate_init_script(
    shell: str,
    *,
    has_venv: bool = False,
    vault_mountpoint: str | None = None,
    env_vars: dict[str, str] | None = None,
    home_in_vault: bool = False,
) -> str:
    """Generate an init script for the given shell."""
    shell_name = Path(shell).name
    is_fish = shell_name == "fish"
    lines: list[str] = []

    if is_fish:
        lines.append("# init.fish — runs inside the sandbox after project loads")
        lines.append("")
        if home_in_vault:
            lines.append("# HOME is inside the vault — create it on first launch")
            lines.append("mkdir -p $PWRAP_VAULT_DIR/.home")
            lines.append("")
        if has_venv:
            lines.append("# Virtual environment activation")
            lines.append("source .venv/bin/activate.fish")
            lines.append("")
        if env_vars:
            lines.append("# Environment variables")
            for k, v in env_vars.items():
                lines.append(f"set -gx {k} {v}")
            lines.append("")
        if vault_mountpoint:
            lines.append("# Encrypted vault is available at $PWRAP_VAULT_DIR")
            lines.append("# Example: set -gx MY_APP_STATE $PWRAP_VAULT_DIR/state")
            lines.append("")
        if not has_venv and not env_vars and not vault_mountpoint and not home_in_vault:
            lines.append("# Add your project setup here (venv, aliases, env vars)")
            lines.append("")
    else:
        lines.append("# init.sh — runs inside the sandbox after project loads")
        lines.append("")
        if home_in_vault:
            lines.append("# HOME is inside the vault — create it on first launch")
            lines.append('mkdir -p "$PWRAP_VAULT_DIR/.home"')
            lines.append("")
        if has_venv:
            lines.append("# Virtual environment activation")
            lines.append("source .venv/bin/activate")
            lines.append("")
        if env_vars:
            lines.append("# Environment variables")
            for k, v in env_vars.items():
                lines.append(f"export {k}={v}")
            lines.append("")
        if vault_mountpoint:
            lines.append("# Encrypted vault is available at $PWRAP_VAULT_DIR")
            lines.append('# Example: export MY_APP_STATE="$PWRAP_VAULT_DIR/state"')
            lines.append("")
        if not has_venv and not env_vars and not vault_mountpoint and not home_in_vault:
            lines.append("# Add your project setup here (venv, aliases, env vars)")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Vault initialization
# ---------------------------------------------------------------------------


def init_vault(config_dir: Path, prompter: Prompter) -> bool:
    """Initialize a gocryptfs encrypted volume.

    Returns True if the vault was initialized, False if skipped/failed.
    """
    from .deps import require_dep

    cipherdir = config_dir / "encrypted"
    if cipherdir.exists():
        return True  # Already initialized

    try:
        require_dep("gocryptfs")
    except Exception as e:
        print(f"  gocryptfs not available: {e}")
        return False

    if not prompter.confirm("  Initialize encrypted vault now?", default=True):
        print("  Skipped. You can set it up later with:")
        print(f"    mkdir -p {cipherdir} && gocryptfs -init {cipherdir}")
        return False

    cipherdir.mkdir(parents=True, exist_ok=True)
    cipherdir.chmod(0o700)

    print(f"  Creating encrypted volume at {cipherdir}")
    print("  You will be prompted to set a vault password.")
    result = subprocess.run(["gocryptfs", "-init", str(cipherdir)])
    if result.returncode != 0:
        print("  Failed to initialize vault.")
        return False

    print("  Vault initialized.")
    return True


# ---------------------------------------------------------------------------
# Main guided flow
# ---------------------------------------------------------------------------


def run_guide(
    project_dir: str,
    prompter: Prompter | None = None,
    *,
    name: str | None = None,
    shell: str | None = None,
) -> Path:
    """Run the guided setup wizard for an existing project directory.

    Args:
        project_dir: Path to the existing project directory.
        prompter: Prompt implementation (defaults to ConsolePrompter).
        name: Override project name (skips the name question).
        shell: Override shell (skips the shell question).

    Returns the path to the created config directory.
    """
    if prompter is None:
        prompter = ConsolePrompter()

    resolved_dir = core.expand_path(project_dir).resolve()
    if not resolved_dir.is_dir():
        raise SystemExit(f"Project directory does not exist: {resolved_dir}")

    # Auto-detect features
    features = detect_features(resolved_dir)

    print(f"\n  Guided setup for: {resolved_dir}")
    print(f"  Detected: {', '.join(_feature_summary(features)) or 'nothing special'}\n")

    # --- Q1: Project name ---
    default_name = name or resolved_dir.name
    if name is None:
        name = prompter.ask("  Project name", default=default_name)
    validate_project_name(name)

    # --- Q2: Shell ---
    if shell is None:
        default_shell = os.environ.get("SHELL", "/bin/bash")
        shell = prompter.ask("  Shell", default=default_shell)

    # --- Q3: Sandbox ---
    sandbox_enabled = prompter.confirm("  Enable sandbox isolation?", default=True)

    whitelist: list[str] = []
    writable: list[str] = []
    unshare_net = False
    clean_env = True
    env_vars: dict[str, str] = {}
    vault_mountpoint: str | None = None
    vault_shared = False
    blacklist_mnt = True
    home_in_vault = False

    if sandbox_enabled:
        # --- Q4: Docker ---
        # On WSL2 with Docker Desktop, the socket only exists when Docker
        # Desktop is running. Ask anyway so the user can configure it ahead
        # of time.
        on_wsl = is_wsl()
        docker_socket = find_docker_socket()
        has_docker_hint = features.has_docker or docker_socket is not None or on_wsl
        if has_docker_hint:
            need_docker = prompter.confirm(
                "  Need access to Docker? (exposes docker socket = root on host)",
                default=features.has_docker,
            )
            if need_docker:
                if docker_socket:
                    writable.append(docker_socket)
                    print(f"    → Will expose {docker_socket}")
                elif on_wsl:
                    expected = find_wsl_docker_socket_path()
                    if expected:
                        print(
                            "    → Docker Desktop socket not found "
                            "(Docker Desktop may not be running)."
                        )
                        print(f"      Expected path: {expected}")
                        print(
                            "      Add it to 'writable' in the config "
                            "when Docker Desktop is running."
                        )
                    else:
                        print("    → No docker socket found on this host.")
                        print(
                            "      You can add one manually to 'writable' "
                            "in the config."
                        )
                else:
                    print("    → No docker socket found on this host.")
                    print(
                        "      You can add one manually to 'writable' "
                        "in the config."
                    )

        # --- Q5: Network isolation ---
        unshare_net = prompter.confirm(
            "  Isolate network? (no internet access in sandbox)", default=False
        )

        # --- Q6: WSL detection ---
        wsl_resolv_whitelisted = False
        if on_wsl:
            print("    → WSL detected.")
            need_mnt = prompter.confirm(
                "  Need access to Windows drives (/mnt/c, /mnt/d, ...)?",
                default=False,
            )
            if need_mnt:
                blacklist_mnt = False
                print("    → /mnt will NOT be blacklisted (Windows drives visible).")
                print("      Warning: Docker Desktop sockets under /mnt/wsl are masked")
                print("      by default, but other files under /mnt are exposed.")
            elif not unshare_net and wsl_needs_resolv_whitelist():
                # DNS needs resolv.conf which is a symlink into /mnt/wsl
                wsl_resolv_whitelisted = True
                print("    → Whitelisting /mnt/wsl/resolv.conf for DNS resolution.")

        # --- Q7: Clean environment ---
        clean_env = prompter.confirm(
            "  Clean environment? (only PATH/HOME/USER/SHELL/TERM/LANG pass through)",
            default=True,
        )

        # --- Q8: Encrypted vault ---
        vault_candidates: list[tuple[str, str]] = []
        if features.env_files:
            for f in features.env_files:
                vault_candidates.append(
                    (f, f"{f} — found in project directory")
                )
        vault_candidates.extend([
            ("shell_history", "Shell history (fish/bash/zsh)"),
            ("claude_state", "Claude Code state (~/.claude, config, history)"),
            ("ai_chat", "AI chat history (aichat, etc.)"),
        ])

        use_vault = prompter.confirm(
            "  Use encrypted vault (gocryptfs) for secrets?", default=False
        )
        if use_vault:
            selected = prompter.multi_select(
                "  What should be encrypted?",
                vault_candidates,
                defaults={f for f, _ in vault_candidates if f in features.env_files},
            )
            vault_shared = prompter.confirm(
                "  Share vault across multiple terminals?", default=False
            )
            # Mountpoint inside the project dir
            vault_mountpoint = str(resolved_dir / "vault")

            # Set env vars for selected items
            if "shell_history" in selected:
                env_vars["XDG_DATA_HOME"] = "vault/.config"
            if "claude_state" in selected:
                env_vars["CLAUDE_CONFIG_DIR"] = "vault/claude"
            if "ai_chat" in selected:
                env_vars["AICHAT_CONFIG_DIR"] = "vault/aichat"

            # --- Q8b: HOME inside vault ---
            home_in_vault = prompter.confirm(
                "  Set HOME inside the vault? (all shell/tool state encrypted at rest)",
                default=False,
            )
            if home_in_vault:
                env_vars["HOME"] = str(resolved_dir / "vault" / ".home")
                print(f"    → HOME will be {resolved_dir / 'vault' / '.home'}")

                # If clean_env is off, host XDG vars would override
                # HOME-relative defaults and point tools at host paths
                # (which are blacklisted in the sandbox).
                if not clean_env:
                    host_xdg = find_host_xdg_vars()
                    if host_xdg:
                        print(
                            f"    → Warning: host has XDG vars set "
                            f"({', '.join(host_xdg)}) that would override"
                        )
                        print(
                            "      HOME-relative paths inside the vault."
                        )
                        enable_clean = prompter.confirm(
                            "    Enable clean_env to strip host XDG vars?",
                            default=True,
                        )
                        if enable_clean:
                            clean_env = True
                            print("    → clean_env enabled.")

        # --- Q9: Home whitelist ---
        wl_candidates = find_whitelist_candidates(shell)
        # Add WSL resolv.conf as a pre-selected candidate if needed
        wsl_candidates: list[tuple[str, str]] = []
        if wsl_resolv_whitelisted:
            wsl_candidates.append(
                ("/mnt/wsl/resolv.conf", "WSL DNS resolution (resolv.conf)")
            )
        all_wl_candidates = wsl_candidates + wl_candidates
        if all_wl_candidates:
            # Pre-select shell config, gitconfig, and WSL resolv.conf
            defaults = set()
            for path, desc in all_wl_candidates:
                desc_lower = desc.lower()
                is_shell_cfg = "shell config" in desc_lower or (
                    "config" in desc_lower and "fish" in desc_lower
                )
                if is_shell_cfg or path == "~/.gitconfig":
                    defaults.add(path)
                if path == "/mnt/wsl/resolv.conf":
                    defaults.add(path)
            selected_wl = prompter.multi_select(
                "  Whitelist home paths (read-only access)?",
                all_wl_candidates,
                defaults=defaults,
            )
            whitelist = sorted(selected_wl)

    # --- Q10: Venv activation ---
    activate_venv = False
    if features.has_venv:
        activate_venv = prompter.confirm(
            "  Activate .venv in init script?", default=True
        )

    # --- Generate config ---
    config_dir = core.get_config_dir() / name
    if config_dir.exists():
        raise SystemExit(f"Project already exists: {config_dir}")

    toml = generate_config_toml(
        name=name,
        project_dir=resolved_dir,
        shell=shell,
        sandbox_enabled=sandbox_enabled,
        whitelist=whitelist,
        writable=writable,
        unshare_net=unshare_net,
        clean_env=clean_env,
        env_vars=env_vars if env_vars else None,
        vault_mountpoint=vault_mountpoint,
        vault_shared=vault_shared,
        blacklist_mnt=blacklist_mnt,
    )

    init_content = generate_init_script(
        shell,
        has_venv=activate_venv,
        vault_mountpoint=vault_mountpoint,
        env_vars=env_vars if env_vars else None,
        home_in_vault=home_in_vault,
    )

    # --- Write files ---
    config_dir.mkdir(parents=True)
    config_dir.chmod(0o700)

    project_toml = config_dir / "project.toml"
    project_toml.write_text(toml)
    project_toml.chmod(0o600)

    shell_name = Path(shell).name
    if shell_name == "fish":
        init_path = config_dir / "init.fish"
    else:
        init_path = config_dir / "init.sh"
    init_path.write_text(init_content)
    init_path.chmod(0o600)

    # --- Initialize vault if requested ---
    if vault_mountpoint:
        init_vault(config_dir, prompter)

    # --- Summary ---
    print(f"\n  Created: {project_toml}")
    print(f"  Created: {init_path}")
    print(f"\n  Launch with: pwrap {name}")
    print(f"  Edit config: {project_toml}")

    return config_dir


def _feature_summary(features: ProjectFeatures) -> list[str]:
    """Human-readable summary of detected features."""
    parts: list[str] = []
    if features.has_venv:
        parts.append("Python venv (.venv/)")
    if features.has_docker:
        parts.append("Docker (compose/Dockerfile)")
    if features.has_git:
        parts.append("Git repo")
    if features.env_files:
        parts.append(f"env files ({', '.join(features.env_files)})")
    if features.language:
        parts.append(f"{features.language} project")
    if features.has_node_modules:
        parts.append("node_modules/")
    if features.has_python_version_file:
        parts.append("version pinning (.python-version/.tool-versions)")
    return parts
