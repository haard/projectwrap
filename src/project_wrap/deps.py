"""Dependency checking for optional external tools."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum


class DepStatus(Enum):
    """Dependency availability status."""

    AVAILABLE = "available"
    MISSING = "missing"
    UNSUPPORTED = "unsupported"


@dataclass
class Dependency:
    """External dependency information."""

    name: str
    binary: str
    install_hint: str
    required_for: str
    # Optional feature probe: returns (ok, reason). Runs only if the binary
    # is found on PATH. `reason` is shown to the user on failure.
    feature_probe: Callable[[str], tuple[bool, str]] | None = field(
        default=None, repr=False
    )

    def check(self) -> tuple[DepStatus, str]:
        """Check if dependency is available and satisfies feature requirements.

        Returns (status, detail). `detail` is empty on success, otherwise a
        human-readable reason (missing flag, install hint, etc).
        """
        path = shutil.which(self.binary)
        if not path:
            return DepStatus.MISSING, ""
        if self.feature_probe is not None:
            ok, reason = self.feature_probe(path)
            if not ok:
                return DepStatus.UNSUPPORTED, reason
        return DepStatus.AVAILABLE, ""


_bwrap_probe_cache: tuple[bool, str] | None = None


def _probe_bwrap(path: str) -> tuple[bool, str]:
    """Check that bwrap supports --unshare-user and --uid.

    These flags are required by the vault path (vault.py:_inject_uid) to
    drop from the outer user-ns "root" back to the real uid inside the
    sandbox. Result is cached per-process.
    """
    global _bwrap_probe_cache
    if _bwrap_probe_cache is not None:
        return _bwrap_probe_cache

    try:
        result = subprocess.run(
            [path, "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        _bwrap_probe_cache = (False, f"could not run '{path} --help': {e}")
        return _bwrap_probe_cache

    help_text = result.stdout + result.stderr
    missing = [f for f in ("--unshare-user", "--uid") if f not in help_text]
    if missing:
        _bwrap_probe_cache = (
            False,
            f"bwrap is missing required flags: {', '.join(missing)}. "
            f"Upgrade bubblewrap (>= 0.4) — encrypted vaults need these to "
            f"drop back to your real uid inside the sandbox.",
        )
        return _bwrap_probe_cache

    _bwrap_probe_cache = (True, "")
    return _bwrap_probe_cache


# Known optional dependencies
DEPS = {
    "bwrap": Dependency(
        name="bubblewrap",
        binary="bwrap",
        install_hint="sudo apt install bubblewrap",
        required_for="sandbox isolation",
        feature_probe=_probe_bwrap,
    ),
    "gocryptfs": Dependency(
        name="gocryptfs",
        binary="gocryptfs",
        install_hint="sudo apt install gocryptfs",
        required_for="encrypted volumes",
    ),
}


class MissingDependencyError(Exception):
    """Raised when a required dependency is not available."""

    def __init__(self, dep: Dependency):
        self.dep = dep
        super().__init__(
            f"{dep.name} is required for {dep.required_for} but is not installed.\n"
            f"Install with: {dep.install_hint}"
        )


class UnsupportedDependencyError(Exception):
    """Raised when a dependency is installed but lacks a required feature."""

    def __init__(self, dep: Dependency, reason: str):
        self.dep = dep
        self.reason = reason
        super().__init__(f"{dep.name}: {reason}")


def require_dep(name: str) -> None:
    """Ensure a dependency is available, raise if not."""
    dep = DEPS.get(name)
    if dep is None:
        raise ValueError(f"Unknown dependency: {name}")

    status, detail = dep.check()
    if status == DepStatus.MISSING:
        raise MissingDependencyError(dep)
    if status == DepStatus.UNSUPPORTED:
        raise UnsupportedDependencyError(dep, detail)


def check_optional_deps(verbose: bool = False) -> dict[str, DepStatus]:
    """Check all optional dependencies and return their status."""
    results = {}

    for name, dep in DEPS.items():
        status, detail = dep.check()
        results[name] = status

        if verbose:
            icon = "✓" if status == DepStatus.AVAILABLE else "✗"
            status_text = status.value
            print(f"  {icon} {dep.name} ({dep.binary}): {status_text}")
            if status == DepStatus.MISSING:
                print(f"      Install: {dep.install_hint}")
                print(f"      Used for: {dep.required_for}")
            elif status == DepStatus.UNSUPPORTED:
                print(f"      {detail}")

    return results
