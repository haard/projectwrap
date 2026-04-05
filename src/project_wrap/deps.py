"""Dependency checking for optional external tools."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from enum import Enum


class DepStatus(Enum):
    """Dependency availability status."""

    AVAILABLE = "available"
    MISSING = "missing"


@dataclass
class Dependency:
    """External dependency information."""

    name: str
    binary: str
    install_hint: str
    required_for: str

    def check(self) -> DepStatus:
        """Check if dependency is available."""
        if shutil.which(self.binary):
            return DepStatus.AVAILABLE
        return DepStatus.MISSING


# Known optional dependencies
DEPS = {
    "bwrap": Dependency(
        name="bubblewrap",
        binary="bwrap",
        install_hint="sudo apt install bubblewrap",
        required_for="sandbox isolation",
    ),
    "age": Dependency(
        name="age",
        binary="age",
        install_hint="sudo apt install age",
        required_for="decrypting secrets",
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


def require_dep(name: str) -> None:
    """Ensure a dependency is available, raise if not."""
    dep = DEPS.get(name)
    if dep is None:
        raise ValueError(f"Unknown dependency: {name}")

    if dep.check() == DepStatus.MISSING:
        raise MissingDependencyError(dep)


def check_optional_deps(verbose: bool = False) -> dict[str, DepStatus]:
    """Check all optional dependencies and return their status."""
    results = {}

    for name, dep in DEPS.items():
        status = dep.check()
        results[name] = status

        if verbose:
            icon = "✓" if status == DepStatus.AVAILABLE else "✗"
            status_text = "available" if status == DepStatus.AVAILABLE else "missing"
            print(f"  {icon} {dep.name} ({dep.binary}): {status_text}")
            if status == DepStatus.MISSING:
                print(f"      Install: {dep.install_hint}")
                print(f"      Used for: {dep.required_for}")

    return results
