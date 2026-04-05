"""Tests for dependency checking module."""

import pytest
from project_wrap.deps import (
    DEPS,
    Dependency,
    DepStatus,
    MissingDependencyError,
    check_optional_deps,
    require_dep,
)


def test_dependency_check_available(monkeypatch):
    """Test that available dependency is detected."""
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/bwrap")

    dep = Dependency(
        name="test",
        binary="bwrap",
        install_hint="apt install test",
        required_for="testing",
    )

    assert dep.check() == DepStatus.AVAILABLE


def test_dependency_check_missing(monkeypatch):
    """Test that missing dependency is detected."""
    monkeypatch.setattr("shutil.which", lambda x: None)

    dep = Dependency(
        name="test",
        binary="nonexistent",
        install_hint="apt install test",
        required_for="testing",
    )

    assert dep.check() == DepStatus.MISSING


def test_require_dep_available(monkeypatch):
    """Test require_dep passes when dependency available."""
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/bwrap")

    # Should not raise
    require_dep("bwrap")


def test_require_dep_missing(monkeypatch):
    """Test require_dep raises when dependency missing."""
    monkeypatch.setattr("shutil.which", lambda x: None)

    with pytest.raises(MissingDependencyError) as exc_info:
        require_dep("bwrap")

    assert "bubblewrap" in str(exc_info.value)
    assert "apt install bubblewrap" in str(exc_info.value)


def test_require_dep_unknown():
    """Test require_dep raises for unknown dependency."""
    with pytest.raises(ValueError, match="Unknown dependency"):
        require_dep("nonexistent_dep")


def test_check_optional_deps(monkeypatch, capsys):
    """Test check_optional_deps reports status."""

    def fake_which(name):
        return "/usr/bin/bwrap" if name == "bwrap" else None

    monkeypatch.setattr("shutil.which", fake_which)

    results = check_optional_deps(verbose=True)

    assert results["bwrap"] == DepStatus.AVAILABLE

    captured = capsys.readouterr()
    assert "bubblewrap" in captured.out


def test_known_deps_have_required_fields():
    """Test all known dependencies have required fields."""
    for name, dep in DEPS.items():
        assert dep.name, f"{name} missing name"
        assert dep.binary, f"{name} missing binary"
        assert dep.install_hint, f"{name} missing install_hint"
        assert dep.required_for, f"{name} missing required_for"
