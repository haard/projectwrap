"""Tests for dependency checking module."""

import pytest
from project_wrap import deps as deps_module
from project_wrap.deps import (
    DEPS,
    Dependency,
    DepStatus,
    MissingDependencyError,
    UnsupportedDependencyError,
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

    status, detail = dep.check()
    assert status == DepStatus.AVAILABLE
    assert detail == ""


def test_dependency_check_missing(monkeypatch):
    """Test that missing dependency is detected."""
    monkeypatch.setattr("shutil.which", lambda x: None)

    dep = Dependency(
        name="test",
        binary="nonexistent",
        install_hint="apt install test",
        required_for="testing",
    )

    status, _ = dep.check()
    assert status == DepStatus.MISSING


def test_dependency_unsupported_via_probe(monkeypatch):
    """Feature probe failure surfaces as UNSUPPORTED."""
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/bwrap")

    dep = Dependency(
        name="test",
        binary="bwrap",
        install_hint="apt install test",
        required_for="testing",
        feature_probe=lambda _path: (False, "missing --foo"),
    )

    status, detail = dep.check()
    assert status == DepStatus.UNSUPPORTED
    assert "missing --foo" in detail


@pytest.mark.real_probe
def test_bwrap_probe_accepts_modern_help(monkeypatch):
    """_probe_bwrap returns True when --unshare-user and --uid are in help."""
    import subprocess

    fake_result = subprocess.CompletedProcess(
        args=["bwrap", "--help"],
        returncode=0,
        stdout="usage: bwrap --unshare-user --uid N --gid N ...",
        stderr="",
    )
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: fake_result)

    ok, reason = deps_module._probe_bwrap("/usr/bin/bwrap")
    assert ok is True
    assert reason == ""


@pytest.mark.real_probe
def test_bwrap_probe_rejects_stripped_build(monkeypatch):
    """_probe_bwrap returns False when required flags are absent."""
    import subprocess

    fake_result = subprocess.CompletedProcess(
        args=["bwrap", "--help"],
        returncode=0,
        stdout="usage: bwrap --bind --tmpfs ...",
        stderr="",
    )
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: fake_result)

    ok, reason = deps_module._probe_bwrap("/usr/bin/bwrap")
    assert ok is False
    assert "--unshare-user" in reason
    assert "--uid" in reason


def test_require_dep_available(monkeypatch):
    """Test require_dep passes when dependency available."""
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/bwrap")
    monkeypatch.setattr(
        deps_module, "_probe_bwrap", lambda _p: (True, "")
    )

    # Should not raise
    require_dep("bwrap")


def test_require_dep_missing(monkeypatch):
    """Test require_dep raises when dependency missing."""
    monkeypatch.setattr("shutil.which", lambda x: None)

    with pytest.raises(MissingDependencyError) as exc_info:
        require_dep("bwrap")

    assert "bubblewrap" in str(exc_info.value)
    assert "apt install bubblewrap" in str(exc_info.value)


def test_require_dep_unsupported(monkeypatch):
    """require_dep raises UnsupportedDependencyError when probe fails."""
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/bwrap")
    monkeypatch.setattr(
        deps_module.DEPS["bwrap"],
        "feature_probe",
        lambda _p: (False, "missing --uid"),
    )

    with pytest.raises(UnsupportedDependencyError) as exc_info:
        require_dep("bwrap")

    assert "missing --uid" in str(exc_info.value)


def test_require_dep_unknown():
    """Test require_dep raises for unknown dependency."""
    with pytest.raises(ValueError, match="Unknown dependency"):
        require_dep("nonexistent_dep")


def test_check_optional_deps(monkeypatch, capsys):
    """Test check_optional_deps reports status."""

    def fake_which(name):
        return "/usr/bin/bwrap" if name == "bwrap" else None

    monkeypatch.setattr("shutil.which", fake_which)
    monkeypatch.setattr(
        deps_module, "_probe_bwrap", lambda _p: (True, "")
    )

    results = check_optional_deps(verbose=True)

    assert results["bwrap"] == DepStatus.AVAILABLE

    captured = capsys.readouterr()
    assert "bubblewrap" in captured.out


def test_check_optional_deps_unsupported(monkeypatch, capsys):
    """Verbose output explains which flags are missing."""
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/bwrap")
    monkeypatch.setattr(
        deps_module.DEPS["bwrap"],
        "feature_probe",
        lambda _p: (False, "bwrap is missing required flags: --uid"),
    )

    results = check_optional_deps(verbose=True)

    assert results["bwrap"] == DepStatus.UNSUPPORTED
    captured = capsys.readouterr()
    assert "--uid" in captured.out


def test_known_deps_have_required_fields():
    """Test all known dependencies have required fields."""
    for name, dep in DEPS.items():
        assert dep.name, f"{name} missing name"
        assert dep.binary, f"{name} missing binary"
        assert dep.install_hint, f"{name} missing install_hint"
        assert dep.required_for, f"{name} missing required_for"
