"""Tests for guide module (guided setup wizard)."""

import tomllib

import pytest

import project_wrap.guide as guide_module
from project_wrap.guide import (
    ScriptedPrompter,
    detect_features,
    find_docker_socket,
    find_host_xdg_vars,
    find_whitelist_candidates,
    find_wsl_docker_socket_path,
    generate_config_toml,
    generate_init_script,
    is_wsl,
    run_guide,
    wsl_needs_resolv_whitelist,
)
from project_wrap.validate import validate_config


@pytest.fixture(autouse=True)
def _not_wsl(monkeypatch):
    """Default to non-WSL so the WSL question is skipped in most tests."""
    monkeypatch.setattr(guide_module, "is_wsl", lambda: False)
    monkeypatch.setattr(guide_module, "_wsl_cache", False)

# ---------------------------------------------------------------------------
# detect_features
# ---------------------------------------------------------------------------


class TestDetectFeatures:
    def test_empty_dir(self, tmp_path):
        f = detect_features(tmp_path)
        assert not f.has_venv
        assert not f.has_docker
        assert not f.has_git
        assert f.env_files == []
        assert f.language is None

    def test_detects_venv(self, tmp_path):
        (tmp_path / ".venv").mkdir()
        f = detect_features(tmp_path)
        assert f.has_venv

    def test_detects_docker_compose(self, tmp_path):
        (tmp_path / "docker-compose.yml").write_text("services: {}")
        f = detect_features(tmp_path)
        assert f.has_docker

    def test_detects_dockerfile(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM alpine")
        f = detect_features(tmp_path)
        assert f.has_docker

    def test_detects_git(self, tmp_path):
        (tmp_path / ".git").mkdir()
        f = detect_features(tmp_path)
        assert f.has_git

    def test_detects_env_files(self, tmp_path):
        (tmp_path / ".env").write_text("FOO=bar")
        (tmp_path / ".env.local").write_text("BAZ=qux")
        f = detect_features(tmp_path)
        assert ".env" in f.env_files
        assert ".env.local" in f.env_files

    def test_detects_python_project(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]")
        f = detect_features(tmp_path)
        assert f.language == "python"

    def test_detects_node_project(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        f = detect_features(tmp_path)
        assert f.language == "node"

    def test_detects_rust_project(self, tmp_path):
        (tmp_path / "Cargo.toml").write_text("[package]")
        f = detect_features(tmp_path)
        assert f.language == "rust"

    def test_detects_node_modules(self, tmp_path):
        (tmp_path / "node_modules").mkdir()
        f = detect_features(tmp_path)
        assert f.has_node_modules

    def test_detects_python_version_file(self, tmp_path):
        (tmp_path / ".python-version").write_text("3.12")
        f = detect_features(tmp_path)
        assert f.has_python_version_file

    def test_env_files_only_top_level(self, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / ".env").write_text("NESTED=1")
        (tmp_path / ".env").write_text("TOP=1")
        f = detect_features(tmp_path)
        assert f.env_files == [".env"]


# ---------------------------------------------------------------------------
# generate_config_toml
# ---------------------------------------------------------------------------


class TestGenerateConfigToml:
    def test_minimal_sandbox_config(self, tmp_path):
        toml = generate_config_toml(
            name="myproj",
            project_dir=tmp_path,
            shell="/usr/bin/fish",
            sandbox_enabled=True,
            whitelist=["~/.gitconfig"],
            writable=[],
            unshare_net=False,
            clean_env=True,
        )
        cfg = tomllib.loads(toml)
        assert cfg["project"]["name"] == "myproj"
        assert cfg["project"]["shell"] == "/usr/bin/fish"
        assert cfg["sandbox"]["enabled"] is True
        assert "~/.gitconfig" in cfg["sandbox"]["whitelist"]
        assert cfg["sandbox"]["clean_env"] is True
        validate_config(cfg)

    def test_no_sandbox(self, tmp_path):
        toml = generate_config_toml(
            name="myproj",
            project_dir=tmp_path,
            shell="/bin/bash",
            sandbox_enabled=False,
            whitelist=[],
            writable=[],
            unshare_net=False,
            clean_env=False,
        )
        cfg = tomllib.loads(toml)
        assert cfg["sandbox"]["enabled"] is False
        validate_config(cfg)

    def test_with_docker_writable(self, tmp_path):
        toml = generate_config_toml(
            name="myproj",
            project_dir=tmp_path,
            shell="/bin/bash",
            sandbox_enabled=True,
            whitelist=[],
            writable=["/run/docker.sock"],
            unshare_net=False,
            clean_env=True,
        )
        cfg = tomllib.loads(toml)
        assert "/run/docker.sock" in cfg["sandbox"]["writable"]
        validate_config(cfg)

    def test_with_unshare_net(self, tmp_path):
        toml = generate_config_toml(
            name="myproj",
            project_dir=tmp_path,
            shell="/bin/bash",
            sandbox_enabled=True,
            whitelist=[],
            writable=[],
            unshare_net=True,
            clean_env=True,
        )
        cfg = tomllib.loads(toml)
        assert cfg["sandbox"]["unshare_net"] is True
        validate_config(cfg)

    def test_with_env_vars(self, tmp_path):
        toml = generate_config_toml(
            name="myproj",
            project_dir=tmp_path,
            shell="/bin/bash",
            sandbox_enabled=True,
            whitelist=[],
            writable=[],
            unshare_net=False,
            clean_env=True,
            env_vars={"FOO": "bar", "BAZ": "qux"},
        )
        cfg = tomllib.loads(toml)
        assert cfg["env"]["FOO"] == "bar"
        assert cfg["env"]["BAZ"] == "qux"
        validate_config(cfg)

    def test_with_vault(self, tmp_path):
        toml = generate_config_toml(
            name="myproj",
            project_dir=tmp_path,
            shell="/bin/bash",
            sandbox_enabled=True,
            whitelist=[],
            writable=[],
            unshare_net=False,
            clean_env=True,
            vault_mountpoint=str(tmp_path / "vault"),
            vault_shared=True,
        )
        cfg = tomllib.loads(toml)
        assert cfg["encrypted"]["cipherdir"] == "encrypted"
        assert cfg["encrypted"]["shared"] is True
        validate_config(cfg)

    def test_empty_whitelist(self, tmp_path):
        toml = generate_config_toml(
            name="myproj",
            project_dir=tmp_path,
            shell="/bin/bash",
            sandbox_enabled=True,
            whitelist=[],
            writable=[],
            unshare_net=False,
            clean_env=True,
        )
        cfg = tomllib.loads(toml)
        assert cfg["sandbox"]["whitelist"] == []
        validate_config(cfg)

    def test_special_chars_in_name(self, tmp_path):
        toml = generate_config_toml(
            name='my"project',
            project_dir=tmp_path,
            shell="/bin/bash",
            sandbox_enabled=False,
            whitelist=[],
            writable=[],
            unshare_net=False,
            clean_env=False,
        )
        cfg = tomllib.loads(toml)
        assert cfg["project"]["name"] == 'my"project'


# ---------------------------------------------------------------------------
# generate_init_script
# ---------------------------------------------------------------------------


class TestGenerateInitScript:
    def test_fish_with_venv(self):
        content = generate_init_script("/usr/bin/fish", has_venv=True)
        assert "source .venv/bin/activate.fish" in content
        assert "init.fish" in content

    def test_bash_with_venv(self):
        content = generate_init_script("/bin/bash", has_venv=True)
        assert "source .venv/bin/activate" in content
        assert "init.sh" in content

    def test_fish_with_env_vars(self):
        content = generate_init_script(
            "/usr/bin/fish",
            env_vars={"FOO": "bar"},
        )
        assert "set -gx FOO bar" in content

    def test_bash_with_env_vars(self):
        content = generate_init_script(
            "/bin/bash",
            env_vars={"FOO": "bar"},
        )
        assert "export FOO=bar" in content

    def test_with_vault_hint(self):
        content = generate_init_script(
            "/usr/bin/fish",
            vault_mountpoint="/home/user/project/vault",
        )
        assert "PWRAP_VAULT_DIR" in content

    def test_empty_init(self):
        content = generate_init_script("/bin/bash")
        assert "init.sh" in content
        assert "Add your project setup here" in content

    def test_zsh_uses_sh_format(self):
        content = generate_init_script("/usr/bin/zsh", has_venv=True)
        assert "source .venv/bin/activate" in content
        assert "init.sh" in content


# ---------------------------------------------------------------------------
# wsl_needs_resolv_whitelist
# ---------------------------------------------------------------------------


class TestWslNeedsResolvWhitelist:
    def test_true_when_resolv_conf_exists(self, monkeypatch, tmp_path):
        resolv = tmp_path / "resolv.conf"
        resolv.write_text("nameserver 8.8.8.8")

        class FakePath:
            def __init__(self, p):
                self._p = str(p)

            def exists(self):
                return self._p == "/mnt/wsl/resolv.conf"

            def is_symlink(self):
                return False

        monkeypatch.setattr(guide_module, "Path", FakePath)
        assert wsl_needs_resolv_whitelist() is True

    def test_true_when_etc_resolv_is_symlink(self, monkeypatch):
        class FakePath:
            def __init__(self, p):
                self._p = str(p)

            def exists(self):
                return False

            def is_symlink(self):
                return self._p == "/etc/resolv.conf"

        monkeypatch.setattr(guide_module, "Path", FakePath)
        assert wsl_needs_resolv_whitelist() is True

    def test_false_when_neither(self, monkeypatch):
        class FakePath:
            def __init__(self, p):
                self._p = str(p)

            def exists(self):
                return False

            def is_symlink(self):
                return False

        monkeypatch.setattr(guide_module, "Path", FakePath)
        assert wsl_needs_resolv_whitelist() is False


# ---------------------------------------------------------------------------
# find_wsl_docker_socket_path
# ---------------------------------------------------------------------------


class TestFindWslDockerSocketPath:
    def test_returns_path_with_distro_name(self, monkeypatch):
        monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu-22.04")
        result = find_wsl_docker_socket_path()
        assert result == "/mnt/wsl/docker-desktop-bind-mounts/Ubuntu-22.04/docker.sock"

    def test_returns_none_without_distro_name(self, monkeypatch):
        monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
        result = find_wsl_docker_socket_path()
        assert result is None

    def test_path_format(self, monkeypatch):
        monkeypatch.setenv("WSL_DISTRO_NAME", "Debian")
        result = find_wsl_docker_socket_path()
        assert result == "/mnt/wsl/docker-desktop-bind-mounts/Debian/docker.sock"


# ---------------------------------------------------------------------------
# find_docker_socket
# ---------------------------------------------------------------------------


class TestFindDockerSocket:
    def test_no_socket(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            "project_wrap.guide.core._DOCKER_SOCKET_CANDIDATES", []
        )
        assert find_docker_socket() is None

    def test_finds_socket(self, monkeypatch, tmp_path):
        sock = tmp_path / "docker.sock"
        sock.write_text("")
        monkeypatch.setattr(
            "project_wrap.guide.core._DOCKER_SOCKET_CANDIDATES",
            [str(sock)],
        )
        result = find_docker_socket()
        assert result == str(sock)

    def test_converts_home_to_tilde(self, monkeypatch, tmp_path):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        sock = home / ".docker" / "run" / "docker.sock"
        sock.parent.mkdir(parents=True)
        sock.write_text("")
        monkeypatch.setattr(
            "project_wrap.guide.core._DOCKER_SOCKET_CANDIDATES",
            ["~/.docker/run/docker.sock"],
        )
        result = find_docker_socket()
        assert result == "~/.docker/run/docker.sock"


# ---------------------------------------------------------------------------
# find_whitelist_candidates
# ---------------------------------------------------------------------------


class TestFindWhitelistCandidates:
    def test_returns_existing_paths(self, monkeypatch, tmp_path):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))

        # Create some paths
        (home / ".gitconfig").write_text("[user]")
        fish_config = home / ".config" / "fish"
        fish_config.mkdir(parents=True)

        candidates = find_whitelist_candidates("/usr/bin/fish")
        paths = [c[0] for c in candidates]
        assert "~/.gitconfig" in paths
        assert "~/.config/fish" in paths

    def test_skips_missing_paths(self, monkeypatch, tmp_path):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))

        candidates = find_whitelist_candidates("/usr/bin/fish")
        paths = [c[0] for c in candidates]
        assert "~/.ssh" not in paths
        assert "~/.aws" not in paths

    def test_bash_shell_config(self, monkeypatch, tmp_path):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        (home / ".bashrc").write_text("# bash")

        candidates = find_whitelist_candidates("/bin/bash")
        paths = [c[0] for c in candidates]
        assert "~/.bashrc" in paths


# ---------------------------------------------------------------------------
# run_guide (integration-style with ScriptedPrompter)
# ---------------------------------------------------------------------------


class TestRunGuide:
    def _setup_project(self, tmp_path, monkeypatch, **files):
        """Create a project dir and config dir, return (project_dir, config_dir)."""
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        for name, content in files.items():
            p = project_dir / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        config_dir = tmp_path / "config"
        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)
        return project_dir, config_dir

    def test_basic_sandbox_no_extras(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)

        prompter = ScriptedPrompter(
            answers=["myproject", "/usr/bin/fish"],
            confirms=[
                True,   # sandbox enabled
                False,  # docker
                False,  # network isolation
                True,   # clean env
                False,  # vault
            ],
            multi_selects=[
                set(),  # whitelist (none selected)
            ],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        assert result == config_dir / "myproject"
        toml_path = result / "project.toml"
        assert toml_path.exists()

        with open(toml_path, "rb") as f:
            cfg = tomllib.load(f)
        assert cfg["project"]["name"] == "myproject"
        assert cfg["sandbox"]["enabled"] is True
        validate_config(cfg)

    def test_with_docker_and_whitelist(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(
            tmp_path, monkeypatch,
            **{"docker-compose.yml": "services: {}"},
        )
        # Create a fake docker socket
        sock = tmp_path / "docker.sock"
        sock.write_text("")
        monkeypatch.setattr(
            "project_wrap.guide.core._DOCKER_SOCKET_CANDIDATES",
            [str(sock)],
        )

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                True,   # sandbox
                True,   # docker
                False,  # network
                True,   # clean env
                False,  # vault
            ],
            multi_selects=[
                {"~/.gitconfig"},  # whitelist
            ],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert str(sock) in cfg["sandbox"]["writable"]
        assert "~/.gitconfig" in cfg["sandbox"]["whitelist"]
        validate_config(cfg)

    def test_with_vault(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(
            tmp_path, monkeypatch,
            **{".env": "SECRET=abc"},
        )
        # Skip actual gocryptfs init
        monkeypatch.setattr(
            "project_wrap.guide.init_vault", lambda *a, **kw: True
        )

        prompter = ScriptedPrompter(
            answers=["myproject", "/usr/bin/fish"],
            confirms=[
                True,   # sandbox
                False,  # network
                True,   # clean env
                True,   # vault
                False,  # shared vault
                False,  # HOME in vault
            ],
            multi_selects=[
                {".env", "shell_history"},  # vault contents
                set(),  # whitelist
            ],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert "encrypted" in cfg
        assert cfg["encrypted"]["shared"] is False
        assert "XDG_DATA_HOME" in cfg.get("env", {})
        validate_config(cfg)

    def test_with_venv_init_script(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)
        (project_dir / ".venv").mkdir()

        prompter = ScriptedPrompter(
            answers=["myproject", "/usr/bin/fish"],
            confirms=[
                True,   # sandbox
                False,  # docker
                False,  # network
                True,   # clean env
                False,  # vault
                True,   # activate venv
            ],
            multi_selects=[
                set(),  # whitelist
            ],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        init_content = (result / "init.fish").read_text()
        assert "source .venv/bin/activate.fish" in init_content

    def test_no_sandbox(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                False,  # sandbox disabled
            ],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert cfg["sandbox"]["enabled"] is False
        validate_config(cfg)

    def test_name_override(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)

        prompter = ScriptedPrompter(
            answers=["/bin/bash"],  # only shell question
            confirms=[
                False,  # sandbox
            ],
        )

        result = run_guide(
            str(project_dir), prompter=prompter, name="custom-name"
        )

        assert result == config_dir / "custom-name"
        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert cfg["project"]["name"] == "custom-name"

    def test_shell_override(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)

        prompter = ScriptedPrompter(
            answers=["myproject"],  # only name question
            confirms=[
                False,  # sandbox
            ],
        )

        result = run_guide(
            str(project_dir), prompter=prompter, shell="/bin/bash"
        )

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert cfg["project"]["shell"] == "/bin/bash"

    def test_fails_if_project_exists(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)
        (config_dir / "myproject").mkdir(parents=True)

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[False],
        )

        with pytest.raises(SystemExit, match="Project already exists"):
            run_guide(str(project_dir), prompter=prompter)

    def test_fails_if_dir_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "project_wrap.core.get_config_dir", lambda: tmp_path / "config"
        )
        prompter = ScriptedPrompter()

        with pytest.raises(SystemExit, match="Project directory does not exist"):
            run_guide(str(tmp_path / "nonexistent"), prompter=prompter)

    def test_creates_init_sh_for_bash(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[False],
        )

        result = run_guide(str(project_dir), prompter=prompter)
        assert (result / "init.sh").exists()
        assert not (result / "init.fish").exists()

    def test_creates_init_fish_for_fish(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)

        prompter = ScriptedPrompter(
            answers=["myproject", "/usr/bin/fish"],
            confirms=[False],
        )

        result = run_guide(str(project_dir), prompter=prompter)
        assert (result / "init.fish").exists()
        assert not (result / "init.sh").exists()

    def test_secure_permissions(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[False],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        assert result.stat().st_mode & 0o777 == 0o700
        assert (result / "project.toml").stat().st_mode & 0o777 == 0o600
        assert (result / "init.sh").stat().st_mode & 0o777 == 0o600

    def test_unshare_net_in_config(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                True,   # sandbox
                True,   # network isolation
                True,   # clean env
                False,  # vault
            ],
            multi_selects=[set()],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert cfg["sandbox"]["unshare_net"] is True
        validate_config(cfg)

    def test_vault_with_claude_state(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "project_wrap.guide.init_vault", lambda *a, **kw: True
        )

        prompter = ScriptedPrompter(
            answers=["myproject", "/usr/bin/fish"],
            confirms=[
                True,   # sandbox
                False,  # network
                True,   # clean env
                True,   # vault
                True,   # shared vault
                False,  # HOME in vault
            ],
            multi_selects=[
                {"claude_state"},  # vault contents
                set(),  # whitelist
            ],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert cfg["encrypted"]["shared"] is True
        assert cfg["env"]["CLAUDE_CONFIG_DIR"] == "vault/claude"
        validate_config(cfg)


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestGuideCLI:
    def test_guide_flag(self, tmp_path, monkeypatch, capsys):
        from project_wrap.cli import main

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        config_dir = tmp_path / "config"
        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        # Patch run_guide to use a scripted prompter
        original_run_guide = __import__("project_wrap.guide", fromlist=["run_guide"]).run_guide

        def patched_run_guide(dir_arg, prompter=None, **kwargs):
            prompter = ScriptedPrompter(
                answers=["myproject", "/bin/bash"],
                confirms=[False],
            )
            return original_run_guide(dir_arg, prompter=prompter, **kwargs)

        monkeypatch.setattr("project_wrap.cli.run_guide", patched_run_guide)

        result = main(["--guide", str(project_dir)])

        assert result == 0
        assert (config_dir / "myproject" / "project.toml").exists()

    def test_guide_in_help(self, capsys):
        from project_wrap.cli import main

        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "--guide" in captured.out


# ---------------------------------------------------------------------------
# is_wsl detection
# ---------------------------------------------------------------------------


class TestIsWsl:
    def test_detects_wsl_via_osrelease(self, monkeypatch):
        monkeypatch.setattr(guide_module, "_wsl_cache", None)

        class FakePath:
            def __init__(self, p):
                self._p = str(p)

            def exists(self):
                return self._p == "/proc/sys/kernel/osrelease"

            def read_text(self):
                return "6.6.87.2-microsoft-standard-WSL2\n"

            def is_dir(self):
                return False

        monkeypatch.setattr(guide_module, "Path", FakePath)
        assert is_wsl() is True

    def test_detects_wsl_via_mnt_wsl(self, monkeypatch, tmp_path):
        monkeypatch.setattr(guide_module, "_wsl_cache", None)

        class FakePath:
            def __init__(self, p):
                self._p = str(p)

            def exists(self):
                return self._p == "/proc/sys/kernel/osrelease"

            def read_text(self):
                return "6.6.87.2-standard\n"  # no WSL marker

            def is_dir(self):
                return self._p == "/mnt/wsl"

        monkeypatch.setattr(guide_module, "Path", FakePath)
        assert is_wsl() is True

    def test_not_wsl(self, monkeypatch):
        monkeypatch.setattr(guide_module, "_wsl_cache", None)

        class FakePath:
            def __init__(self, p):
                self._p = str(p)

            def exists(self):
                return self._p == "/proc/sys/kernel/osrelease"

            def read_text(self):
                return "6.6.87.2-standard\n"

            def is_dir(self):
                return False

        monkeypatch.setattr(guide_module, "Path", FakePath)
        assert is_wsl() is False

    def test_caches_result(self, monkeypatch):
        monkeypatch.setattr(guide_module, "_wsl_cache", None)
        call_count = 0

        class FakePath:
            def __init__(self, p):
                self._p = str(p)

            def exists(self):
                nonlocal call_count
                call_count += 1
                return False

            def read_text(self):
                return ""

            def is_dir(self):
                return False

        monkeypatch.setattr(guide_module, "Path", FakePath)
        is_wsl()
        is_wsl()
        is_wsl()
        # Should only check once due to caching
        assert call_count <= 2  # osrelease exists check + maybe is_dir


# ---------------------------------------------------------------------------
# generate_config_toml with blacklist_mnt
# ---------------------------------------------------------------------------


class TestGenerateConfigTomlBlacklistMnt:
    def test_blacklist_mnt_true(self, tmp_path):
        toml = generate_config_toml(
            name="p", project_dir=tmp_path, shell="/bin/bash",
            sandbox_enabled=True, whitelist=[], writable=[],
            unshare_net=False, clean_env=True, blacklist_mnt=True,
        )
        cfg = tomllib.loads(toml)
        assert "/mnt" in cfg["sandbox"]["blacklist"]
        validate_config(cfg)

    def test_blacklist_mnt_false(self, tmp_path):
        toml = generate_config_toml(
            name="p", project_dir=tmp_path, shell="/bin/bash",
            sandbox_enabled=True, whitelist=[], writable=[],
            unshare_net=False, clean_env=True, blacklist_mnt=False,
        )
        cfg = tomllib.loads(toml)
        assert "/mnt" not in cfg["sandbox"]["blacklist"]
        assert "~" in cfg["sandbox"]["blacklist"]
        validate_config(cfg)

    def test_blacklist_mnt_default_is_true(self, tmp_path):
        toml = generate_config_toml(
            name="p", project_dir=tmp_path, shell="/bin/bash",
            sandbox_enabled=True, whitelist=[], writable=[],
            unshare_net=False, clean_env=True,
        )
        cfg = tomllib.loads(toml)
        assert "/mnt" in cfg["sandbox"]["blacklist"]


# ---------------------------------------------------------------------------
# generate_init_script with home_in_vault
# ---------------------------------------------------------------------------


class TestGenerateInitScriptHomeInVault:
    def test_fish_home_in_vault(self):
        content = generate_init_script(
            "/usr/bin/fish", home_in_vault=True,
            vault_mountpoint="/home/user/proj/vault",
        )
        assert "mkdir -p $PWRAP_VAULT_DIR/.home" in content
        assert "HOME is inside the vault" in content

    def test_bash_home_in_vault(self):
        content = generate_init_script(
            "/bin/bash", home_in_vault=True,
            vault_mountpoint="/home/user/proj/vault",
        )
        assert 'mkdir -p "$PWRAP_VAULT_DIR/.home"' in content
        assert "HOME is inside the vault" in content

    def test_home_in_vault_with_venv(self):
        content = generate_init_script(
            "/bin/bash", has_venv=True, home_in_vault=True,
            vault_mountpoint="/home/user/proj/vault",
        )
        assert "mkdir -p" in content
        assert "source .venv/bin/activate" in content

    def test_no_home_in_vault_by_default(self):
        content = generate_init_script("/bin/bash")
        assert "mkdir -p" not in content
        assert "HOME is inside the vault" not in content


# ---------------------------------------------------------------------------
# run_guide with WSL
# ---------------------------------------------------------------------------


class TestRunGuideWSL:
    def _setup_project(self, tmp_path, monkeypatch, **files):
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        for name, content in files.items():
            p = project_dir / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        config_dir = tmp_path / "config"
        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)
        return project_dir, config_dir

    def test_wsl_no_mnt_access_whitelists_resolv(self, tmp_path, monkeypatch):
        """On WSL without /mnt access and network enabled, resolv.conf is whitelisted."""
        monkeypatch.setattr(guide_module, "is_wsl", lambda: True)
        monkeypatch.setattr(guide_module, "_wsl_cache", True)
        monkeypatch.setattr(
            "project_wrap.guide.wsl_needs_resolv_whitelist", lambda: True
        )

        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                True,   # sandbox
                False,  # docker (asked because on WSL)
                False,  # network (not isolated)
                False,  # WSL: no /mnt access
                True,   # clean env
                False,  # vault
            ],
            multi_selects=[
                {"/mnt/wsl/resolv.conf"},  # whitelist (keep resolv.conf)
            ],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert "/mnt" in cfg["sandbox"]["blacklist"]
        assert "/mnt/wsl/resolv.conf" in cfg["sandbox"]["whitelist"]
        validate_config(cfg)

    def test_wsl_resolv_deselected_not_in_whitelist(self, tmp_path, monkeypatch):
        """On WSL, user can deselect resolv.conf from whitelist."""
        monkeypatch.setattr(guide_module, "is_wsl", lambda: True)
        monkeypatch.setattr(guide_module, "_wsl_cache", True)
        monkeypatch.setattr(
            "project_wrap.guide.wsl_needs_resolv_whitelist", lambda: True
        )

        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                True,   # sandbox
                False,  # docker
                False,  # network
                False,  # WSL: no /mnt access
                True,   # clean env
                False,  # vault
            ],
            multi_selects=[
                set(),  # whitelist (deselect resolv.conf)
            ],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert "/mnt/wsl/resolv.conf" not in cfg["sandbox"].get("whitelist", [])
        validate_config(cfg)

    def test_wsl_with_mnt_access_no_blacklist(self, tmp_path, monkeypatch):
        """On WSL with /mnt access, /mnt is not blacklisted."""
        monkeypatch.setattr(guide_module, "is_wsl", lambda: True)
        monkeypatch.setattr(guide_module, "_wsl_cache", True)

        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                True,   # sandbox
                False,  # docker (asked because on WSL)
                False,  # network
                True,   # WSL: need /mnt access
                True,   # clean env
                False,  # vault
            ],
            multi_selects=[set()],  # whitelist
        )

        result = run_guide(str(project_dir), prompter=prompter)

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert "/mnt" not in cfg["sandbox"]["blacklist"]
        assert "~" in cfg["sandbox"]["blacklist"]
        validate_config(cfg)

    def test_wsl_without_mnt_access_keeps_blacklist(self, tmp_path, monkeypatch):
        """On WSL without /mnt access, /mnt stays blacklisted."""
        monkeypatch.setattr(guide_module, "is_wsl", lambda: True)
        monkeypatch.setattr(guide_module, "_wsl_cache", True)

        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                True,   # sandbox
                False,  # docker (asked because on WSL)
                False,  # network
                False,  # WSL: no /mnt access
                True,   # clean env
                False,  # vault
            ],
            multi_selects=[set()],  # whitelist
        )

        result = run_guide(str(project_dir), prompter=prompter)

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert "/mnt" in cfg["sandbox"]["blacklist"]
        validate_config(cfg)

    def test_wsl_network_isolated_no_resolv_needed(self, tmp_path, monkeypatch):
        """On WSL with network isolation, no resolv.conf whitelist needed."""
        monkeypatch.setattr(guide_module, "is_wsl", lambda: True)
        monkeypatch.setattr(guide_module, "_wsl_cache", True)

        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                True,   # sandbox
                False,  # docker (asked because on WSL)
                True,   # network isolation
                False,  # WSL: no /mnt access
                True,   # clean env
                False,  # vault
            ],
            multi_selects=[set()],  # whitelist
        )

        result = run_guide(str(project_dir), prompter=prompter)

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert "/mnt" in cfg["sandbox"]["blacklist"]
        assert cfg["sandbox"]["unshare_net"] is True
        # resolv.conf should NOT be in whitelist (network is isolated)
        assert "/mnt/wsl/resolv.conf" not in cfg["sandbox"].get("whitelist", [])
        validate_config(cfg)

    def test_wsl_docker_asked_even_without_socket(self, tmp_path, monkeypatch, capsys):
        """On WSL, Docker question is asked even if no socket is visible."""
        monkeypatch.setattr(guide_module, "is_wsl", lambda: True)
        monkeypatch.setattr(guide_module, "_wsl_cache", True)
        # No docker socket on host
        monkeypatch.setattr(
            "project_wrap.guide.find_docker_socket", lambda: None
        )
        monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu-22.04")

        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                True,   # sandbox
                True,   # docker (yes, even without socket)
                False,  # network
                False,  # WSL: no /mnt access
                True,   # clean env
                False,  # vault
            ],
            multi_selects=[set()],  # whitelist
        )

        result = run_guide(str(project_dir), prompter=prompter)

        captured = capsys.readouterr().out
        assert "Docker Desktop socket not found" in captured
        assert "/mnt/wsl/docker-desktop-bind-mounts/Ubuntu-22.04/docker.sock" in captured

        # Socket should NOT be in writable (it doesn't exist)
        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert cfg["sandbox"].get("writable", []) == []
        validate_config(cfg)

    def test_wsl_docker_socket_found_added_to_writable(self, tmp_path, monkeypatch):
        """On WSL with Docker Desktop running, socket is added to writable."""
        monkeypatch.setattr(guide_module, "is_wsl", lambda: True)
        monkeypatch.setattr(guide_module, "_wsl_cache", True)
        monkeypatch.setattr(
            "project_wrap.guide.find_docker_socket",
            lambda: "/mnt/wsl/docker-desktop-bind-mounts/Ubuntu/docker.sock",
        )

        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                True,   # sandbox
                True,   # docker
                False,  # network
                False,  # WSL: no /mnt access
                True,   # clean env
                False,  # vault
            ],
            multi_selects=[set()],  # whitelist
        )

        result = run_guide(str(project_dir), prompter=prompter)

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        wsl_sock = "/mnt/wsl/docker-desktop-bind-mounts/Ubuntu/docker.sock"
        assert wsl_sock in cfg["sandbox"]["writable"]
        validate_config(cfg)


# ---------------------------------------------------------------------------
# run_guide with HOME in vault
# ---------------------------------------------------------------------------


class TestRunGuideHomeInVault:
    def _setup_project(self, tmp_path, monkeypatch, **files):
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        for name, content in files.items():
            p = project_dir / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        config_dir = tmp_path / "config"
        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)
        return project_dir, config_dir

    def test_home_in_vault_sets_env(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "project_wrap.guide.init_vault", lambda *a, **kw: True
        )

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                True,   # sandbox
                False,  # network
                True,   # clean env
                True,   # vault
                False,  # shared vault
                True,   # HOME in vault
            ],
            multi_selects=[
                {"shell_history"},  # vault contents
                set(),  # whitelist
            ],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        expected_home = str(project_dir.resolve() / "vault" / ".home")
        assert cfg["env"]["HOME"] == expected_home
        validate_config(cfg)

    def test_home_in_vault_init_script(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "project_wrap.guide.init_vault", lambda *a, **kw: True
        )

        prompter = ScriptedPrompter(
            answers=["myproject", "/usr/bin/fish"],
            confirms=[
                True,   # sandbox
                False,  # network
                True,   # clean env
                True,   # vault
                False,  # shared vault
                True,   # HOME in vault
            ],
            multi_selects=[
                set(),  # vault contents (none)
                set(),  # whitelist
            ],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        init_content = (result / "init.fish").read_text()
        assert "mkdir -p $PWRAP_VAULT_DIR/.home" in init_content

    def test_no_home_in_vault_by_default(self, tmp_path, monkeypatch):
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "project_wrap.guide.init_vault", lambda *a, **kw: True
        )

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                True,   # sandbox
                False,  # network
                True,   # clean env
                True,   # vault
                False,  # shared vault
                False,  # HOME in vault
            ],
            multi_selects=[
                set(),  # vault contents
                set(),  # whitelist
            ],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert "HOME" not in cfg.get("env", {})
        validate_config(cfg)

        init_content = (result / "init.sh").read_text()
        assert "mkdir -p" not in init_content


# ---------------------------------------------------------------------------
# find_host_xdg_vars
# ---------------------------------------------------------------------------


class TestFindHostXdgVars:
    def test_returns_set_vars(self, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", "/custom/config")
        monkeypatch.setenv("XDG_DATA_HOME", "/custom/data")
        monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
        monkeypatch.delenv("XDG_STATE_HOME", raising=False)
        result = find_host_xdg_vars()
        assert "XDG_CONFIG_HOME" in result
        assert "XDG_DATA_HOME" in result
        assert "XDG_CACHE_HOME" not in result
        assert "XDG_STATE_HOME" not in result

    def test_returns_empty_when_none_set(self, monkeypatch):
        for v in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"):
            monkeypatch.delenv(v, raising=False)
        assert find_host_xdg_vars() == []

    def test_returns_all_four(self, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", "/c")
        monkeypatch.setenv("XDG_DATA_HOME", "/d")
        monkeypatch.setenv("XDG_CACHE_HOME", "/cache")
        monkeypatch.setenv("XDG_STATE_HOME", "/s")
        result = find_host_xdg_vars()
        assert len(result) == 4


# ---------------------------------------------------------------------------
# run_guide: XDG warning when HOME in vault + clean_env off
# ---------------------------------------------------------------------------


class TestRunGuideHomeInVaultXdg:
    def _setup_project(self, tmp_path, monkeypatch, **files):
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        for name, content in files.items():
            p = project_dir / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        config_dir = tmp_path / "config"
        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)
        return project_dir, config_dir

    def test_warns_and_enables_clean_env(self, tmp_path, monkeypatch, capsys):
        """HOME in vault + clean_env=false + host XDG vars → warn + enable clean_env."""
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "project_wrap.guide.init_vault", lambda *a, **kw: True
        )
        monkeypatch.setattr(
            "project_wrap.guide.find_host_xdg_vars",
            lambda: ["XDG_CONFIG_HOME", "XDG_DATA_HOME"],
        )

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                True,   # sandbox
                False,  # network
                False,  # clean env (initially off)
                True,   # vault
                False,  # shared vault
                True,   # HOME in vault
                True,   # enable clean_env for XDG (NEW)
            ],
            multi_selects=[
                set(),  # vault contents
                set(),  # whitelist
            ],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        captured = capsys.readouterr().out
        assert "XDG vars set" in captured
        assert "clean_env enabled" in captured

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert cfg["sandbox"]["clean_env"] is True
        assert "HOME" in cfg["env"]
        validate_config(cfg)

    def test_warns_but_user_declines_clean_env(self, tmp_path, monkeypatch, capsys):
        """HOME in vault + clean_env=false + host XDG vars → warn, user says no."""
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "project_wrap.guide.init_vault", lambda *a, **kw: True
        )
        monkeypatch.setattr(
            "project_wrap.guide.find_host_xdg_vars",
            lambda: ["XDG_CONFIG_HOME"],
        )

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                True,   # sandbox
                False,  # network
                False,  # clean env
                True,   # vault
                False,  # shared vault
                True,   # HOME in vault
                False,  # enable clean_env? (user says no)
            ],
            multi_selects=[
                set(),  # vault contents
                set(),  # whitelist
            ],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        captured = capsys.readouterr().out
        assert "XDG vars set" in captured

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        # clean_env stays false
        assert cfg["sandbox"]["clean_env"] is False
        assert "HOME" in cfg["env"]
        validate_config(cfg)

    def test_no_warning_when_clean_env_already_on(self, tmp_path, monkeypatch, capsys):
        """HOME in vault + clean_env=true → no XDG warning, no extra question."""
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "project_wrap.guide.init_vault", lambda *a, **kw: True
        )
        # Even if host has XDG vars, no warning because clean_env is on
        monkeypatch.setattr(
            "project_wrap.guide.find_host_xdg_vars",
            lambda: ["XDG_CONFIG_HOME"],
        )

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                True,   # sandbox
                False,  # network
                True,   # clean env (already on)
                True,   # vault
                False,  # shared vault
                True,   # HOME in vault
                # No XDG question — clean_env is already true
            ],
            multi_selects=[
                set(),  # vault contents
                set(),  # whitelist
            ],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        captured = capsys.readouterr().out
        assert "XDG vars set" not in captured

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert cfg["sandbox"]["clean_env"] is True
        validate_config(cfg)

    def test_no_warning_when_no_host_xdg_vars(self, tmp_path, monkeypatch, capsys):
        """HOME in vault + clean_env=false + no host XDG vars → no warning."""
        project_dir, config_dir = self._setup_project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "project_wrap.guide.init_vault", lambda *a, **kw: True
        )
        monkeypatch.setattr(
            "project_wrap.guide.find_host_xdg_vars",
            lambda: [],
        )

        prompter = ScriptedPrompter(
            answers=["myproject", "/bin/bash"],
            confirms=[
                True,   # sandbox
                False,  # network
                False,  # clean env
                True,   # vault
                False,  # shared vault
                True,   # HOME in vault
                # No XDG question — no host XDG vars
            ],
            multi_selects=[
                set(),  # vault contents
                set(),  # whitelist
            ],
        )

        result = run_guide(str(project_dir), prompter=prompter)

        captured = capsys.readouterr().out
        assert "XDG vars set" not in captured

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert cfg["sandbox"]["clean_env"] is False
        validate_config(cfg)
