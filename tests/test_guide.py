"""Tests for guide module (guided setup wizard)."""

import tomllib

import pytest

from project_wrap.guide import (
    ScriptedPrompter,
    detect_features,
    find_docker_socket,
    find_whitelist_candidates,
    generate_config_toml,
    generate_init_script,
    run_guide,
)
from project_wrap.validate import validate_config

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
                False,  # docker
                False,  # network
                True,   # clean env
                True,   # vault
                True,   # shared vault
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
