"""Tests for core module."""

import os
import shlex
from pathlib import Path

import pytest
import tomllib

from project_wrap.core import (
    build_bwrap_args,
    build_shell_argv,
    check_config_permissions,
    create_project,
    ensure_templates,
    expand_path,
    get_config_dir,
    get_init_script,
    load_config,
    prepare_project,
    redact_bwrap_args,
    validate_config,
    validate_project_name,
    validate_shell,
)


class TestExpandPath:
    """Tests for path expansion."""

    def test_expands_tilde(self):
        result = expand_path("~/projects")
        assert result == Path.home() / "projects"

    def test_expands_env_vars(self, monkeypatch):
        monkeypatch.setenv("MY_VAR", "/custom/path")
        result = expand_path("$MY_VAR/subdir")
        assert result == Path("/custom/path/subdir")


class TestGetConfigDir:
    """Tests for config directory resolution."""

    def test_default_config_dir(self, monkeypatch):
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        result = get_config_dir()
        assert result == Path.home() / ".config" / "pwrap"

    def test_xdg_config_dir(self, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", "/custom/config")
        result = get_config_dir()
        assert result == Path("/custom/config/pwrap")


class TestLoadConfig:
    """Tests for config loading."""

    def test_load_directory_config(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "project"
        project_dir = config_dir / "myproject"
        project_dir.mkdir(parents=True)

        config_file = project_dir / "project.toml"
        config_file.write_text("""
[project]
name = "My Project"
dir = "~/projects/myproject"

[sandbox]
enabled = true
""")

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        result = load_config("myproject")

        assert result["project"]["name"] == "My Project"
        assert result["sandbox"]["enabled"] is True

    def test_load_unknown_project(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "project"
        config_dir.mkdir()

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        with pytest.raises(SystemExit, match="Unknown project"):
            load_config("nonexistent")

    def test_load_missing_toml(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "project"
        project_dir = config_dir / "myproject"
        project_dir.mkdir(parents=True)

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        with pytest.raises(SystemExit, match="Missing config"):
            load_config("myproject")


class TestBuildBwrapArgs:
    """Tests for bubblewrap argument building."""

    def test_basic_args(self, tmp_path):
        result = build_bwrap_args({}, tmp_path)

        assert result[0] == "bwrap"
        assert "--ro-bind" in result
        assert "--dev" in result
        assert "--proc" in result

    def test_home_readonly_project_writable(self, tmp_path):
        result = build_bwrap_args({}, tmp_path)
        home = str(Path.home())

        # Home should be ro-bind: --ro-bind <home> <home>
        home_idx = result.index(home)
        assert result[home_idx - 1] == "--ro-bind"
        assert result[home_idx + 1] == home

        # Project dir should be writable bind: --bind <proj> <proj>
        proj_str = str(tmp_path)
        proj_idx = result.index(proj_str, home_idx + 1)
        assert result[proj_idx - 1] == "--bind"
        assert result[proj_idx + 1] == proj_str

    def test_hardening_flags(self, tmp_path):
        result = build_bwrap_args({}, tmp_path)

        assert "--die-with-parent" in result
        assert "--unshare-ipc" in result

    def test_new_session_explicit_true(self, tmp_path):
        result = build_bwrap_args({"new_session": True}, tmp_path)
        assert "--new-session" in result

    def test_new_session_explicit_false(self, tmp_path, monkeypatch):
        monkeypatch.setattr("project_wrap.core.tiocsti_vulnerable", lambda: False)
        result = build_bwrap_args({"new_session": False}, tmp_path)
        assert "--new-session" not in result

    def test_new_session_auto_on_vulnerable(self, tmp_path, monkeypatch):
        monkeypatch.setattr("project_wrap.core.tiocsti_vulnerable", lambda: True)
        result = build_bwrap_args({}, tmp_path)
        assert "--new-session" in result

    def test_new_session_auto_off_safe_kernel(self, tmp_path, monkeypatch):
        monkeypatch.setattr("project_wrap.core.tiocsti_vulnerable", lambda: False)
        result = build_bwrap_args({}, tmp_path)
        assert "--new-session" not in result

    def test_new_session_false_vulnerable_warns(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr("project_wrap.core.tiocsti_vulnerable", lambda: True)
        build_bwrap_args({"new_session": False}, tmp_path)
        assert "TIOCSTI" in capsys.readouterr().err

    def test_runtime_dir_isolated(self, tmp_path):
        result = build_bwrap_args({}, tmp_path)
        uid = os.getuid()
        runtime_dir = f"/run/user/{uid}"
        idx = result.index(runtime_dir)
        assert result[idx - 1] == "--tmpfs"

    def test_blacklist_args(self, tmp_path):
        blacklist_dir = tmp_path / "secret"
        blacklist_dir.mkdir()

        result = build_bwrap_args(
            {"blacklist": [str(blacklist_dir)]},
            tmp_path,
        )

        idx = result.index(str(blacklist_dir))
        assert result[idx - 1] == "--tmpfs"

    def test_blacklist_nonexistent_path_raises(self, tmp_path):
        nonexistent = tmp_path / "does_not_exist"

        with pytest.raises(SystemExit, match="Blacklist path does not exist"):
            build_bwrap_args(
                {"blacklist": [str(nonexistent)]},
                tmp_path,
            )

    def test_whitelist_under_blacklist_ok(self, tmp_path):
        parent = tmp_path / "parent"
        parent.mkdir()
        child = parent / "child"
        child.mkdir()

        result = build_bwrap_args(
            {"blacklist": [str(parent)], "whitelist": [str(child)]},
            tmp_path,
        )

        idx = result.index(str(child))
        assert result[idx - 1] == "--bind"
        assert result[idx + 1] == str(child)

    def test_whitelist_not_under_blacklist_raises(self, tmp_path):
        orphan = tmp_path / "orphan"
        orphan.mkdir()

        with pytest.raises(SystemExit, match="not under any blacklisted path"):
            build_bwrap_args(
                {"whitelist": [str(orphan)]},
                tmp_path,
            )

    def test_whitelist_with_no_blacklist_raises(self, tmp_path):
        some_dir = tmp_path / "somedir"
        some_dir.mkdir()

        with pytest.raises(SystemExit, match="not under any blacklisted path"):
            build_bwrap_args(
                {"whitelist": [str(some_dir)]},
                tmp_path,
            )

    def test_project_wrap_env_always_set(self, tmp_path):
        result = build_bwrap_args({}, tmp_path)

        idx = result.index("PROJECT_WRAP")
        assert result[idx - 1] == "--setenv"
        assert result[idx + 1] == "1"

    def test_blacklist_symlink_resolves(self, tmp_path):
        target = tmp_path / "real_dir"
        target.mkdir()
        link = tmp_path / "link"
        link.symlink_to(target)

        result = build_bwrap_args(
            {"blacklist": [str(link)]},
            tmp_path,
        )

        # Should use resolved path, not the symlink
        assert str(target) in result
        idx = result.index(str(target))
        assert result[idx - 1] == "--tmpfs"

    def test_writable_paths(self, tmp_path):
        writable_dir = tmp_path / "shims"
        writable_dir.mkdir()

        result = build_bwrap_args(
            {"writable": [str(writable_dir)]},
            tmp_path,
        )

        resolved = str(writable_dir.resolve())
        idx = result.index(resolved)
        assert result[idx - 1] == "--bind"
        assert result[idx + 1] == resolved

    def test_writable_nonexistent_raises(self, tmp_path):
        with pytest.raises(SystemExit, match="Writable path does not exist"):
            build_bwrap_args(
                {"writable": [str(tmp_path / "nope")]},
                tmp_path,
            )

    def test_writable_resolves_symlinks(self, tmp_path):
        target = tmp_path / "real"
        target.mkdir()
        link = tmp_path / "link"
        link.symlink_to(target)

        result = build_bwrap_args(
            {"writable": [str(link)]},
            tmp_path,
        )

        resolved = str(target.resolve())
        idx = result.index(resolved)
        assert result[idx - 1] == "--bind"

    def test_unshare_net(self, tmp_path):
        result = build_bwrap_args(
            {"unshare_net": True},
            tmp_path,
        )

        assert "--unshare-net" in result

    def test_unshare_pid_default_true(self, tmp_path):
        result = build_bwrap_args({}, tmp_path)
        assert "--unshare-pid" in result

    def test_unshare_pid_opt_out(self, tmp_path):
        result = build_bwrap_args({"unshare_pid": False}, tmp_path)
        assert "--unshare-pid" not in result

    def test_init_script_bind_mounted(self, tmp_path):
        init_file = tmp_path / "init.fish"
        init_file.write_text("# init")

        result = build_bwrap_args({}, tmp_path, init_script=init_file)

        idx = result.index(str(init_file))
        assert result[idx - 1] == "--ro-bind"
        assert result[idx + 1] == str(init_file)

    def test_no_init_script(self, tmp_path):
        result = build_bwrap_args({}, tmp_path, init_script=None)
        # Should not contain any ro-bind for init scripts
        # (only the root and home ro-binds)
        ro_bind_count = result.count("--ro-bind")
        assert ro_bind_count == 2  # root + home


class TestGetInitScript:
    """Tests for init script discovery."""

    def test_finds_shell_specific(self, tmp_path):
        (tmp_path / "init.fish").write_text("# fish init")

        result = get_init_script(tmp_path, "/usr/bin/fish")

        assert result == tmp_path / "init.fish"

    def test_falls_back_to_sh(self, tmp_path):
        (tmp_path / "init.sh").write_text("# bash init")

        result = get_init_script(tmp_path, "/bin/bash")

        assert result == tmp_path / "init.sh"

    def test_returns_none_if_missing(self, tmp_path):
        result = get_init_script(tmp_path, "/bin/bash")
        assert result is None


class TestBuildShellArgv:
    """Tests for shell argv building."""

    def test_fish_uses_init_command(self, tmp_path):
        result = build_shell_argv(
            project_dir=tmp_path / "project",
            config_dir=tmp_path / "config",
            shell="/usr/bin/fish",
        )

        assert result[0] == "/usr/bin/fish"
        assert result[1] == "--init-command"
        assert f"cd {shlex.quote(str(tmp_path / 'project'))}" in result[2]

    def test_bash_uses_exec_fallback(self, tmp_path):
        result = build_shell_argv(
            project_dir=tmp_path / "project",
            config_dir=tmp_path / "config",
            shell="/bin/bash",
        )

        assert result[0] == "/bin/bash"
        assert result[1] == "-c"
        assert "exec" in result[2]
        assert f"cd {shlex.quote(str(tmp_path / 'project'))}" in result[2]

    def test_zsh_uses_exec_fallback(self, tmp_path):
        result = build_shell_argv(
            project_dir=tmp_path / "project",
            config_dir=tmp_path / "config",
            shell="/bin/zsh",
        )

        assert result[0] == "/bin/zsh"
        assert result[1] == "-c"
        assert "exec" in result[2]

    def test_includes_init_script(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "init.fish").write_text("# custom init")

        result = build_shell_argv(
            project_dir=tmp_path / "project",
            config_dir=config_dir,
            shell="/usr/bin/fish",
        )

        assert "init.fish" in result[2]

    def test_paths_with_spaces_quoted(self, tmp_path):
        project_dir = tmp_path / "my project"
        project_dir.mkdir()

        result = build_shell_argv(
            project_dir=project_dir,
            config_dir=tmp_path / "config",
            shell="/usr/bin/fish",
        )

        assert shlex.quote(str(project_dir)) in result[2]


class TestValidateProjectName:
    """Tests for project name validation."""

    def test_rejects_empty_name(self):
        with pytest.raises(SystemExit, match="cannot be empty"):
            validate_project_name("")

    def test_rejects_whitespace_only(self):
        with pytest.raises(SystemExit, match="cannot be empty"):
            validate_project_name("   ")

    def test_rejects_slash(self):
        with pytest.raises(SystemExit, match="contains '/'"):
            validate_project_name("foo/bar")

    def test_rejects_dotdot(self):
        with pytest.raises(SystemExit, match="contains '..'"):
            validate_project_name("..")

    def test_rejects_dotdot_traversal(self):
        with pytest.raises(SystemExit, match="contains '..'"):
            validate_project_name("..secret")

    def test_rejects_null_byte(self):
        with pytest.raises(SystemExit, match="null byte"):
            validate_project_name("foo\x00bar")

    def test_rejects_leading_dash(self):
        with pytest.raises(SystemExit, match="starts with '-'"):
            validate_project_name("-verbose")

    def test_accepts_valid_name(self):
        validate_project_name("my-project")  # Should not raise

    def test_rejects_single_dot(self):
        with pytest.raises(SystemExit, match="'.'"):
            validate_project_name(".")

    def test_accepts_dotfile_name(self):
        validate_project_name(".myproject")  # Single dot is fine

    def test_load_config_validates_name(self, tmp_path, monkeypatch):
        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: tmp_path)
        with pytest.raises(SystemExit, match="contains '/'"):
            load_config("../../etc")


class TestCheckConfigPermissions:
    """Tests for config file permission checking."""

    def test_rejects_world_writable(self, tmp_path):
        config = tmp_path / "project.toml"
        config.write_text("[project]\n")
        config.chmod(0o666)

        with pytest.raises(SystemExit, match="world-writable"):
            check_config_permissions(config)

    def test_rejects_group_writable(self, tmp_path):
        config = tmp_path / "project.toml"
        config.write_text("[project]\n")
        config.chmod(0o664)

        with pytest.raises(SystemExit, match="group-writable"):
            check_config_permissions(config)

    def test_accepts_secure_permissions(self, tmp_path):
        config = tmp_path / "project.toml"
        config.write_text("[project]\n")
        config.chmod(0o600)

        check_config_permissions(config)  # Should not raise

    def test_accepts_owner_read_only(self, tmp_path):
        config = tmp_path / "project.toml"
        config.write_text("[project]\n")
        config.chmod(0o644)

        check_config_permissions(config)  # Should not raise


class TestValidateConfig:
    """Tests for config schema validation."""

    def test_rejects_unknown_top_level_key(self):
        with pytest.raises(SystemExit, match="Unknown config sections"):
            validate_config({"sandox": {"enabled": True}})

    def test_rejects_unknown_sandbox_key(self):
        with pytest.raises(SystemExit, match="unknown keys.*enbled"):
            validate_config({"sandbox": {"enbled": True}})

    def test_rejects_wrong_type(self):
        with pytest.raises(SystemExit, match="expected bool, got str"):
            validate_config({"sandbox": {"enabled": "true"}})

    def test_rejects_blacklist_non_string_items(self):
        with pytest.raises(SystemExit, match="all items must be strings"):
            validate_config({"sandbox": {"blacklist": [1, 2]}})

    def test_rejects_non_table_section(self):
        with pytest.raises(SystemExit, match="must be a table"):
            validate_config({"project": "not a table"})

    def test_accepts_valid_full_config(self):
        validate_config({
            "project": {"name": "test", "dir": "~/test", "shell": "/bin/bash"},
            "sandbox": {"enabled": True, "blacklist": ["~/.aws"], "whitelist": []},
            "encrypted": {
                "cipherdir": "encrypted",
                "mountpoint": "~/.local/share/myapp",
                "shared": False,
            },
        })

    def test_accepts_empty_config(self):
        validate_config({})

    def test_accepts_partial_sections(self):
        validate_config({"project": {"name": "test"}})

    def test_ignores_internal_keys(self):
        validate_config({"_config_dir": "/some/path", "project": {"name": "test"}})

    def test_integration_load_config_validates(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "project"
        project_dir = config_dir / "myproject"
        project_dir.mkdir(parents=True)
        config_file = project_dir / "project.toml"
        config_file.write_text('[sandox]\nenabled = true\n')

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        with pytest.raises(SystemExit, match="Unknown config sections"):
            load_config("myproject")


class TestRedactBwrapArgs:
    """Tests for bwrap argument redaction."""

    def test_redacts_setenv_value(self):
        args = ["bwrap", "--setenv", "SECRET", "supersecret123"]
        result = redact_bwrap_args(args)

        assert result[2] == "SECRET"
        assert result[3] == "***"

    def test_redacts_multiple_setenv(self):
        args = ["bwrap", "--setenv", "A", "val1", "--setenv", "B", "val2"]
        result = redact_bwrap_args(args)

        assert result[3] == "***"
        assert result[6] == "***"
        assert result[2] == "A"
        assert result[5] == "B"

    def test_preserves_non_setenv_args(self):
        args = ["bwrap", "--bind", "/src", "/dst", "--tmpfs", "/tmp"]
        result = redact_bwrap_args(args)
        assert result == args

    def test_does_not_mutate_original(self):
        args = ["bwrap", "--setenv", "KEY", "secret"]
        redact_bwrap_args(args)
        assert args[3] == "secret"

    def test_handles_trailing_setenv(self):
        args = ["bwrap", "--setenv", "KEY"]
        result = redact_bwrap_args(args)
        assert result == ["bwrap", "--setenv", "KEY"]


class TestBlacklistErrors:
    """Tests for blacklist path validation."""

    def test_rejects_nonexistent_blacklist(self, tmp_path):
        nonexistent = tmp_path / "does_not_exist"

        with pytest.raises(SystemExit, match="Blacklist path does not exist"):
            build_bwrap_args(
                {"blacklist": [str(nonexistent)]},
                tmp_path,
            )

    def test_accepts_existing_blacklist(self, tmp_path):
        existing = tmp_path / "existing"
        existing.mkdir()

        result = build_bwrap_args(
            {"blacklist": [str(existing)]},
            {},
            tmp_path,
        )

        assert str(existing) in result


class TestValidateShell:
    """Tests for shell validation."""

    def test_rejects_relative_path(self):
        with pytest.raises(SystemExit, match="absolute path"):
            validate_shell("bash")

    def test_rejects_nonexistent_shell(self, tmp_path):
        with pytest.raises(SystemExit, match="does not exist"):
            validate_shell(str(tmp_path / "noshell"))

    def test_rejects_shell_not_in_etc_shells(self, tmp_path, monkeypatch):
        fake_shell = tmp_path / "fakeshell"
        fake_shell.write_text("#!/bin/sh")
        fake_shell.chmod(0o755)

        fake_etc_shells = tmp_path / "shells"
        fake_etc_shells.write_text("/bin/bash\n/bin/sh\n")
        monkeypatch.setattr("project_wrap.validate.ETC_SHELLS", fake_etc_shells)

        with pytest.raises(SystemExit, match="not in /etc/shells"):
            validate_shell(str(fake_shell))

    def test_accepts_valid_shell(self, tmp_path, monkeypatch):
        fake_shell = tmp_path / "goodshell"
        fake_shell.write_text("#!/bin/sh")
        fake_shell.chmod(0o755)

        fake_etc_shells = tmp_path / "shells"
        fake_etc_shells.write_text(f"{fake_shell}\n/bin/bash\n")
        monkeypatch.setattr("project_wrap.validate.ETC_SHELLS", fake_etc_shells)

        validate_shell(str(fake_shell))  # Should not raise


class TestWhitelistSymlinkResolution:
    """Tests for symlink resolution in whitelist containment check."""

    def test_rejects_symlink_escaping_blacklist(self, tmp_path):
        parent = tmp_path / "parent"
        parent.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        sneaky = parent / "sneaky"
        sneaky.symlink_to(outside)

        with pytest.raises(SystemExit, match="not under any blacklisted path"):
            build_bwrap_args(
                {"blacklist": [str(parent)], "whitelist": [str(sneaky)]},
                tmp_path,
            )


def _make_project_config(tmp_path, monkeypatch, toml_content, project_name="testproj"):
    """Helper to set up a project config dir for prepare_project tests."""
    config_dir = tmp_path / "config"
    project_conf_dir = config_dir / project_name
    project_conf_dir.mkdir(parents=True)
    config_file = project_conf_dir / "project.toml"
    config_file.write_text(toml_content)

    monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)
    monkeypatch.setattr("project_wrap.core.rename_tmux_window", lambda n: None)
    monkeypatch.delenv("TMUX", raising=False)

    return config_dir, project_conf_dir


class TestPrepareProject:
    """Tests for prepare_project."""

    def test_nonsandbox_project(self, tmp_path, monkeypatch):
        project_dir = tmp_path / "work"
        project_dir.mkdir()

        fake_shell = tmp_path / "shell"
        fake_shell.write_text("#!/bin/sh")
        fake_shell.chmod(0o755)

        fake_etc = tmp_path / "shells"
        fake_etc.write_text(f"{fake_shell}\n")
        monkeypatch.setattr("project_wrap.validate.ETC_SHELLS", fake_etc)

        _make_project_config(tmp_path, monkeypatch, f"""
[project]
name = "My Work"
dir = "{project_dir}"
shell = "{fake_shell}"
""")

        result = prepare_project("testproj")

        assert not result.is_sandboxed
        assert result.display_name == "My Work"
        assert result.program == str(fake_shell)

    def test_sandbox_project(self, tmp_path, monkeypatch):
        project_dir = tmp_path / "work"
        project_dir.mkdir()

        fake_shell = tmp_path / "shell"
        fake_shell.write_text("#!/bin/sh")
        fake_shell.chmod(0o755)

        fake_etc = tmp_path / "shells"
        fake_etc.write_text(f"{fake_shell}\n")
        monkeypatch.setattr("project_wrap.validate.ETC_SHELLS", fake_etc)
        monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/bwrap")

        _make_project_config(tmp_path, monkeypatch, f"""
[project]
name = "Sandboxed"
dir = "{project_dir}"
shell = "{fake_shell}"

[sandbox]
enabled = true
""")

        result = prepare_project("testproj")

        assert result.is_sandboxed
        assert result.program == "bwrap"
        assert result.display_name == "Sandboxed"

    def test_missing_project_dir_raises(self, tmp_path, monkeypatch):
        fake_shell = tmp_path / "shell"
        fake_shell.write_text("#!/bin/sh")
        fake_shell.chmod(0o755)

        fake_etc = tmp_path / "shells"
        fake_etc.write_text(f"{fake_shell}\n")
        monkeypatch.setattr("project_wrap.validate.ETC_SHELLS", fake_etc)

        _make_project_config(tmp_path, monkeypatch, f"""
[project]
dir = "{tmp_path / 'nonexistent'}"
shell = "{fake_shell}"
""")

        with pytest.raises(SystemExit, match="Project directory does not exist"):
            prepare_project("testproj")

class TestCreateProject:
    """Tests for create_project."""

    def test_creates_config(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "config"
        project_dir = tmp_path / "work"
        project_dir.mkdir()

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        result = create_project(str(project_dir), name="myproj")

        assert result == config_dir / "myproj"
        config_file = result / "project.toml"
        assert config_file.exists()

        with open(config_file, "rb") as f:
            cfg = tomllib.load(f)
        assert cfg["project"]["name"] == "myproj"
        assert cfg["project"]["dir"] == str(project_dir.resolve())
        assert cfg["sandbox"]["enabled"] is True

    def test_creates_fish_init_for_fish_shell(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "config"
        project_dir = tmp_path / "work"
        project_dir.mkdir()

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        result = create_project(str(project_dir), name="myproj", shell="/usr/bin/fish")

        assert (result / "init.fish").exists()
        assert not (result / "init.sh").exists()

    def test_creates_sh_init_for_bash_shell(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "config"
        project_dir = tmp_path / "work"
        project_dir.mkdir()

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        result = create_project(str(project_dir), name="myproj", shell="/bin/bash")

        assert (result / "init.sh").exists()
        assert not (result / "init.fish").exists()

    def test_config_contains_shell(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "config"
        project_dir = tmp_path / "work"
        project_dir.mkdir()

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        result = create_project(str(project_dir), name="myproj", shell="/usr/bin/fish")

        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert cfg["project"]["shell"] == "/usr/bin/fish"

    def test_name_defaults_to_dir_basename(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "config"
        project_dir = tmp_path / "myproj"
        project_dir.mkdir()

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        result = create_project(str(project_dir))

        assert result == config_dir / "myproj"
        with open(result / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert cfg["project"]["name"] == "myproj"

    def test_roundtrips_through_validation(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "config"
        project_dir = tmp_path / "work"
        project_dir.mkdir()

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        create_project(str(project_dir), name="myproj")

        with open(config_dir / "myproj" / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        validate_config(cfg)  # Should not raise

    def test_no_sandbox(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "config"
        project_dir = tmp_path / "work"
        project_dir.mkdir()

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        create_project(str(project_dir), name="myproj", sandbox=False)

        with open(config_dir / "myproj" / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        assert cfg["sandbox"]["enabled"] is False

    def test_fails_if_exists(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "config"
        existing = config_dir / "myproj"
        existing.mkdir(parents=True)

        project_dir = tmp_path / "work"
        project_dir.mkdir()

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        with pytest.raises(SystemExit, match="Project already exists"):
            create_project(str(project_dir), name="myproj")

    def test_stores_absolute_path(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "config"
        project_dir = tmp_path / "work"
        project_dir.mkdir()

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        create_project(str(project_dir), name="myproj")

        with open(config_dir / "myproj" / "project.toml", "rb") as f:
            cfg = tomllib.load(f)
        stored = cfg["project"]["dir"]
        assert Path(stored).is_absolute()
        assert stored == str(project_dir.resolve())

    def test_fails_if_project_dir_missing(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "config"
        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        with pytest.raises(SystemExit, match="Project directory does not exist"):
            create_project(str(tmp_path / "nonexistent"), name="myproj")


class TestBwrapRoBindExtra:
    """Tests for ro_bind_extra parameter in build_bwrap_args."""

    def test_ro_binds_extra_paths(self, tmp_path):
        extra1 = tmp_path / "archive.age"
        extra1.write_text("encrypted")
        extra2 = tmp_path / "key.txt"
        extra2.write_text("identity")

        result = build_bwrap_args({}, tmp_path, ro_bind_extra=[extra1, extra2])

        idx1 = result.index(str(extra1))
        assert result[idx1 - 1] == "--ro-bind"
        assert result[idx1 + 1] == str(extra1)

        idx2 = result.index(str(extra2))
        assert result[idx2 - 1] == "--ro-bind"

    def test_no_extra_paths(self, tmp_path):
        result = build_bwrap_args({}, tmp_path, ro_bind_extra=None)
        ro_bind_count = result.count("--ro-bind")
        assert ro_bind_count == 2  # root + home only


class TestEncrypted:
    """Tests for gocryptfs encrypted volume config."""

    def test_encrypted_without_sandbox_raises(self, tmp_path, monkeypatch):
        project_dir = tmp_path / "work"
        project_dir.mkdir()

        fake_shell = tmp_path / "shell"
        fake_shell.write_text("#!/bin/sh")
        fake_shell.chmod(0o755)

        fake_etc = tmp_path / "shells"
        fake_etc.write_text(f"{fake_shell}\n")
        monkeypatch.setattr("project_wrap.validate.ETC_SHELLS", fake_etc)

        _, conf_dir = _make_project_config(tmp_path, monkeypatch, f"""
[project]
dir = "{project_dir}"
shell = "{fake_shell}"

[encrypted]
cipherdir = "{tmp_path / 'cipherdir'}"
mountpoint = "/tmp/decrypted"
""")
        (tmp_path / "cipherdir").mkdir()

        with pytest.raises(SystemExit, match="requires sandbox to be enabled"):
            prepare_project("testproj")

    def test_encrypted_missing_cipherdir_raises(self, tmp_path, monkeypatch):
        project_dir = tmp_path / "work"
        project_dir.mkdir()

        fake_shell = tmp_path / "shell"
        fake_shell.write_text("#!/bin/sh")
        fake_shell.chmod(0o755)

        fake_etc = tmp_path / "shells"
        fake_etc.write_text(f"{fake_shell}\n")
        monkeypatch.setattr("project_wrap.validate.ETC_SHELLS", fake_etc)
        monkeypatch.setattr("shutil.which", lambda x: f"/usr/bin/{x}")

        _make_project_config(tmp_path, monkeypatch, f"""
[project]
dir = "{project_dir}"
shell = "{fake_shell}"

[sandbox]
enabled = true

[encrypted]
cipherdir = "{tmp_path / 'nonexistent'}"
mountpoint = "/tmp/decrypted"
""")

        with pytest.raises(SystemExit, match="cipherdir does not exist"):
            prepare_project("testproj")

    def test_encrypted_schema_rejects_unknown_key(self):
        with pytest.raises(SystemExit, match="unknown keys"):
            validate_config({"encrypted": {"cipherdir": "x", "bogus": "y"}})

    def test_encrypted_schema_valid(self):
        validate_config({
            "encrypted": {
                "cipherdir": "encrypted",
                "mountpoint": "~/.local/share/myapp",
                "shared": False,
            },
        })

    def test_rw_bind_extra(self, tmp_path):
        extra = tmp_path / "mountpoint"
        extra.mkdir()

        result = build_bwrap_args({}, tmp_path, rw_bind_extra=[extra])

        idx = result.index(str(extra))
        assert result[idx - 1] == "--bind"
        assert result[idx + 1] == str(extra)


class TestEnsureTemplates:
    """Tests for user-editable template management."""

    def test_creates_templates_on_first_run(self, tmp_path, monkeypatch):
        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: tmp_path)

        created = ensure_templates()

        assert created is True
        assert (tmp_path / "project.tpl.toml").exists()
        assert (tmp_path / "init.tpl.fish").exists()
        assert (tmp_path / "init.tpl.sh").exists()

    def test_returns_false_when_templates_exist(self, tmp_path, monkeypatch):
        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: tmp_path)
        (tmp_path / "project.tpl.toml").write_text("[project]")

        created = ensure_templates()

        assert created is False

    def test_create_project_uses_user_template(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        project_dir = tmp_path / "work"
        project_dir.mkdir()

        # Write a custom user template
        (config_dir / "project.tpl.toml").write_text(
            '[project]\nname = "{name}"\ndir = "{dir}"\nshell = "{shell}"\n'
            "\n[sandbox]\nenabled = {sandbox_enabled}\ncustom = true\n"
        )
        (config_dir / "init.tpl.fish").write_text("# my custom fish init")

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        result = create_project(str(project_dir), name="myproj", shell="/usr/bin/fish")

        content = (result / "project.toml").read_text()
        assert "custom = true" in content

        init_content = (result / "init.fish").read_text()
        assert "my custom fish init" in init_content
