"""Tests for scaffold module (template management and project creation)."""

import os
import tomllib
from pathlib import Path

import pytest
from project_wrap.scaffold import create_project, ensure_templates
from project_wrap.validate import check_config_permissions, validate_config


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

    def test_sets_secure_perms_under_permissive_umask(self, tmp_path, monkeypatch):
        config_dir = tmp_path / "config"
        project_dir = tmp_path / "work"
        project_dir.mkdir()

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        old_umask = os.umask(0o002)
        try:
            result = create_project(str(project_dir), name="myproj", shell="/usr/bin/fish")
        finally:
            os.umask(old_umask)

        assert result.stat().st_mode & 0o777 == 0o700
        assert (result / "project.toml").stat().st_mode & 0o777 == 0o600
        assert (result / "init.fish").stat().st_mode & 0o777 == 0o600

        # And the result must pass the permission check it triggered.
        check_config_permissions(result / "project.toml")


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
