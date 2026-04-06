"""Tests for CLI module."""

import pytest
from project_wrap.cli import main


class TestCLI:
    """Tests for CLI argument parsing and dispatch."""

    def test_help_flag(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "pwrap" in captured.out
        assert "--check-deps" in captured.out

    def test_list_flag(self, tmp_path, monkeypatch, capsys):
        config_dir = tmp_path / "project"
        config_dir.mkdir()

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        result = main(["--list"])

        assert result == 0
        captured = capsys.readouterr()
        assert "Projects:" in captured.out

    def test_check_deps(self, capsys, monkeypatch):
        # Mock all deps as available
        monkeypatch.setattr("shutil.which", lambda x: f"/usr/bin/{x}")

        result = main(["--check-deps"])

        assert result == 0
        captured = capsys.readouterr()
        assert "bubblewrap" in captured.out

    def test_unknown_project(self, tmp_path, monkeypatch, capsys):
        config_dir = tmp_path / "project"
        config_dir.mkdir()

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        result = main(["nonexistent"])

        assert result == 1
        assert "Unknown project" in capsys.readouterr().err

    def test_new_first_run_creates_templates(self, tmp_path, monkeypatch, capsys):
        config_dir = tmp_path / "config"
        project_dir = tmp_path / "work"
        project_dir.mkdir()

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        result = main(["--new", str(project_dir), "myproj"])

        assert result == 0
        assert (config_dir / "project.tpl.toml").exists()
        captured = capsys.readouterr().out
        assert "Templates created" in captured
        assert "run pwrap --new again" in captured
        # Project should NOT be created yet
        assert not (config_dir / "myproj").exists()

    def test_new_project(self, tmp_path, monkeypatch, capsys):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        project_dir = tmp_path / "work"
        project_dir.mkdir()

        # Pre-create templates so it doesn't pause
        (config_dir / "project.tpl.toml").write_text(
            '[project]\nname = "{name}"\ndir = "{dir}"\nshell = "{shell}"\n'
            "\n[sandbox]\nenabled = {sandbox_enabled}\n"
        )
        (config_dir / "init.tpl.fish").write_text("# fish")
        (config_dir / "init.tpl.sh").write_text("# sh")

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        result = main(["--new", str(project_dir), "myproj"])

        assert result == 0
        assert (config_dir / "myproj" / "project.toml").exists()
        assert "Created" in capsys.readouterr().out

    def test_writeback_outside_sandbox(self, capsys):
        result = main(["--writeback"])

        assert result == 1
        assert "Not in a writeback" in capsys.readouterr().err

    def test_new_without_name_uses_dir_basename(self, tmp_path, monkeypatch, capsys):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        project_dir = tmp_path / "myproj"
        project_dir.mkdir()

        (config_dir / "project.tpl.toml").write_text(
            '[project]\nname = "{name}"\ndir = "{dir}"\nshell = "{shell}"\n'
            "\n[sandbox]\nenabled = {sandbox_enabled}\n"
        )
        (config_dir / "init.tpl.fish").write_text("# fish")
        (config_dir / "init.tpl.sh").write_text("# sh")

        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_dir)

        result = main(["--new", str(project_dir)])

        assert result == 0
        assert (config_dir / "myproj" / "project.toml").exists()
        assert "Created" in capsys.readouterr().out
