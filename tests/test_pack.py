"""Tests for pack/unpack (project transfer between workstations)."""

import io
import json
import tarfile
from pathlib import Path

import pytest

from project_wrap.cli import main
from project_wrap.pack import pack_project, unpack_archive


def make_project(
    config_root: Path,
    name: str,
    project_dir: Path,
    toml_extra: str = "",
    init_name: str = "init.sh",
) -> Path:
    """Create a valid project config dir + project dir on disk."""
    cfg_dir = config_root / name
    cfg_dir.mkdir(parents=True)
    cfg_dir.chmod(0o700)
    toml = (
        f'[project]\nname = "{name}"\ndir = "{project_dir}"\nshell = "/bin/bash"\n'
        f"\n[sandbox]\nenabled = true\n"
        f"{toml_extra}"
    )
    project_toml = cfg_dir / "project.toml"
    project_toml.write_text(toml)
    project_toml.chmod(0o600)
    init = cfg_dir / init_name
    init.write_text("# init\n")
    init.chmod(0o600)
    return cfg_dir


def make_tar(path: Path, members: list[tuple[str, str]]) -> Path:
    """Create a tar.gz with plain file members (name, text content)."""
    with tarfile.open(path, "w:gz") as tar:
        for name, content in members:
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def manifest_member(name: str, project_dir: str) -> tuple[str, str]:
    manifest = {
        "format": "pwrap-pack",
        "version": 1,
        "pwrap_version": "0.0.0",
        "created": "2026-10-27T00:00:00+00:00",
        "project": name,
        "project_dir": project_dir,
        "project_dir_raw": project_dir,
        "has_vault": False,
    }
    return ("pwrap-manifest.json", json.dumps(manifest))


def tar_names(archive: Path) -> list[str]:
    with tarfile.open(archive, "r:gz") as tar:
        return tar.getnames()


def read_member(archive: Path, name: str) -> str:
    with tarfile.open(archive, "r:gz") as tar:
        member = tar.extractfile(name)
        assert member is not None
        return member.read().decode()


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """Config root + project dir, with get_config_dir pointed at the config root."""
    config_root = tmp_path / "config"
    config_root.mkdir()
    project_dir = tmp_path / "work" / "myproj"
    project_dir.mkdir(parents=True)
    monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_root)
    return config_root, project_dir


class TestPack:
    def test_pack_creates_archive(self, workspace, tmp_path):
        config_root, project_dir = workspace
        (project_dir / "src").mkdir()
        (project_dir / "src" / "main.py").write_text("print('hi')\n")
        make_project(config_root, "myproj", project_dir)

        archive = pack_project("myproj", output=str(tmp_path / "out.tar.gz"))

        assert archive == tmp_path / "out.tar.gz"
        names = tar_names(archive)
        assert "pwrap-manifest.json" in names
        assert "config/project.toml" in names
        assert "config/init.sh" in names
        assert "project/src/main.py" in names
        manifest = json.loads(read_member(archive, "pwrap-manifest.json"))
        assert manifest["format"] == "pwrap-pack"
        assert manifest["project"] == "myproj"
        assert manifest["project_dir"] == str(project_dir)
        assert manifest["has_vault"] is False

    def test_pack_default_output_in_cwd(self, workspace, tmp_path, monkeypatch):
        config_root, project_dir = workspace
        make_project(config_root, "myproj", project_dir)
        monkeypatch.chdir(tmp_path)

        archive = pack_project("myproj")

        assert archive == tmp_path / "myproj.pwrap.tar.gz"
        assert archive.exists()

    def test_pack_includes_vault(self, workspace, tmp_path):
        config_root, project_dir = workspace
        cfg_dir = make_project(
            config_root,
            "myproj",
            project_dir,
            toml_extra=(
                '\n[encrypted]\ncipherdir = "encrypted"\n'
                f'mountpoint = "{tmp_path}/mnt"\nshared = false\n'
            ),
        )
        cipherdir = cfg_dir / "encrypted"
        cipherdir.mkdir()
        (cipherdir / "gocryptfs.conf").write_text("{}")

        archive = pack_project("myproj", output=str(tmp_path / "out.tar.gz"))

        names = tar_names(archive)
        assert "vault/gocryptfs.conf" in names
        # The relative cipherdir lives in the config dir — it must be packed
        # as vault/, not as a config file.
        assert "config/encrypted/gocryptfs.conf" not in names
        manifest = json.loads(read_member(archive, "pwrap-manifest.json"))
        assert manifest["has_vault"] is True

    def test_pack_unknown_project(self, workspace, tmp_path):
        with pytest.raises(SystemExit, match="Unknown project"):
            pack_project("nonexistent", output=str(tmp_path / "out.tar.gz"))

    def test_pack_missing_project_dir(self, workspace, tmp_path):
        config_root, _project_dir = workspace
        missing = tmp_path / "does-not-exist"
        make_project(config_root, "myproj", missing)

        with pytest.raises(SystemExit, match="Project directory does not exist"):
            pack_project("myproj", output=str(tmp_path / "out.tar.gz"))

    def test_pack_missing_cipherdir(self, workspace, tmp_path):
        config_root, project_dir = workspace
        make_project(
            config_root,
            "myproj",
            project_dir,
            toml_extra=(
                '\n[encrypted]\ncipherdir = "encrypted"\n'
                f'mountpoint = "{tmp_path}/mnt"\n'
            ),
        )

        with pytest.raises(SystemExit, match="cipherdir does not exist"):
            pack_project("myproj", output=str(tmp_path / "out.tar.gz"))

    def test_pack_refuses_existing_output(self, workspace, tmp_path):
        config_root, project_dir = workspace
        make_project(config_root, "myproj", project_dir)
        existing = tmp_path / "out.tar.gz"
        existing.write_text("occupied")

        with pytest.raises(SystemExit, match="Output file already exists"):
            pack_project("myproj", output=str(existing))

    def test_pack_refuses_output_inside_project_dir(self, workspace):
        config_root, project_dir = workspace
        make_project(config_root, "myproj", project_dir)

        with pytest.raises(SystemExit, match="must not be inside the packed directory"):
            pack_project("myproj", output=str(project_dir / "backup.tar.gz"))

    def test_pack_excludes_mounted_vault_mountpoint(self, workspace, tmp_path, monkeypatch):
        config_root, project_dir = workspace
        mountpoint = project_dir / "vault-mnt"
        mountpoint.mkdir()
        (mountpoint / "secret.txt").write_text("plaintext secret")
        (project_dir / "src").mkdir()
        (project_dir / "src" / "main.py").write_text("print('hi')\n")
        cfg_dir = make_project(
            config_root,
            "myproj",
            project_dir,
            toml_extra=(
                '\n[encrypted]\ncipherdir = "encrypted"\n'
                f'mountpoint = "{mountpoint}"\n'
            ),
        )
        cipherdir = cfg_dir / "encrypted"
        cipherdir.mkdir()
        (cipherdir / "gocryptfs.conf").write_text("{}")
        monkeypatch.setattr(
            "os.path.ismount", lambda p: str(p) == str(mountpoint)
        )

        archive = pack_project("myproj", output=str(tmp_path / "out.tar.gz"))

        names = tar_names(archive)
        assert "project/vault-mnt/secret.txt" not in names
        assert "project/src/main.py" in names
        assert "vault/gocryptfs.conf" in names

    def test_pack_warns_on_env_secrets(self, workspace, tmp_path, capsys):
        config_root, project_dir = workspace
        make_project(
            config_root,
            "myproj",
            project_dir,
            toml_extra='\n[env]\nAPI_KEY = "s3cr3t"\n',
        )

        pack_project("myproj", output=str(tmp_path / "out.tar.gz"))

        assert "plaintext" in capsys.readouterr().err


class TestUnpack:
    def _packed_project(self, workspace, tmp_path, toml_extra: str = ""):
        """Create + pack a project; returns (archive, project_dir, cfg_dir)."""
        config_root, project_dir = workspace
        cfg_dir = make_project(config_root, "myproj", project_dir, toml_extra=toml_extra)
        (project_dir / "src").mkdir()
        (project_dir / "src" / "main.py").write_text("print('hi')\n")
        archive = tmp_path / "myproj.pwrap.tar.gz"
        pack_project("myproj", output=str(archive))
        return archive, project_dir, cfg_dir

    def test_unpack_roundtrip(self, workspace, tmp_path, monkeypatch, capsys):
        config_root, project_dir = workspace
        outside = tmp_path / "outside"
        outside.mkdir()
        toml_extra = (
            "blacklist = [\n"
            f'    "{project_dir}/node_modules",\n'
            f'    "{outside}",\n'
            "]\n"
            '\n[env]\n'
            f'HOME = "{project_dir}/.home"\n'
            '\n[encrypted]\n'
            'cipherdir = "encrypted"\n'
            f'mountpoint = "{tmp_path}/mnt"\n'
            "shared = false\n"
        )
        cfg_dir = make_project(config_root, "myproj", project_dir, toml_extra=toml_extra)
        (project_dir / "src").mkdir()
        (project_dir / "src" / "main.py").write_text("print('hi')\n")
        (project_dir / "node_modules").mkdir()
        (project_dir / "node_modules" / "dep.js").write_text("// dep\n")
        cipherdir = cfg_dir / "encrypted"
        cipherdir.mkdir()
        (cipherdir / "gocryptfs.conf").write_text("{}")
        # venv-style absolute symlink must survive the roundtrip
        venv_bin = project_dir / ".venv" / "bin"
        venv_bin.mkdir(parents=True)
        (venv_bin / "python").symlink_to("/usr/bin/python3")
        archive = tmp_path / "myproj.pwrap.tar.gz"
        pack_project("myproj", output=str(archive))

        # Unpack "on another workstation": fresh config root, new project path
        new_config_root = tmp_path / "newconfig"
        new_config_root.mkdir()
        monkeypatch.setattr(
            "project_wrap.core.get_config_dir", lambda: new_config_root
        )
        new_dir = tmp_path / "newhome" / "myproj"

        result = unpack_archive(str(archive), str(new_dir))

        assert result == new_config_root / "myproj"
        # Project files
        assert (new_dir / "src" / "main.py").read_text() == "print('hi')\n"
        assert (new_dir / "node_modules" / "dep.js").exists()
        assert (new_dir / ".venv" / "bin" / "python").is_symlink()
        # Config installed with rewritten paths
        toml = (new_config_root / "myproj" / "project.toml").read_text()
        assert f'dir = "{new_dir}"' in toml
        assert f'"{new_dir}/node_modules"' in toml
        assert f'HOME = "{new_dir}/.home"' in toml
        # Paths outside the old project dir are untouched
        assert f'"{outside}"' in toml
        # Mountpoint was not under the old project dir — unchanged
        assert f'mountpoint = "{tmp_path}/mnt"' in toml
        # Init script + vault installed
        assert (new_config_root / "myproj" / "init.sh").exists()
        assert (new_config_root / "myproj" / "encrypted" / "gocryptfs.conf").exists()
        out = capsys.readouterr().out
        assert "Rewrote paths:" in out
        assert "Launch with: pwrap myproj" in out

    def test_unpack_refuses_nonempty_target(self, workspace, tmp_path, monkeypatch):
        archive, _project_dir, _cfg_dir = self._packed_project(workspace, tmp_path)
        new_config_root = tmp_path / "newconfig"
        new_config_root.mkdir()
        monkeypatch.setattr(
            "project_wrap.core.get_config_dir", lambda: new_config_root
        )
        new_dir = tmp_path / "newhome" / "myproj"
        new_dir.mkdir(parents=True)
        (new_dir / "existing.txt").write_text("occupied")

        with pytest.raises(SystemExit, match="Target directory is not empty"):
            unpack_archive(str(archive), str(new_dir))

    def test_unpack_force_over_nonempty_target(self, workspace, tmp_path, monkeypatch):
        archive, _project_dir, _cfg_dir = self._packed_project(workspace, tmp_path)
        new_config_root = tmp_path / "newconfig"
        new_config_root.mkdir()
        monkeypatch.setattr(
            "project_wrap.core.get_config_dir", lambda: new_config_root
        )
        new_dir = tmp_path / "newhome" / "myproj"
        new_dir.mkdir(parents=True)
        (new_dir / "existing.txt").write_text("occupied")

        unpack_archive(str(archive), str(new_dir), force=True)

        assert (new_dir / "src" / "main.py").exists()
        assert (new_config_root / "myproj" / "project.toml").exists()

    def test_unpack_refuses_existing_config(self, workspace, tmp_path, monkeypatch):
        archive, _project_dir, _cfg_dir = self._packed_project(workspace, tmp_path)
        new_config_root = tmp_path / "newconfig"
        (new_config_root / "myproj").mkdir(parents=True)
        monkeypatch.setattr(
            "project_wrap.core.get_config_dir", lambda: new_config_root
        )

        with pytest.raises(SystemExit, match="Config already exists"):
            unpack_archive(str(archive), str(tmp_path / "newhome" / "myproj"))

    def test_unpack_force_replaces_config(self, workspace, tmp_path, monkeypatch):
        archive, _project_dir, _cfg_dir = self._packed_project(workspace, tmp_path)
        new_config_root = tmp_path / "newconfig"
        existing = new_config_root / "myproj"
        existing.mkdir(parents=True)
        (existing / "project.toml").write_text("old")
        monkeypatch.setattr(
            "project_wrap.core.get_config_dir", lambda: new_config_root
        )

        unpack_archive(str(archive), str(tmp_path / "newhome" / "myproj"), force=True)

        assert "old" not in (existing / "project.toml").read_text()
        assert (existing / "init.sh").exists()

    def test_unpack_comments_missing_paths(self, workspace, tmp_path, monkeypatch, capsys):
        config_root, project_dir = workspace
        missing = "/nonexistent/pwrap-test-path"
        toml_extra = f'blacklist = [\n    "{missing}",\n]\n'
        archive, _project_dir, _cfg_dir = self._packed_project(
            workspace, tmp_path, toml_extra=toml_extra
        )
        new_config_root = tmp_path / "newconfig"
        new_config_root.mkdir()
        monkeypatch.setattr(
            "project_wrap.core.get_config_dir", lambda: new_config_root
        )

        unpack_archive(str(archive), str(tmp_path / "newhome" / "myproj"))

        toml = (new_config_root / "myproj" / "project.toml").read_text()
        assert f'# "{missing}",  # path not found on host' in toml
        assert "Commented out 1 path entry" in capsys.readouterr().out

    def test_unpack_keeps_paths_under_new_project_dir(
        self, workspace, tmp_path, monkeypatch
    ):
        """Entries rewritten to the new project dir must not be commented out."""
        config_root, project_dir = workspace
        toml_extra = f'blacklist = [\n    "{project_dir}/node_modules",\n]\n'
        make_project(config_root, "myproj", project_dir, toml_extra=toml_extra)
        (project_dir / "node_modules").mkdir()
        (project_dir / "node_modules" / "dep.js").write_text("// dep\n")
        archive = tmp_path / "myproj.pwrap.tar.gz"
        pack_project("myproj", output=str(archive))
        new_config_root = tmp_path / "newconfig"
        new_config_root.mkdir()
        monkeypatch.setattr(
            "project_wrap.core.get_config_dir", lambda: new_config_root
        )
        new_dir = tmp_path / "newhome" / "myproj"

        unpack_archive(str(archive), str(new_dir))

        toml = (new_config_root / "myproj" / "project.toml").read_text()
        assert f'"{new_dir}/node_modules"' in toml
        assert "path not found on host" not in toml

    def test_unpack_rejects_missing_archive(self, tmp_path):
        with pytest.raises(SystemExit, match="Archive not found"):
            unpack_archive(str(tmp_path / "nope.tar.gz"), str(tmp_path / "dest"))

    def test_unpack_rejects_non_pwrap_archive(self, tmp_path):
        archive = make_tar(tmp_path / "plain.tar.gz", [("foo.txt", "hello")])

        with pytest.raises(SystemExit, match="Not a pwrap archive"):
            unpack_archive(str(archive), str(tmp_path / "dest"))

    def test_unpack_rejects_newer_format_version(self, tmp_path):
        manifest = {
            "format": "pwrap-pack",
            "version": 99,
            "project": "myproj",
            "project_dir": "/old/myproj",
        }
        archive = make_tar(
            tmp_path / "future.tar.gz",
            [("pwrap-manifest.json", json.dumps(manifest))],
        )

        with pytest.raises(SystemExit, match="newer pwrap"):
            unpack_archive(str(archive), str(tmp_path / "dest"))

    def test_unpack_rejects_traversal_member(self, tmp_path):
        archive = make_tar(
            tmp_path / "evil.tar.gz",
            [
                manifest_member("myproj", "/old/myproj"),
                ("../evil.txt", "pwned"),
            ],
        )

        with pytest.raises(SystemExit, match="unsafe path"):
            unpack_archive(str(archive), str(tmp_path / "dest"))

    def test_unpack_rejects_extract_through_symlink(self, tmp_path):
        with tarfile.open(tmp_path / "evil.tar.gz", "w:gz") as tar:
            link = tarfile.TarInfo("link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/tmp"
            tar.addfile(link)
            data = b"pwned"
            info = tarfile.TarInfo("link/evil.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
            manifest = json.dumps(
                {
                    "format": "pwrap-pack",
                    "version": 1,
                    "project": "myproj",
                    "project_dir": "/old/myproj",
                }
            ).encode()
            minfo = tarfile.TarInfo("pwrap-manifest.json")
            minfo.size = len(manifest)
            tar.addfile(minfo, io.BytesIO(manifest))

        with pytest.raises(SystemExit, match="through symlink"):
            unpack_archive(str(tmp_path / "evil.tar.gz"), str(tmp_path / "dest"))

    def test_unpack_rejects_missing_vault(self, tmp_path):
        config = (
            '[project]\nname = "myproj"\ndir = "/old/myproj"\nshell = "/bin/bash"\n'
            "\n[sandbox]\nenabled = true\n"
            '\n[encrypted]\ncipherdir = "encrypted"\nmountpoint = "/tmp/mnt"\n'
        )
        archive = make_tar(
            tmp_path / "novault.tar.gz",
            [
                manifest_member("myproj", "/old/myproj"),
                ("config/project.toml", config),
                ("project/file.txt", "data"),
            ],
        )

        with pytest.raises(SystemExit, match="no vault"):
            unpack_archive(str(archive), str(tmp_path / "dest"))

    def test_unpack_rejects_invalid_config_schema(self, tmp_path, monkeypatch):
        config_root = tmp_path / "newconfig"
        config_root.mkdir()
        monkeypatch.setattr("project_wrap.core.get_config_dir", lambda: config_root)
        config = (
            '[project]\nname = "myproj"\ndir = "/old/myproj"\nshell = "/bin/bash"\n'
            "\n[bogus]\nfoo = 1\n"
        )
        archive = make_tar(
            tmp_path / "badconfig.tar.gz",
            [
                manifest_member("myproj", "/old/myproj"),
                ("config/project.toml", config),
                ("project/file.txt", "data"),
            ],
        )

        with pytest.raises(SystemExit, match="Unknown config sections"):
            unpack_archive(str(archive), str(tmp_path / "dest"))
        # Nothing was installed
        assert not (config_root / "myproj").exists()
        assert not (tmp_path / "dest").exists()

    def test_unpack_rejects_traversal_project_name(self, tmp_path):
        manifest = {
            "format": "pwrap-pack",
            "version": 1,
            "project": "../evil",
            "project_dir": "/old/myproj",
        }
        archive = make_tar(
            tmp_path / "evilname.tar.gz",
            [
                ("pwrap-manifest.json", json.dumps(manifest)),
                ("config/project.toml", "[project]\n"),
                ("project/file.txt", "data"),
            ],
        )

        with pytest.raises(SystemExit, match="Invalid project name"):
            unpack_archive(str(archive), str(tmp_path / "dest"))

    def test_unpack_absolute_cipherdir_outside_project(
        self, workspace, tmp_path, monkeypatch
    ):
        """A cipherdir outside the project dir keeps its absolute path."""
        config_root, project_dir = workspace
        cipherdir = tmp_path / "elsewhere" / "vault"
        cipherdir.mkdir(parents=True)
        (cipherdir / "gocryptfs.conf").write_text("{}")
        toml_extra = (
            "\n[encrypted]\n"
            f'cipherdir = "{cipherdir}"\n'
            f'mountpoint = "{tmp_path}/mnt"\n'
        )
        archive, _project_dir, _cfg_dir = self._packed_project(
            workspace, tmp_path, toml_extra=toml_extra
        )
        # Simulate the other workstation: the original cipherdir is gone
        import shutil

        shutil.rmtree(cipherdir)
        new_config_root = tmp_path / "newconfig"
        new_config_root.mkdir()
        monkeypatch.setattr(
            "project_wrap.core.get_config_dir", lambda: new_config_root
        )

        unpack_archive(str(archive), str(tmp_path / "newhome" / "myproj"))

        assert (cipherdir / "gocryptfs.conf").exists()
        toml = (new_config_root / "myproj" / "project.toml").read_text()
        assert f'cipherdir = "{cipherdir}"' in toml

    def test_unpack_refuses_nonempty_cipherdir(self, workspace, tmp_path, monkeypatch):
        config_root, project_dir = workspace
        cipherdir = tmp_path / "elsewhere" / "vault"
        cipherdir.mkdir(parents=True)
        (cipherdir / "gocryptfs.conf").write_text("{}")
        toml_extra = (
            "\n[encrypted]\n"
            f'cipherdir = "{cipherdir}"\n'
            f'mountpoint = "{tmp_path}/mnt"\n'
        )
        archive, _project_dir, _cfg_dir = self._packed_project(
            workspace, tmp_path, toml_extra=toml_extra
        )
        new_config_root = tmp_path / "newconfig"
        new_config_root.mkdir()
        monkeypatch.setattr(
            "project_wrap.core.get_config_dir", lambda: new_config_root
        )

        with pytest.raises(SystemExit, match="cipherdir already exists"):
            unpack_archive(str(archive), str(tmp_path / "newhome" / "myproj"))


class TestCLI:
    def test_pack_dispatch(self, workspace, tmp_path, capsys):
        config_root, project_dir = workspace
        make_project(config_root, "myproj", project_dir)
        archive = tmp_path / "out.tar.gz"

        result = main(["pack", "myproj", "-o", str(archive)])

        assert result == 0
        assert archive.exists()
        assert "Created" in capsys.readouterr().out

    def test_unpack_dispatch(self, workspace, tmp_path, monkeypatch, capsys):
        config_root, project_dir = workspace
        make_project(config_root, "myproj", project_dir)
        archive = tmp_path / "out.tar.gz"
        pack_project("myproj", output=str(archive))
        new_config_root = tmp_path / "newconfig"
        new_config_root.mkdir()
        monkeypatch.setattr(
            "project_wrap.core.get_config_dir", lambda: new_config_root
        )

        result = main(["unpack", str(archive), str(tmp_path / "newhome" / "myproj")])

        assert result == 0
        assert (new_config_root / "myproj" / "project.toml").exists()
        assert "Unpacked myproj" in capsys.readouterr().out

    def test_pack_help(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["pack", "--help"])
        assert exc_info.value.code == 0

    def test_unpack_help(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["unpack", "--help"])
        assert exc_info.value.code == 0

    def test_pack_error_returns_1(self, workspace, capsys):
        result = main(["pack", "nonexistent"])
        assert result == 1
        assert "Unknown project" in capsys.readouterr().err

    def test_unpack_error_returns_1(self, tmp_path, capsys):
        result = main(["unpack", str(tmp_path / "nope.tar.gz"), str(tmp_path / "d")])
        assert result == 1
        assert "Archive not found" in capsys.readouterr().err

    def test_main_help_mentions_subcommands(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "pwrap pack" in out
        assert "pwrap unpack" in out
