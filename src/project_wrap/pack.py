"""Pack and unpack projects for transfer between workstations.

`pwrap pack <project>` writes a gzipped tar archive containing:

    pwrap-manifest.json   # format marker, pwrap version, original project dir
    config/project.toml   # the project config
    config/init.*         # init scripts
    project/              # the project directory contents
    vault/                # the gocryptfs cipherdir (only with [encrypted])

`pwrap unpack <file> <path>` extracts the archive, installs the config into
~/.config/pwrap/<name>/, unpacks the project into <path>, and rewrites every
config path that pointed inside the old project directory to the new one.
The rewritten config is then validated: schema errors abort the unpack, and
blacklist/writable entries that do not exist on the new host are commented
out (same behavior as `pwrap --new`).

The vault cipherdir is ciphertext, so it is safe to move inside the archive;
the gocryptfs password is never stored anywhere. A vault mountpoint that is
currently mounted is excluded from the project files — packing it would leak
the decrypted plaintext into the archive.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import tomllib
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__, core
from .scaffold import _comment_missing_paths
from .validate import validate_config, validate_project_name

MANIFEST_NAME = "pwrap-manifest.json"
FORMAT_NAME = "pwrap-pack"
FORMAT_VERSION = 1

_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]")
_KEY_VALUE_RE = re.compile(r"^(\s*)(\w+)\s*=\s*(.*)$")
_STRING_RE = re.compile(r'"([^"]*)"')

# [sandbox] keys whose list entries are host paths
_PATH_LIST_KEYS = {"blacklist", "whitelist", "writable"}


# --- manifest ---


def _build_manifest(
    name: str,
    project_dir: Path,
    config: dict[str, Any],
) -> dict[str, Any]:
    """Build the archive manifest."""
    return {
        "format": FORMAT_NAME,
        "version": FORMAT_VERSION,
        "pwrap_version": __version__,
        "created": datetime.now(UTC).isoformat(),
        "project": name,
        "project_dir": str(project_dir),
        "project_dir_raw": config.get("project", {}).get("dir", ""),
        "has_vault": bool(config.get("encrypted")),
    }


def _read_manifest(tar: tarfile.TarFile) -> dict[str, Any]:
    """Read and validate the manifest from an open archive."""
    try:
        member = tar.extractfile(MANIFEST_NAME)
    except KeyError:
        raise SystemExit(f"Not a pwrap archive (missing {MANIFEST_NAME})")
    if member is None:
        raise SystemExit(f"Not a pwrap archive (missing {MANIFEST_NAME})")
    try:
        manifest = json.loads(member.read().decode())
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise SystemExit(f"Invalid manifest in archive: {e}")
    if not isinstance(manifest, dict):
        raise SystemExit("Invalid manifest in archive: not an object")
    if manifest.get("format") != FORMAT_NAME:
        raise SystemExit(f"Not a pwrap archive (missing {MANIFEST_NAME})")
    version = manifest.get("version")
    if not isinstance(version, int) or version < 1:
        raise SystemExit(f"Invalid manifest in archive: bad version {version!r}")
    if version > FORMAT_VERSION:
        raise SystemExit(
            f"Archive was created by a newer pwrap (format v{version}); "
            f"upgrade pwrap to unpack it."
        )
    if not isinstance(manifest.get("project"), str):
        raise SystemExit("Invalid manifest in archive: missing project name")
    if not isinstance(manifest.get("project_dir"), str):
        raise SystemExit("Invalid manifest in archive: missing project_dir")
    return manifest


# --- safe extraction ---


def _make_extract_filter(
    dest: Path,
) -> Callable[[tarfile.TarInfo, str], tarfile.TarInfo | None]:
    """Build a tarfile extraction filter that refuses unsafe members.

    Rejects absolute paths, `..` traversal, hardlinks pointing outside the
    archive, and device/fifo members. Symlinks are allowed (venvs are full of
    absolute symlinks), but nothing may be extracted *through* a symlink —
    that is the classic tar escape where a link member redirects a later file
    member outside the extraction directory.
    """
    dest_resolved = dest.resolve()

    def filt(member: tarfile.TarInfo, _path: str) -> tarfile.TarInfo | None:
        rel = Path(member.name)
        if rel.is_absolute() or ".." in rel.parts:
            raise SystemExit(f"Refusing unsafe path in archive: {member.name!r}")
        if member.isdev() or member.isfifo():
            raise SystemExit(f"Refusing special file in archive: {member.name!r}")
        if member.islnk():
            link = Path(member.linkname)
            if link.is_absolute() or ".." in link.parts:
                raise SystemExit(f"Refusing unsafe link in archive: {member.name!r}")
        # Never write through an existing symlink (checked per member, so
        # symlinks created by earlier members are already on disk).
        for i in range(1, len(rel.parts)):
            if dest.joinpath(*rel.parts[:i]).is_symlink():
                raise SystemExit(
                    f"Refusing to extract through symlink: {member.name!r}"
                )
        if not (member.issym() or member.islnk()):
            resolved = (dest / rel).resolve()
            if resolved != dest_resolved and dest_resolved not in resolved.parents:
                raise SystemExit(f"Refusing unsafe path in archive: {member.name!r}")
        return member

    return filt


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract an archive into dest after validating every member."""
    filt = _make_extract_filter(dest)
    if sys.version_info >= (3, 11, 4):
        tar.extractall(dest, filter=filt)
    else:
        # PEP 706 filter parameter not available; validate manually.
        for member in tar.getmembers():
            filt(member, str(dest))
            tar.extract(member, dest)


# --- path rewriting ---


def _normalize(path: Path) -> Path:
    """Lexically normalize a path (collapse .. and .) without touching the fs."""
    return Path(os.path.normpath(str(path)))


def _rewrite_path_value(value: str, old_dirs: list[Path], new_dir: Path) -> str:
    """Rewrite a config path value that points inside an old project dir.

    Returns the value unchanged if it is relative or not under any old dir.
    """
    expanded = _normalize(core.expand_path(value))
    if not expanded.is_absolute():
        return value
    for old in old_dirs:
        try:
            rel = expanded.relative_to(old)
        except ValueError:
            continue
        return str(new_dir / rel)
    return value


def _rewrite_line_strings(
    line: str,
    old_dirs: list[Path],
    new_dir: Path,
    changes: list[tuple[str, str]],
    first_only: bool = False,
) -> str:
    """Rewrite quoted path strings on a TOML line, preserving formatting."""

    def repl(match: re.Match[str]) -> str:
        value = match.group(1)
        new_value = _rewrite_path_value(value, old_dirs, new_dir)
        if new_value != value:
            changes.append((value, new_value))
        return f'"{new_value}"'

    return _STRING_RE.sub(repl, line, count=1 if first_only else 0)


def _rewrite_config_paths(
    toml_text: str,
    old_dirs: list[Path],
    new_dir: Path,
) -> tuple[str, list[tuple[str, str]]]:
    """Rewrite config paths that point inside the old project directory.

    Line-based so comments and formatting survive. Handles:
    - [project] dir (always replaced with the new project dir)
    - [sandbox] blacklist/whitelist/writable entries (single- and multi-line)
    - [encrypted] cipherdir/mountpoint
    - [env] values

    Returns the new text and a list of (old, new) value changes.
    """
    changes: list[tuple[str, str]] = []
    out: list[str] = []
    section = ""
    in_path_list = False

    for line in toml_text.splitlines():
        section_match = _SECTION_RE.match(line)
        if section_match:
            section = section_match.group(1).strip()
            in_path_list = False
            out.append(line)
            continue

        if in_path_list:
            stripped = line.lstrip()
            if stripped.startswith("]"):
                in_path_list = False
                out.append(line)
            elif stripped and not stripped.startswith("#"):
                out.append(_rewrite_line_strings(line, old_dirs, new_dir, changes))
            else:
                out.append(line)
            continue

        kv = _KEY_VALUE_RE.match(line)
        if kv:
            key = kv.group(2)
            rest = kv.group(3)
            if section == "project" and key == "dir":
                dir_match = _STRING_RE.search(line)
                if dir_match and dir_match.group(1) != str(new_dir):
                    changes.append((dir_match.group(1), str(new_dir)))
                out.append(_STRING_RE.sub(lambda _m: f'"{new_dir}"', line, count=1))
                continue
            if section == "sandbox" and key in _PATH_LIST_KEYS:
                out.append(_rewrite_line_strings(line, old_dirs, new_dir, changes))
                if rest.lstrip().startswith("[") and "]" not in rest:
                    in_path_list = True
                continue
            if (
                section == "encrypted" and key in ("cipherdir", "mountpoint")
            ) or section == "env":
                out.append(
                    _rewrite_line_strings(
                        line, old_dirs, new_dir, changes, first_only=True
                    )
                )
                continue

        out.append(line)

    result = "\n".join(out)
    if toml_text.endswith("\n"):
        result += "\n"
    return result, changes


def _old_dirs(manifest: dict[str, Any]) -> list[Path]:
    """Candidate old project dirs from the manifest (resolved + raw)."""
    dirs = [_normalize(Path(manifest["project_dir"]))]
    raw = manifest.get("project_dir_raw", "")
    if raw:
        expanded = _normalize(core.expand_path(raw))
        if expanded.is_absolute() and expanded not in dirs:
            dirs.append(expanded)
    return dirs


# --- pack ---


def _format_size(size: int) -> str:
    """Human-readable size."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KiB"
    return f"{size / (1024 * 1024):.1f} MiB"


def _make_project_filter(
    project_dir: Path,
    exclude: list[Path],
) -> Callable[[tarfile.TarInfo], tarfile.TarInfo | None]:
    """Build a tarfile add-filter that skips excluded subtrees of the project.

    Excluded: the vault cipherdir (packed separately as vault/) and a mounted
    vault mountpoint (packing it would leak decrypted plaintext).
    """

    def filt(member: tarfile.TarInfo) -> tarfile.TarInfo | None:
        rel = Path(member.name)
        if rel.parts and rel.parts[0] == "project":
            real = project_dir.joinpath(*rel.parts[1:])
            for ex in exclude:
                if real == ex or ex in real.parents:
                    return None
        return member

    return filt


def pack_project(name: str, output: str | None = None) -> Path:
    """Pack a project (folder, config, vault) into a tar.gz archive.

    Args:
        name: Project name (config in ~/.config/pwrap/<name>).
        output: Output archive path. Defaults to <name>.pwrap.tar.gz in cwd.

    Returns the archive path.
    """
    config = core.load_config(name)
    config_dir: Path = config["_config_dir"]
    project_cfg = config.get("project", {})
    project_dir = core.expand_path(
        project_cfg.get("dir", f"~/projects/{name}")
    ).resolve()
    if not project_dir.is_dir():
        raise SystemExit(f"Project directory does not exist: {project_dir}")

    # Resolve the vault cipherdir/mountpoint
    encrypted = config.get("encrypted", {})
    cipherdir: Path | None = None
    mountpoint: Path | None = None
    if encrypted:
        if "cipherdir" not in encrypted or "mountpoint" not in encrypted:
            raise SystemExit("[encrypted] requires cipherdir and mountpoint")
        raw = encrypted["cipherdir"]
        cipherdir_path = core.expand_path(raw)
        if not cipherdir_path.is_absolute():
            cipherdir_path = config_dir / raw
        cipherdir = cipherdir_path.resolve()
        if not cipherdir.is_dir():
            raise SystemExit(
                f"Encrypted cipherdir does not exist: {cipherdir}\n"
                f"Nothing to pack — remove the [encrypted] section or create "
                f"the cipherdir first."
            )
        mountpoint = core.expand_path(encrypted["mountpoint"]).resolve()

    if output is None:
        output_path = Path.cwd() / f"{name}.pwrap.tar.gz"
    else:
        output_path = core.expand_path(output)
    output_path = _normalize(output_path)
    if output_path.exists():
        raise SystemExit(
            f"Output file already exists: {output_path}\n"
            f"Remove it or pass -o/--output to choose another path."
        )
    # The archive is written before the project dir is read; refuse to write
    # it inside a directory that gets packed (it would embed itself).
    for guarded in (project_dir, cipherdir):
        if guarded is not None and (
            output_path == guarded or guarded in output_path.parents
        ):
            raise SystemExit(
                f"Output file must not be inside the packed directory: {output_path}"
            )

    # Subtrees of the project dir to exclude from project/
    exclude: list[Path] = []
    excluded_mount: Path | None = None
    if cipherdir is not None and cipherdir != project_dir:
        if cipherdir.is_relative_to(project_dir):
            exclude.append(cipherdir)
    if (
        mountpoint is not None
        and mountpoint != project_dir
        and mountpoint.is_relative_to(project_dir)
        and os.path.ismount(mountpoint)
    ):
        # Currently mounted: contains decrypted plaintext. The cipherdir is
        # packed (ciphertext), so nothing is lost.
        exclude.append(mountpoint)
        excluded_mount = mountpoint

    manifest = _build_manifest(name, project_dir, config)
    manifest_data = (json.dumps(manifest, indent=2) + "\n").encode()

    with tarfile.open(output_path, "w:gz") as tar:
        # Config: project.toml + init scripts (a relative cipherdir lives in
        # the config dir too — it is packed separately as vault/).
        for f in sorted(config_dir.iterdir()):
            if f.is_file() and (f.name == "project.toml" or f.name.startswith("init.")):
                tar.add(f, arcname=f"config/{f.name}")
        # Manifest
        info = tarfile.TarInfo(MANIFEST_NAME)
        info.size = len(manifest_data)
        info.mtime = int(datetime.now(UTC).timestamp())
        tar.addfile(info, io.BytesIO(manifest_data))
        # Project directory
        tar.add(
            project_dir,
            arcname="project",
            filter=_make_project_filter(project_dir, exclude),
        )
        # Vault cipherdir (ciphertext — safe to move)
        if cipherdir is not None:
            tar.add(cipherdir, arcname="vault")

    size = output_path.stat().st_size
    print(f"Packed {name}:")
    print(f"  Project: {project_dir}")
    print(f"  Config:  {config_dir}")
    if cipherdir is not None:
        print(f"  Vault:   {cipherdir} (encrypted at rest)")
    print(f"  Archive: {output_path} ({_format_size(size)})")
    if excluded_mount is not None:
        print(
            f"  Note: vault is mounted at {excluded_mount}; its decrypted "
            "contents were excluded from the project files."
        )
    if config.get("env"):
        print(
            "  Warning: [env] values are stored in plaintext in the archive — "
            "they may contain secrets.",
            file=sys.stderr,
        )

    return output_path


# --- unpack ---


def _resolve_cipherdir(raw: str, config_dir: Path) -> Path:
    """Resolve a cipherdir config value (relative values are config-dir local)."""
    p = core.expand_path(raw)
    if not p.is_absolute():
        p = config_dir / raw
    return p.resolve()


def unpack_archive(archive: str, dest: str, force: bool = False) -> Path:
    """Unpack a pwrap archive to a new location.

    Installs the config into ~/.config/pwrap/<name>/, unpacks the project
    into dest, extracts the vault cipherdir, and rewrites config paths that
    pointed inside the old project directory. The rewritten config is
    validated before anything is installed: schema errors abort, and
    blacklist/writable entries missing on this host are commented out.

    Args:
        archive: Path to a .pwrap.tar.gz archive.
        dest: New project directory.
        force: Replace an existing config dir / non-empty target dirs.

    Returns the installed config directory.
    """
    archive_path = core.expand_path(archive)
    if not archive_path.is_file():
        raise SystemExit(f"Archive not found: {archive_path}")
    new_dir = core.expand_path(dest).resolve()

    with tempfile.TemporaryDirectory(prefix="pwrap-unpack-") as tmp:
        staging = Path(tmp)
        with tarfile.open(archive_path, "r:gz") as tar:
            manifest = _read_manifest(tar)
            _safe_extract(tar, staging)

        name: str = manifest["project"]
        validate_project_name(name)
        old_dirs = _old_dirs(manifest)

        config_src = staging / "config" / "project.toml"
        if not config_src.is_file():
            raise SystemExit("Invalid archive: missing config/project.toml")
        original_text = config_src.read_text()

        # Rewrite paths, comment out entries missing on this host, and
        # validate the result — all before anything is installed. Paths under
        # the new project dir don't exist on disk yet; check the staged copy.
        def staged_exists(value: str) -> bool:
            p = core.expand_path(value)
            if not p.is_absolute():
                return p.exists()
            try:
                rel = p.relative_to(new_dir)
            except ValueError:
                return p.exists()
            return (staging / "project" / rel).exists()

        rewritten, changes = _rewrite_config_paths(original_text, old_dirs, new_dir)
        rewritten = _comment_missing_paths(rewritten, exists=staged_exists)
        try:
            parsed = tomllib.loads(rewritten)
        except tomllib.TOMLDecodeError as e:
            raise SystemExit(f"Invalid config in archive: {e}")
        validate_config(parsed)

        config_dir = core.get_config_dir() / name
        encrypted = parsed.get("encrypted", {})
        vault_src = staging / "vault"
        vault_target: Path | None = None
        if encrypted:
            if "cipherdir" not in encrypted:
                raise SystemExit("Invalid config in archive: [encrypted] missing cipherdir")
            if not vault_src.is_dir():
                raise SystemExit(
                    "Config has an [encrypted] section but the archive contains "
                    "no vault. Refusing to unpack."
                )
            vault_target = _resolve_cipherdir(encrypted["cipherdir"], config_dir)
        elif vault_src.is_dir():
            print(
                "Warning: archive contains a vault but the config has no "
                "[encrypted] section. Extracting it into the config directory; "
                "add an [encrypted] section to use it.",
                file=sys.stderr,
            )
            vault_target = config_dir / "vault"

        # --- pre-flight checks (no writes yet) ---
        if config_dir.exists() and not force:
            raise SystemExit(
                f"Config already exists: {config_dir}\n"
                f"Remove it first, or re-run with --force to replace it."
            )
        if new_dir.exists() and any(new_dir.iterdir()) and not force:
            raise SystemExit(
                f"Target directory is not empty: {new_dir}\n"
                f"Choose an empty path, or re-run with --force to unpack over it."
            )
        if vault_target is not None and (
            vault_target.exists() and any(vault_target.iterdir()) and not force
        ):
            raise SystemExit(
                f"Encrypted cipherdir already exists and is not empty: {vault_target}\n"
                f"Remove it first, or re-run with --force to replace it."
            )

        # --- install ---
        if config_dir.exists():
            print(f"Replacing existing config: {config_dir}")
            shutil.rmtree(config_dir)
        config_dir.mkdir(parents=True)
        config_dir.chmod(0o700)
        project_toml = config_dir / "project.toml"
        project_toml.write_text(rewritten)
        project_toml.chmod(0o600)
        for init in sorted((staging / "config").glob("init.*")):
            if init.is_file():
                shutil.copy2(init, config_dir / init.name)
                (config_dir / init.name).chmod(0o600)

        new_dir.mkdir(parents=True, exist_ok=True)
        if any(new_dir.iterdir()):
            print(f"Unpacking over existing directory: {new_dir}")
        shutil.copytree(staging / "project", new_dir, symlinks=True, dirs_exist_ok=True)

        if vault_target is not None:
            vault_target.mkdir(parents=True, exist_ok=True)
            shutil.copytree(vault_src, vault_target, symlinks=True, dirs_exist_ok=True)
            vault_target.chmod(0o700)

    # --- summary ---
    commented = rewritten.count("# path not found on host") - original_text.count(
        "# path not found on host"
    )
    print(f"Unpacked {name}:")
    print(f"  Project: {new_dir}")
    print(f"  Config:  {project_toml}")
    if vault_target is not None:
        print(f"  Vault:   {vault_target} (encrypted; original password required)")
    if changes:
        print("  Rewrote paths:")
        for old, new in changes:
            print(f"    {old} -> {new}")
    if commented:
        print(
            f"  Commented out {commented} path "
            f"{'entry' if commented == 1 else 'entries'} not found on this host "
            f"(see project.toml)."
        )
    shell = parsed.get("project", {}).get("shell", "")
    if shell and not Path(shell).is_file():
        print(f"  Warning: shell does not exist on this host: {shell}")
    print(f"  Launch with: pwrap {name}")

    return config_dir
