"""CLI entry point for project-wrap."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .core import (
    get_config_dir,
    list_projects,
    run_project,
)
from .deps import check_optional_deps
from .guide import run_guide
from .pack import pack_project, unpack_archive
from .scaffold import create_project, ensure_templates


def _exit_code(e: SystemExit) -> int:
    """Convert a SystemExit into a process exit code."""
    if isinstance(e.code, int):
        return e.code
    print(f"Error: {e.code}", file=sys.stderr)
    return 1


def _pack_cli(argv: list[str]) -> int:
    """Handle `pwrap pack <project> [-o FILE]`."""
    parser = argparse.ArgumentParser(
        prog="pwrap pack",
        description="Pack a project (folder, config, vault) into a tar.gz archive",
    )
    parser.add_argument("project", help="Project name to pack")
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Output archive (default: <name>.pwrap.tar.gz in the current directory)",
    )
    args = parser.parse_args(argv)
    try:
        archive = pack_project(args.project, output=args.output)
    except SystemExit as e:
        return _exit_code(e)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    print(f"Created {archive}")
    return 0


def _unpack_cli(argv: list[str]) -> int:
    """Handle `pwrap unpack <file> <path> [--force]`."""
    parser = argparse.ArgumentParser(
        prog="pwrap unpack",
        description="Unpack a pwrap archive onto this workstation",
    )
    parser.add_argument("archive", help="Archive created by pwrap pack")
    parser.add_argument("path", help="New project directory")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing config dir / unpack over non-empty target dirs",
    )
    args = parser.parse_args(argv)
    try:
        unpack_archive(args.archive, args.path, force=args.force)
    except SystemExit as e:
        return _exit_code(e)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    if argv is None:
        argv = sys.argv[1:]

    if argv[:1] == ["pack"]:
        return _pack_cli(argv[1:])
    if argv[:1] == ["unpack"]:
        return _unpack_cli(argv[1:])

    parser = argparse.ArgumentParser(
        prog="pwrap",
        description="Isolated project environments with bubblewrap sandboxing",
        epilog="Subcommands: pwrap pack <project> [-o FILE], "
        "pwrap unpack <file> <path> [--force]",
    )
    parser.add_argument(
        "project",
        nargs="?",
        help="Project name to load",
    )
    parser.add_argument(
        "--new",
        metavar="DIR",
        help="Create a new project config with DIR as the project directory",
    )
    parser.add_argument(
        "--guide",
        metavar="DIR",
        help="Guided setup: interactively convert an existing folder into a pwrap config",
    )
    parser.add_argument(
        "--no-sandbox",
        action="store_true",
        help="Disable sandbox in generated config (use with --new)",
    )
    parser.add_argument(
        "--shell",
        metavar="SHELL",
        help="Shell to configure (use with --new, defaults to $SHELL)",
    )
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="List available projects",
    )
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help="Check availability of optional dependencies",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output",
    )

    args = parser.parse_args(argv)

    try:
        if args.check_deps:
            check_optional_deps(verbose=True)
            return 0

        if args.new:
            if ensure_templates():
                config_dir = get_config_dir()
                print("Templates created:")
                for name in ["project.tpl.toml", "init.tpl.fish", "init.tpl.sh"]:
                    print(f"  {config_dir / name}")
                print("Edit these templates, then run pwrap --new again.")
                return 0

            print(f"Using template {get_config_dir() / 'project.tpl.toml'}")
            config_path = create_project(
                args.new,
                name=args.project or None,
                sandbox=not args.no_sandbox,
                shell=args.shell,
            )
            print(f"Created {config_path}")
            return 0

        if args.guide:
            config_path = run_guide(
                args.guide,
                name=args.project or None,
                shell=args.shell,
            )
            return 0

        if args.list or not args.project:
            list_projects()
            return 0

        run_project(args.project, verbose=args.verbose)
        return 0  # Won't reach here if exec succeeds

    except KeyboardInterrupt:
        print("\nAborted.")
        return 130
    except SystemExit as e:
        if isinstance(e.code, int):
            return e.code
        print(f"Error: {e.code}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
