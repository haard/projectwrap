"""CLI entry point for project-wrap."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .core import create_project, list_projects, run_project, unmount_project
from .deps import check_optional_deps


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="pwrap",
        description="Isolated project environments with bubblewrap sandboxing",
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
        "--no-sandbox",
        action="store_true",
        help="Disable sandbox in generated config (use with --new)",
    )
    parser.add_argument(
        "-u",
        "--unmount",
        action="store_true",
        help="Unmount encrypted volumes for project",
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
            if not args.project:
                print("Error: --new requires a project name", file=sys.stderr)
                return 1
            config_path = create_project(
                args.project, args.new, sandbox=not args.no_sandbox
            )
            print(f"Created {config_path / 'project.toml'}")
            return 0

        if args.list or not args.project:
            list_projects()
            return 0

        if args.unmount:
            unmount_project(args.project)
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
