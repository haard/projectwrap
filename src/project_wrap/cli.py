"""CLI entry point for project-wrap."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .core import (
    create_project,
    ensure_templates,
    get_config_dir,
    list_projects,
    run_project,
)
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
