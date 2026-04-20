"""project-wrap: Isolated project environments with bubblewrap sandboxing."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("projectwrap")
except PackageNotFoundError:
    __version__ = "0+unknown"
