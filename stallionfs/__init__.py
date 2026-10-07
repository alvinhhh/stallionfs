"""Native filesystem operations and prepared Git workspaces for macOS."""

__version__ = "0.6.0"

from ._scan import clone, delete, mounts, move, scan

__all__ = ["clone", "delete", "mounts", "move", "scan"]
