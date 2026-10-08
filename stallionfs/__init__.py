"""Native filesystem operations and prepared Git workspaces for macOS."""

__version__ = "0.6.3"

__all__ = ["clone", "delete", "mounts", "move", "scan"]


def __getattr__(name):
    if name not in __all__ and name != "_scan":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module
    native = import_module("._scan", __name__)
    value = native if name == "_scan" else getattr(native, name)
    globals()[name] = value
    return value


def __dir__():
    return sorted((set(globals()) | set(__all__) | {"_scan"}) - {"__getattr__", "__dir__"})
