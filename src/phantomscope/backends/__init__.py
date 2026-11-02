"""Backend implementations."""

from .mock import MockBackend

__all__ = ["MockBackend", "MemProcFsBackend", "create_backend"]


def __getattr__(name: str):
    # Import MemProcFS lazily so the rest of the package works without it.
    if name == "MemProcFsBackend":
        from .memprocfs_backend import MemProcFsBackend

        return MemProcFsBackend
    if name == "create_backend":
        from .factory import create_backend

        return create_backend
    raise AttributeError(name)
