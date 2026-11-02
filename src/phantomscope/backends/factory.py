"""Backend construction helpers."""

from __future__ import annotations

from typing import Iterable

from ..backend import MemoryBackend
from ..errors import InvalidArgument
from .mock import MockBackend


def create_backend(
    kind: str = "memprocfs",
    *,
    device: str = "fpga",
    options: Iterable[str] | None = None,
    forensic: int = 0,
    wait_initialize: bool = False,
    name: str = "default",
) -> MemoryBackend:
    """Create (but do not open) a backend.

    ``kind`` is ``memprocfs`` for real DMA / dump analysis or ``mock`` for a
    deterministic synthetic target (useful for demos and tests).
    """
    kind = (kind or "memprocfs").lower()
    if kind in ("mock", "demo"):
        from .demo import populate_demo_backend
        from .mock import MockBackend

        backend = MockBackend(name=name)
        populate_demo_backend(backend)
        return backend
    if kind in ("memprocfs", "dma", "fpga"):
        from .memprocfs_backend import MemProcFsBackend

        return MemProcFsBackend(
            device=device,
            options=options,
            name=name,
            forensic=forensic,
            wait_initialize=wait_initialize,
        )
    raise InvalidArgument(f"unknown backend kind: {kind!r} (expected 'memprocfs' or 'mock')")
