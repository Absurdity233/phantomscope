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

    ``kind`` selects the acquisition model:

    ``memprocfs``
        Real DMA (PCILeech FPGA), a memory dump, ``pmem`` or a LeechAgent
        remote — anything MemProcFS understands, with full OS-level views.
    ``physical``
        A raw physical image addressed directly (``device`` is a dump path,
        optionally with ``memmap=pa,size;...``). No OS structures are assumed.
    ``mock``
        A deterministic synthetic target, for demos and tests.
    ``game``
        The synthetic shooter: same idea, but with a background tick that
        damages the local player and drifts the entities, so the motion-dependent
        workflows (scan narrowing, change tracing) have something to fight against.
    """
    kind = (kind or "memprocfs").lower()
    if kind in ("mock", "demo"):
        from .demo import populate_demo_backend
        from .mock import MockBackend

        backend = MockBackend(name=name)
        populate_demo_backend(backend)
        return backend
    if kind in ("game", "shooter"):
        # A synthetic game client with a running tick: the target to use when the
        # thing being exercised is motion (scan narrowing, change tracing, pointer
        # chains that have to survive a restart), not just reading.
        from .gametarget import build_game_backend

        backend, _state = build_game_backend(with_tick=True, name=name)
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
    if kind in ("physical", "raw", "dump"):
        from ..physical import PhysicalBackend

        return PhysicalBackend(device=device, options=options, name=name)
    raise InvalidArgument(
        f"unknown backend kind: {kind!r} (expected 'memprocfs', 'physical' or 'mock')"
    )
