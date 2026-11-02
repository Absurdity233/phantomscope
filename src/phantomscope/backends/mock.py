"""Deterministic in-memory backend.

Used by the test-suite and by ``phantomscope selftest``.  It implements the
full backend contract over plain Python dictionaries, including threads,
callstacks and PDB-style symbols, which makes it possible to exercise every
dynamic feature without DMA hardware.
"""

from __future__ import annotations

import struct
from bisect import bisect_right

from ..backend import Capabilities, MemoryBackend
from ..errors import BackendError, NotFound
from ..models import ModuleInfo, ProcessInfo, Region, StackFrame, ThreadInfo


class _Space:
    """Sparse virtual address space for one process."""

    def __init__(self) -> None:
        self.regions: dict[int, Region] = {}
        self.data: dict[int, bytearray] = {}
        self.order: list[int] = []

    def map(self, base: int, data: bytes, protection: str = "rw-", tag: str | None = None,
            module: str | None = None) -> None:
        base &= ~0xFFF
        self.regions[base] = Region(base=base, size=len(data), protection=protection, tag=tag, module=module)
        self.data[base] = bytearray(data)
        self.order = sorted(self.regions)

    def find(self, va: int) -> int | None:
        idx = bisect_right(self.order, va) - 1
        if idx < 0:
            return None
        base = self.order[idx]
        if base <= va < base + self.regions[base].size:
            return base
        return None

    def read(self, va: int, size: int) -> bytes:
        out = bytearray(size)
        done = 0
        while done < size:
            cur = va + done
            base = self.find(cur)
            if base is None:
                done += 1
                continue
            region = self.regions[base]
            chunk = bytes(self.data[base][cur - base : cur - base + (size - done)])
            out[done : done + len(chunk)] = chunk
            done += len(chunk)
        return bytes(out)

    def write(self, va: int, data: bytes) -> int:
        written = 0
        while written < len(data):
            cur = va + written
            base = self.find(cur)
            if base is None:
                raise BackendError(f"unmapped address {cur:#x}")
            region = self.regions[base]
            avail = region.end - cur
            chunk = data[written : written + avail]
            self.data[base][cur - base : cur - base + len(chunk)] = chunk
            written += len(chunk)
        return written


class MockBackend(MemoryBackend):
    kind = "mock"
    caps = Capabilities(
        processes=True, modules=True, regions=True, threads=True, callstack=True,
        kernel=True, symbols=True, write=True, physical=True, handles=True, heaps=True,
    )

    def __init__(self, name: str = "mock") -> None:
        super().__init__(name)
        self.bits = 64
        self.spaces: dict[int, _Space] = {}
        self.processes: dict[int, ProcessInfo] = {}
        self.modules: dict[int, list[ModuleInfo]] = {}
        self.threads: dict[int, list[ThreadInfo]] = {}
        self.frames: dict[tuple[int, int], list[StackFrame]] = {}
        self.symbols: dict[tuple[int, str, str], int] = {}
        self.kernel_modules: list[ModuleInfo] = []
        self.kernel_processes: list[ProcessInfo] = []
        self.phys: dict[int, bytearray] = {}
        self.handles: dict[int, list[dict]] = {}
        self.heaps: dict[int, list[dict]] = {}

    # -- construction ------------------------------------------------------
    def add_process(self, pid: int, name: str, **kwargs) -> ProcessInfo:
        proc = ProcessInfo(pid=pid, name=name, **kwargs)
        self.processes[pid] = proc
        self.spaces[pid] = _Space()
        self.modules[pid] = []
        self.threads[pid] = []
        return proc

    def add_region(self, pid: int, base: int, data: bytes, protection: str = "rw-",
                   tag: str | None = None, module: str | None = None) -> Region:
        self._space(pid).map(base, data, protection=protection, tag=tag, module=module)
        return self._space(pid).regions[base & ~0xFFF]

    def add_module(self, pid: int, name: str, base: int, data: bytes, *,
                   entry: int | None = None, path: str | None = None) -> ModuleInfo:
        self._space(pid).map(base, data, protection="r-x", tag="MZ", module=name)
        module = ModuleInfo(
            pid=pid, name=name, base=base, size=len(data), entry=entry, path=path, file_size=len(data)
        )
        self.modules[pid].append(module)
        return module

    def add_thread(self, pid: int, tid: int, frames: list[StackFrame] | None = None, **kwargs) -> ThreadInfo:
        thread = ThreadInfo(pid=pid, tid=tid, **kwargs)
        self.threads[pid].append(thread)
        if frames is not None:
            self.frames[(pid, tid)] = frames
        return thread

    def add_symbol(self, pid: int, module: str, name: str, va: int) -> None:
        self.symbols[(pid, module, name)] = va

    def add_physical(self, pa: int, data: bytes) -> None:
        self.phys[pa] = bytearray(data)

    def _space(self, pid: int) -> _Space:
        try:
            return self.spaces[pid]
        except KeyError as exc:
            raise NotFound(f"no such process: {pid}") from exc

    # -- backend API -------------------------------------------------------
    def list_processes(self) -> list[ProcessInfo]:
        self.require_open()
        return list(self.processes.values())

    def list_modules(self, pid: int) -> list[ModuleInfo]:
        self.require_open()
        self._space(pid)
        return list(self.modules.get(pid, []))

    def list_regions(self, pid: int) -> list[Region]:
        self.require_open()
        return [self._space(pid).regions[b] for b in self._space(pid).order]

    def read(self, pid: int, va: int, size: int) -> bytes:
        self.require_open()
        if size < 0:
            raise BackendError("negative read size")
        return self._space(pid).read(va, size)

    def write(self, pid: int, va: int, data: bytes) -> int:
        self.require_open()
        return self._space(pid).write(va, data)

    def list_threads(self, pid: int) -> list[ThreadInfo]:
        self.require_open()
        self._space(pid)
        return list(self.threads.get(pid, []))

    def thread_callstack(self, pid: int, tid: int) -> list[StackFrame]:
        return list(self.frames.get((pid, tid), []))

    def read_physical(self, pa: int, size: int) -> bytes:
        if pa not in self.phys:
            raise BackendError(f"unmapped physical address {pa:#x}")
        buf = bytes(self.phys[pa])
        return buf[:size].ljust(size, b"\x00")

    def resolve_symbol(self, pid: int, module: str, name: str) -> int | None:
        return self.symbols.get((pid, module.lower(), name))

    def symbolize(self, pid: int, va: int) -> StackFrame | None:
        for module in self.modules.get(pid, []):
            if module.contains(va):
                return StackFrame(va=va, module=module.name, offset=va - module.base)
        return None

    def kernel_modules(self) -> list[ModuleInfo]:
        return list(self.kernel_modules)

    def kernel_processes(self) -> list[ProcessInfo]:
        return list(self.kernel_processes)

    def physical_map(self) -> list[Region]:
        return [Region(base=pa, size=len(buf), protection="rw-", kind="physical") for pa, buf in self.phys.items()]

    def list_handles(self, pid: int) -> list[dict]:
        return list(self.handles.get(pid, []))

    def list_heaps(self, pid: int) -> list[dict]:
        return list(self.heaps.get(pid, []))

    # -- convenience for tests --------------------------------------------
    def set_u64(self, pid: int, va: int, value: int) -> None:
        self.write(pid, va, struct.pack("<Q", value))
