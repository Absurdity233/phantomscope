"""Acquisition backend interface.

A backend is anything that can enumerate processes and read/write process
virtual memory.  The flagship implementation wraps MemProcFS (PCILeech FPGA,
memory dumps, remote LeechAgent, ...), but the same interface also drives the
mock backend used by tests and offline fixtures.

Optional capabilities are advertised through :class:`Capabilities` and have
default implementations raising :class:`~phantomscope.errors.Unavailable`, so a
backend only implements what its acquisition device actually supports.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from .errors import Unavailable
from .models import ModuleInfo, ProcessInfo, Region, StackFrame, ThreadInfo

MAX_IO = 64 * 1024 * 1024


@dataclass
class Capabilities:
    processes: bool = True
    modules: bool = False
    regions: bool = False
    threads: bool = False
    callstack: bool = False
    kernel: bool = False
    symbols: bool = False
    write: bool = False
    physical: bool = False
    handles: bool = False
    heaps: bool = False

    def to_dict(self) -> dict[str, bool]:
        return {
            "processes": self.processes,
            "modules": self.modules,
            "regions": self.regions,
            "threads": self.threads,
            "callstack": self.callstack,
            "kernel": self.kernel,
            "symbols": self.symbols,
            "write": self.write,
            "physical": self.physical,
            "handles": self.handles,
            "heaps": self.heaps,
        }


class MemoryBackend(ABC):
    """Abstract acquisition backend."""

    kind: str = "abstract"
    caps: Capabilities = Capabilities()

    def __init__(self, name: str = "default") -> None:
        self.name = name
        self._open = False
        self.notes: list[str] = []

    # -- lifecycle ---------------------------------------------------------
    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    @property
    def is_open(self) -> bool:
        return self._open

    def require_open(self) -> None:
        if not self._open:
            raise Unavailable(f"backend {self.name!r} is not open")

    # -- required ----------------------------------------------------------
    @abstractmethod
    def list_processes(self) -> list[ProcessInfo]:
        """Return every process visible in the memory image."""

    @abstractmethod
    def read(self, pid: int, va: int, size: int) -> bytes:
        """Read ``size`` bytes of process virtual memory at ``va``."""

    # -- optional ----------------------------------------------------------
    def write(self, pid: int, va: int, data: bytes) -> int:
        raise Unavailable("this backend is read-only")

    def list_modules(self, pid: int) -> list[ModuleInfo]:
        raise Unavailable("module enumeration is not supported by this backend")

    def list_regions(self, pid: int) -> list[Region]:
        raise Unavailable("region enumeration is not supported by this backend")

    def list_threads(self, pid: int) -> list[ThreadInfo]:
        raise Unavailable("thread enumeration is not supported by this backend")

    def thread_callstack(self, pid: int, tid: int) -> list[StackFrame]:
        raise Unavailable("callstack retrieval is not supported by this backend")

    def read_physical(self, pa: int, size: int) -> bytes:
        raise Unavailable("physical memory access is not supported by this backend")

    def resolve_symbol(self, pid: int, module: str, name: str) -> int | None:
        raise Unavailable("symbol resolution is not supported by this backend")

    def symbolize(self, pid: int, va: int) -> StackFrame | None:
        raise Unavailable("symbolisation is not supported by this backend")

    def kernel_modules(self) -> list[ModuleInfo]:
        raise Unavailable("kernel module enumeration is not supported by this backend")

    def kernel_processes(self) -> list[ProcessInfo]:
        raise Unavailable("kernel process enumeration is not supported by this backend")

    def physical_map(self) -> list[Region]:
        raise Unavailable("physical memory map is not supported by this backend")

    def list_handles(self, pid: int) -> list[dict]:
        raise Unavailable("handle enumeration is not supported by this backend")

    def list_heaps(self, pid: int) -> list[dict]:
        raise Unavailable("heap enumeration is not supported by this backend")

    def vads(self, pid: int) -> list[Region]:
        return self.list_regions(pid)

    # -- helpers -----------------------------------------------------------
    def find_process(self, ident: int | str) -> ProcessInfo | None:
        processes = self.list_processes()

        if isinstance(ident, int) or (isinstance(ident, str) and ident.strip().isdigit()):
            pid = int(ident)
            for proc in processes:
                if proc.pid == pid:
                    return proc
            return None

        needle = str(ident).lower()
        exact = [p for p in processes if p.name.lower() == needle]
        if exact:
            return exact[0]
        partial = [p for p in processes if needle in p.name.lower()]
        return partial[0] if len(partial) == 1 else None

    def module_for_va(self, pid: int, va: int) -> ModuleInfo | None:
        try:
            modules = self.list_modules(pid)
        except Unavailable:
            return None
        for module in modules:
            if module.contains(va):
                return module
        return None
