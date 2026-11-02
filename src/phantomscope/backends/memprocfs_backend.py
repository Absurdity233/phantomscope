"""MemProcFS / PCILeech DMA backend.

This is the live-memory implementation.  It talks to whatever acquisition
device MemProcFS supports (``-device fpga`` for a PCILeech FPGA, a memory dump
path, ``pmem``, a remote LeechAgent, ...).

A note on the API surface: MemProcFS is an acquisition library, not a debugger.
It can read and write memory and enumerate threads/callstacks, but it cannot
stop a thread, read its register context or single-step it.  Those capabilities
are provided by the snapshot emulator in :mod:`phantomscope.dynamic.emulator`,
and this backend deliberately exposes only what DMA can really do.
"""

from __future__ import annotations

import os
from typing import Any, Iterable

from ..backend import Capabilities, MemoryBackend
from ..errors import BackendError, NotFound, Unavailable
from ..models import ModuleInfo, ProcessInfo, Region, StackFrame, ThreadInfo


def _pick(mapping: Any, *keys: str, default: Any = None) -> Any:
    """Read the first present key from a dict-like or attribute-like object."""
    if mapping is None:
        return default
    for key in keys:
        try:
            if isinstance(mapping, dict):
                if key in mapping:
                    return mapping[key]
            elif hasattr(mapping, key):
                return getattr(mapping, key)
        except Exception:
            continue
    return default


def _as_int(value: Any, default: int | None = None) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_str(value: Any, default: str | None = None) -> str | None:
    if value is None:
        return default
    try:
        text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    except Exception:
        return default
    return text.strip() or default


class MemProcFsBackend(MemoryBackend):
    kind = "memprocfs"
    caps = Capabilities(
        processes=True,
        modules=True,
        regions=True,
        threads=True,
        callstack=True,
        kernel=True,
        symbols=True,
        write=True,
        physical=True,
        handles=True,
        heaps=True,
    )

    def __init__(
        self,
        device: str = "fpga",
        options: Iterable[str] | None = None,
        *,
        name: str = "dma",
        forensic: int = 0,
        wait_initialize: bool = False,
    ) -> None:
        super().__init__(name)
        self.device = self._normalise_device(device)
        self.options = [str(o) for o in (options or [])]
        self.forensic = int(forensic or 0)
        self.wait_initialize = wait_initialize
        self._vmm: Any = None
        self.bits: int | None = None

    @staticmethod
    def _normalise_device(device: str) -> str:
        text = str(device).strip()
        # Be forgiving about common spellings.
        aliases = {"dma": "fpga", "pcie": "fpga", "usb": "usb3380"}
        low = text.lower()
        if low in aliases:
            return aliases[low]
        if low.startswith("file://") or os.path.sep in text:
            return text
        return text

    # -- lifecycle ---------------------------------------------------------
    def open(self) -> None:
        if self.is_open:
            return
        try:
            import memprocfs  # type: ignore
        except Exception as exc:  # pragma: no cover - depends on host
            raise Unavailable(
                "the memprocfs Python package is not installed; run "
                "`pip install memprocfs` (Windows only)"
            ) from exc

        args = ["-device", self.device]
        if self.forensic:
            args += ["-forensic", str(self.forensic)]
        if self.wait_initialize:
            args.append("-waitinitialize")
        args += self.options

        try:
            self._vmm = memprocfs.Vmm(args)
        except Exception as exc:  # pragma: no cover - depends on hardware
            raise BackendError(
                f"failed to initialise MemProcFS with device {self.device!r}",
                detail=self._init_hint(str(exc)),
            ) from exc

        try:
            self.bits = int(self._vmm.bits)
        except Exception:
            self.bits = None
        self._open = True

    @staticmethod
    def _init_hint(message: str) -> str:
        hint = (
            "Check that the FPGA is powered, the USB/Thunderbolt cable is connected, "
            "the PCILeech firmware is flashed and the target machine is unlocked. "
            "For offline analysis pass a memory dump path as the device."
        )
        return f"{message.strip()} | {hint}" if message else hint

    def close(self) -> None:
        if self._vmm is not None:
            try:
                self._vmm.close()
            except Exception:
                pass
        self._vmm = None
        self._open = False

    def _require(self) -> Any:
        self.require_open()
        if self._vmm is None:  # pragma: no cover - defensive
            raise BackendError("MemProcFS handle is not initialised")
        return self._vmm

    def _process(self, pid: int) -> Any:
        vmm = self._require()
        try:
            proc = vmm.process(int(pid))
        except Exception as exc:
            raise BackendError(f"cannot open process {pid}: {exc}") from exc
        if proc is None:
            raise NotFound(f"no such process: {pid}")
        return proc

    # -- processes ---------------------------------------------------------
    def list_processes(self) -> list[ProcessInfo]:
        vmm = self._require()
        out: list[ProcessInfo] = []
        try:
            raw = vmm.process_list()
        except Exception as exc:
            raise BackendError(f"process enumeration failed: {exc}") from exc
        for entry in raw or []:
            pid = _as_int(_pick(entry, "pid", "PID"))
            if pid is None:
                continue
            name = _as_str(_pick(entry, "name", "Name"), default=f"pid_{pid}") or f"pid_{pid}"
            cmdline = None
            try:
                cmd = _pick(entry, "cmdline", "cmd_line")
                cmdline = _as_str(cmd() if callable(cmd) else cmd)
            except Exception:
                cmdline = None
            out.append(
                ProcessInfo(
                    pid=pid,
                    name=name,
                    ppid=_as_int(_pick(entry, "ppid", "PPID")),
                    path=_as_str(_pick(entry, "pathuser", "path", "fullname")),
                    cmdline=cmdline,
                    eprocess=_as_int(_pick(entry, "eprocess", "va-eprocess")),
                    wow64=bool(_pick(entry, "is_wow64", "wow64", default=False)),
                    session=_as_int(_pick(entry, "session", "Session")),
                    integrity=_as_str(_pick(entry, "integrity")),
                    state=_as_str(_pick(entry, "state")),
                    dtb=_as_int(_pick(entry, "dtb", "dtb_user")),
                )
            )
        return out

    def list_modules(self, pid: int) -> list[ModuleInfo]:
        proc = self._process(pid)
        try:
            raw = proc.module_list()
        except Exception as exc:
            raise BackendError(f"module enumeration failed for pid {pid}: {exc}") from exc
        out: list[ModuleInfo] = []
        for entry in raw or []:
            base = _as_int(_pick(entry, "base", "va-base"))
            name = _as_str(_pick(entry, "name", "shortname"))
            if base is None or not name:
                continue
            out.append(
                ModuleInfo(
                    pid=pid,
                    name=name,
                    base=base,
                    size=_as_int(_pick(entry, "image_size", "cb", "size"), default=0) or 0,
                    entry=_as_int(_pick(entry, "entry", "va-entry")),
                    path=_as_str(_pick(entry, "fullname", "path")),
                    file_size=_as_int(_pick(entry, "file_size")),
                    wow64=bool(_pick(entry, "is_wow64", default=False)),
                )
            )
        out.sort(key=lambda m: m.base)
        return out

    # -- memory ------------------------------------------------------------
    def read(self, pid: int, va: int, size: int) -> bytes:
        proc = self._process(pid)
        try:
            data = proc.memory.read(int(va), int(size))
        except Exception as exc:
            raise BackendError(f"read failed at {va:#x} ({size} bytes): {exc}") from exc
        if data is None:
            raise BackendError(f"read failed at {va:#x} ({size} bytes): no data returned")
        data = bytes(data)
        if len(data) < size:
            # MemProcFS zero-pads failed pages; make that explicit to callers.
            data = data.ljust(size, b"\x00")
        return data

    def write(self, pid: int, va: int, data: bytes) -> int:
        proc = self._process(pid)
        try:
            ok = proc.memory.write(int(va), bytes(data))
        except Exception as exc:
            raise BackendError(f"write failed at {va:#x}: {exc}") from exc
        if ok is False:
            raise BackendError(f"write failed at {va:#x}: target refused the write")
        return len(data)

    def read_physical(self, pa: int, size: int) -> bytes:
        vmm = self._require()
        try:
            data = vmm.memory.read(int(pa), int(size))
        except Exception as exc:
            raise BackendError(f"physical read failed at {pa:#x}: {exc}") from exc
        return bytes(data or b"").ljust(size, b"\x00")

    # -- regions -----------------------------------------------------------
    def list_regions(self, pid: int) -> list[Region]:
        proc = self._process(pid)
        raw: Any = []
        for getter in ("vad", "vad_ex"):
            try:
                fn = getattr(proc.maps, getter)
                raw = fn() or []
                if raw:
                    break
            except Exception:
                continue

        regions: list[Region] = []
        for entry in raw:
            base = _as_int(_pick(entry, "va", "base", "va-start", "address"))
            size = _as_int(_pick(entry, "cb", "size", "cb-size", "pages"))
            if base is None or size is None:
                continue
            regions.append(
                Region(
                    base=base,
                    size=size,
                    protection=_as_str(_pick(entry, "Protection", "protection", "protect"), default="---") or "---",
                    tag=_as_str(_pick(entry, "Tag", "tag", "type")),
                    module=_as_str(_pick(entry, "Module", "module")),
                    kind=_as_str(_pick(entry, "Tag", "tag")),
                )
            )

        if not regions:
            # Fall back to module images so scanners still have something useful.
            try:
                for module in self.list_modules(pid):
                    regions.append(
                        Region(
                            base=module.base,
                            size=module.size,
                            protection="r-x",
                            tag="IMAGE",
                            module=module.name,
                            kind="image",
                        )
                    )
            except Unavailable:
                pass
        regions.sort(key=lambda r: r.base)
        return regions

    # -- threads -----------------------------------------------------------
    def list_threads(self, pid: int) -> list[ThreadInfo]:
        proc = self._process(pid)
        try:
            raw = proc.maps.thread() or []
        except Exception as exc:
            raise BackendError(f"thread enumeration failed for pid {pid}: {exc}") from exc
        out: list[ThreadInfo] = []
        for entry in raw:
            tid = _as_int(_pick(entry, "tid", "TID", "tid-owner"))
            if tid is None:
                continue
            state = _pick(entry, "state", "State")
            if isinstance(state, int):
                state = hex(state)
            out.append(
                ThreadInfo(
                    pid=pid,
                    tid=tid,
                    state=_as_str(state),
                    priority=_as_int(_pick(entry, "priority", "Priority")),
                    teb=_as_int(_pick(entry, "va-teb", "teb")),
                    start=_as_int(_pick(entry, "va-start", "va-win32start", "start")),
                    stack_base=_as_int(_pick(entry, "va-stackbase", "stackbase")),
                    stack_limit=_as_int(_pick(entry, "va-stacklimit", "stacklimit")),
                    ethread=_as_int(_pick(entry, "va-ethread", "ethread")),
                )
            )
        return out

    def thread_callstack(self, pid: int, tid: int) -> list[StackFrame]:
        proc = self._process(pid)
        try:
            raw = proc.maps.thread_callstack(int(tid)) or []
        except Exception as exc:
            raise BackendError(f"callstack retrieval failed for tid {tid}: {exc}") from exc
        frames: list[StackFrame] = []
        for index, entry in enumerate(raw):
            va = _as_int(_pick(entry, "va", "va-retaddr", "va-rsp", "reg-rip", "addr"))
            if va is None:
                continue
            rip = _as_int(_pick(entry, "reg-rip", "rip"))
            role = "rip" if index == 0 and rip else ("return" if _pick(entry, "va-retaddr") else None)
            module = _as_str(_pick(entry, "va-module", "module", "Module"))
            function = _as_str(_pick(entry, "va-fn", "function", "Function"))
            offset = _as_int(_pick(entry, "va-ofs", "va-offset", "offset"))
            symbol = None
            if function:
                symbol = f"{module}!{function}" if module else function
            frames.append(
                StackFrame(va=va, module=module, function=function, offset=offset, symbol=symbol, role=role)
            )
        return frames

    # -- symbols -----------------------------------------------------------
    def resolve_symbol(self, pid: int, module: str, name: str) -> int | None:
        proc = self._process(pid)
        try:
            mod = proc.module(module)
        except Exception:
            mod = None
        if mod is None:
            return None
        try:
            address = mod.procaddress(name)
            if address:
                return int(address)
        except Exception:
            pass
        try:
            address = mod.pdb.symbol_address(name)
            if address:
                return int(address)
        except Exception:
            pass
        return None

    def symbolize(self, pid: int, va: int) -> StackFrame | None:
        module = self.module_for_va(pid, va)
        if module is None:
            return None
        offset = va - module.base
        symbol = None
        try:
            proc = self._process(pid)
            mod = proc.module(module.name)
            symbol = _as_str(mod.pdb.symbol_name(offset))
        except Exception:
            symbol = None
        return StackFrame(va=va, module=module.name, offset=offset, symbol=symbol)

    # -- kernel / physical -------------------------------------------------
    def kernel_modules(self) -> list[ModuleInfo]:
        vmm = self._require()
        try:
            proc = vmm.kernel.process
            raw = proc.module_list() or []
        except Exception as exc:
            raise BackendError(f"kernel module enumeration failed: {exc}") from exc
        out: list[ModuleInfo] = []
        for entry in raw:
            base = _as_int(_pick(entry, "base", "va-base"))
            name = _as_str(_pick(entry, "name", "shortname"))
            if base is None or not name:
                continue
            out.append(
                ModuleInfo(
                    name=name,
                    base=base,
                    size=_as_int(_pick(entry, "image_size", "cb", "size"), default=0) or 0,
                    entry=_as_int(_pick(entry, "entry", "va-entry")),
                    path=_as_str(_pick(entry, "fullname", "path")),
                )
            )
        out.sort(key=lambda m: m.base)
        return out

    def kernel_processes(self) -> list[ProcessInfo]:
        return self.list_processes()

    def physical_map(self) -> list[Region]:
        vmm = self._require()
        try:
            raw = vmm.maps.memmap() or []
        except Exception as exc:
            raise BackendError(f"physical map enumeration failed: {exc}") from exc
        out: list[Region] = []
        for entry in raw:
            base = _as_int(_pick(entry, "pa", "base", "address", "va"))
            size = _as_int(_pick(entry, "cb", "size"))
            if base is None or size is None:
                continue
            out.append(
                Region(
                    base=base,
                    size=size,
                    protection="rw-",
                    tag=_as_str(_pick(entry, "type", "tag", "Type")),
                    kind="physical",
                )
            )
        out.sort(key=lambda r: r.base)
        return out

    def drivers(self) -> list[dict]:
        vmm = self._require()
        try:
            return [self._plain(d) for d in (vmm.maps.kdriver() or [])]
        except Exception as exc:
            raise BackendError(f"driver enumeration failed: {exc}") from exc

    # -- handles / heaps ---------------------------------------------------
    def list_handles(self, pid: int) -> list[dict]:
        proc = self._process(pid)
        try:
            return [self._plain(h) for h in (proc.maps.handle() or [])]
        except Exception as exc:
            raise BackendError(f"handle enumeration failed for pid {pid}: {exc}") from exc

    def list_heaps(self, pid: int) -> list[dict]:
        proc = self._process(pid)
        try:
            return [self._plain(h) for h in (proc.maps.heap() or [])]
        except Exception as exc:
            raise BackendError(f"heap enumeration failed for pid {pid}: {exc}") from exc

    @staticmethod
    def _plain(entry: Any) -> dict:
        if isinstance(entry, dict):
            out = {}
            for key, value in entry.items():
                if isinstance(value, bytes):
                    value = value.decode("utf-8", "replace")
                elif isinstance(value, (int, float, str)) or value is None:
                    pass
                else:
                    value = str(value)
                out[str(key)] = value
            return out
        return {"value": str(entry)}
