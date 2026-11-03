"""MCP server for phantomscope.

Exposes the static and dynamic engines as MCP tools over stdio.

Run with::

    phantomscope-mcp                 # entry point installed by pip
    python -m phantomscope.mcp_server

The server keeps one :class:`SessionManager` for the process lifetime, so a
client can open a DMA session once and then issue many tool calls against it.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

from mcp.server.mcpserver import MCPServer

from . import __version__
from .analysis.engine import StaticEngine
from .backend import MemoryBackend
from .backends.factory import create_backend
from .dynamic.engine import DynamicEngine
from .dynamic.emulator import Emulator, emulator_available, emulator_for
from .dynamic.session import Session, SessionManager
from .errors import InvalidArgument, PhantomError
from .physical import PhysicalBackend
from .utils import hexdump, parse_address

SERVER_NAME = "phantomscope"

INSTRUCTIONS = """\
phantomscope is a DMA reverse-engineering toolkit.

Typical workflow
----------------
1. ``session_open`` (device="fpga" for a PCILeech FPGA, or a dump path).
2. ``processes`` to find a PID (or use ``attach`` with a name).
3. ``modules`` / ``regions`` / ``threads`` / ``callstack`` to orient.
4. ``read`` (with dump=True) / ``read_typed`` / ``dump_region`` for memory,
   ``scan_aob`` / ``scan_value`` / ``scan_next`` / ``pointer_scan`` for discovery,
   ``write`` / ``patch_list`` / ``patch_restore`` for edits (journaled).
5. ``capture_module`` to hand a live module's bytes to the static analyser,
   then ``disassemble`` / ``functions`` / ``xrefs_to`` / ``basic_blocks``, and
   ``struct_layout`` / ``globals_touched`` to infer what the code expects its
   pointers to point at.
6. ``emu_create`` over a loaded image to snapshot-emulate it: ``emu_step``,
   ``emu_run``, ``emu_watch`` and ``emu_call`` stand in for breakpoints,
   which DMA cannot provide.

Static-only workflows (PE files) can start at ``load_file``.

For a raw physical image with no operating system involved, open
``session_open(backend="physical", device="<dump>")`` and use the physical
tools: ``physical_info`` / ``physical_map`` / ``physical_read`` /
``physical_write`` (addresses are physical), ``translate`` /
``virtual_read`` / ``virtual_write`` / ``walk`` (x86-64 page-table walking
with a CR3), ``physical_images`` (find PEs by structure alone) and
``capture_image`` (hand a discovered PE to the static engine).

Every dynamic tool needs a session; every static tool needs a loaded image
key (``images`` lists them).
"""


class _Context:
    """Per-process state shared by all tools."""

    def __init__(self) -> None:
        self.manager = SessionManager()
        self.static = StaticEngine()

    def session(self, name: str | None = None) -> Session:
        return self.manager.get(name)

    def dynamic(self, name: str | None = None) -> DynamicEngine:
        session = self.session(name)
        return session.dynamic  # type: ignore[return-value]

    def backend(self, name: str | None = None) -> MemoryBackend:
        return self.session(name).backend

    def pid(self, pid: int | None, session: str | None = None) -> int:
        if pid is not None:
            return int(pid)
        attached = self.session(session).attached_pid
        if attached is None:
            raise PhantomError("no pid given and no process attached; call `attach` first")
        return attached


STATE = _Context()
server = MCPServer(name=SERVER_NAME, version=__version__, instructions=INSTRUCTIONS)


def _ok(payload: Any) -> str:
    return json.dumps(payload, indent=2, default=str, ensure_ascii=False)


def _fail(exc: Exception) -> str:
    if isinstance(exc, PhantomError):
        return json.dumps(exc.to_dict(), indent=2, ensure_ascii=False)
    return json.dumps({"error": type(exc).__name__, "message": str(exc)}, indent=2)


# ---------------------------------------------------------------------------
# Session tools
# ---------------------------------------------------------------------------


@server.tool()
def session_open(
    device: str = "fpga",
    name: str = "default",
    backend: str = "memprocfs",
    options: str = "",
    forensic: int = 0,
    wait_initialize: bool = False,
) -> str:
    """Open a memory acquisition session.

    device: "fpga" (PCILeech), a memory dump path, "pmem", "usb3380", a
    LeechAgent remote ("rpc://host"), or "mock" for a deterministic test target
    when backend="mock".  options is a space-separated list of extra MemProcFS
    arguments.
    """
    try:
        extra = options.split() if options else []
        session = STATE.manager.open(
            name=name,
            kind=backend,
            device=device,
            options=extra,
            forensic=forensic,
            wait_initialize=wait_initialize,
        )
        return _ok(session.info())
    except Exception as exc:
        return _fail(exc)


@server.tool()
def session_list() -> str:
    """List open sessions."""
    return _ok(STATE.manager.list())


@server.tool()
def session_close(name: str | None = None) -> str:
    """Close a session (all sessions when name is omitted)."""
    if name is None:
        STATE.manager.close_all()
        return _ok({"closed": "all"})
    return _ok({"closed": name, "ok": STATE.manager.close(name)})


@server.tool()
def attach(process: str, session: str = "default") -> str:
    """Attach to a process by PID or name and make it the default target."""
    try:
        backend = STATE.backend(session)
        ident: int | str = int(process) if process.strip().isdigit() else process
        found = backend.find_process(ident)
        if found is None:
            return _ok({"error": "not_found", "message": f"no process matching {process!r}"})
        STATE.session(session).attached_pid = found.pid
        return _ok({"attached": found.to_dict(), "session": session})
    except Exception as exc:
        return _fail(exc)


# ---------------------------------------------------------------------------
# Process / module / thread tools
# ---------------------------------------------------------------------------


@server.tool()
def processes(name_filter: str = "", session: str = "default") -> str:
    """List processes, optionally filtered by name."""
    try:
        dynamic = STATE.dynamic(session)
        return _ok(dynamic.list_processes(name=name_filter or None))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def process_info(pid: int | None = None, session: str = "default") -> str:
    """Detailed information about one process."""
    try:
        dynamic = STATE.dynamic(session)
        return _ok(dynamic.process_info(STATE.pid(pid, session)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def modules(pid: int | None = None, name_filter: str = "", session: str = "default") -> str:
    """List loaded modules of a process."""
    try:
        dynamic = STATE.dynamic(session)
        return _ok(dynamic.list_modules(STATE.pid(pid, session), name=name_filter or None))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def regions(pid: int | None = None, session: str = "default") -> str:
    """List memory regions (VADs) of a process."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok([r.to_dict() for r in dynamic._regions(p)])
    except Exception as exc:
        return _fail(exc)


@server.tool()
def threads(pid: int | None = None, session: str = "default") -> str:
    """List threads of a process."""
    try:
        dynamic = STATE.dynamic(session)
        return _ok(dynamic.threads(STATE.pid(pid, session)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def callstack(tid: int, pid: int | None = None, session: str = "default") -> str:
    """Return the callstack of a thread."""
    try:
        dynamic = STATE.dynamic(session)
        return _ok(dynamic.callstack(STATE.pid(pid, session), tid))
    except Exception as exc:
        return _fail(exc)


# ---------------------------------------------------------------------------
# Memory tools
# ---------------------------------------------------------------------------


@server.tool()
def read(va: str, size: int = 64, pid: int | None = None, dump: bool = True,
         session: str = "default") -> str:
    """Read process virtual memory. ``va`` may be ``0x1234`` or ``module+0x10``."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        address = dynamic.reparse(p, str(va))
        return _ok(dynamic.read(p, address, int(size), dump=dump))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def read_typed(va: str, value_type: str = "uint64", pid: int | None = None,
               session: str = "default") -> str:
    """Read a typed value (int8..uint64, float, double)."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok(dynamic.read_typed(p, dynamic.reparse(p, str(va)), value_type))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def write(va: str, data: str = "", value: str = "", value_type: str = "",
          pid: int | None = None, note: str = "", session: str = "default") -> str:
    """Write bytes or a typed value. Every write is journaled and reversible."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        address = dynamic.reparse(p, str(va))
        parsed_value: Any = None
        if value:
            parsed_value = float(value) if value_type in ("float", "double") else int(value, 0)
        return _ok(
            dynamic.write(
                p,
                address,
                data=data or None,
                value=parsed_value,
                value_type=value_type or None,
                note=note or None,
            )
        )
    except Exception as exc:
        return _fail(exc)


@server.tool()
def patch_list(pid: int | None = None, session: str = "default") -> str:
    """List every write made through this session."""
    try:
        return _ok(STATE.dynamic(session).patches(pid=pid))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def patch_restore(patch_id: int = 0, all: bool = False, pid: int | None = None,
                  session: str = "default") -> str:
    """Restore one patch by id, or every outstanding patch with all=True."""
    try:
        dynamic = STATE.dynamic(session)
        if all:
            return _ok(dynamic.restore_all(pid=pid))
        return _ok(dynamic.restore_patch(int(patch_id)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def address_info(va: str, pid: int | None = None, session: str = "default") -> str:
    """Resolve an address to module/region/function information."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok(dynamic.address_info(p, dynamic.reparse(p, str(va))))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def dump_region(va: str, size: int, pid: int | None = None, out_path: str = "",
                session: str = "default") -> str:
    """Dump a memory range to a file (or return its hex when out_path is empty)."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        base = dynamic.reparse(p, str(va))
        data = dynamic.dump_region(p, base, int(size))
        if out_path:
            with open(out_path, "wb") as handle:
                handle.write(data)
            return _ok({"path": os.path.abspath(out_path), "size": len(data)})
        return _ok({"va": hex(base), "size": len(data), "hex": data.hex()})
    except Exception as exc:
        return _fail(exc)


# ---------------------------------------------------------------------------
# Scanning tools
# ---------------------------------------------------------------------------


@server.tool()
def scan_aob(pattern: str, pid: int | None = None, limit: int = 200,
             module_filter: str = "", session: str = "default") -> str:
    """Scan live process memory for an AOB pattern (``48 8B ?? E8``)."""
    try:
        dynamic = STATE.dynamic(session)
        return _ok(dynamic.scan_aob(
            STATE.pid(pid, session), pattern, limit=limit, region_filter=module_filter or None
        ))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def scan_value(value: str, value_type: str = "uint32", pid: int | None = None,
               label: str = "", limit: int = 200000, module_filter: str = "",
               session: str = "default") -> str:
    """First value scan. Returns a scan key used by scan_next."""
    try:
        dynamic = STATE.dynamic(session)
        parsed: Any = float(value) if value_type in ("float", "double") else int(value, 0)
        return _ok(dynamic.scan_value(
            STATE.pid(pid, session), parsed, value_type, label=label or None,
            limit=limit, region_filter=module_filter or None,
        ))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def scan_next(key: str, value: str = "", changed: bool = False,
              session: str = "default") -> str:
    """Narrow a previous scan to addresses still holding (or no longer holding) a value."""
    try:
        dynamic = STATE.dynamic(session)
        state = dynamic._scans.get(key)
        if state is None:
            return _ok({"error": "not_found", "message": f"unknown scan {key!r}"})
        parsed: Any = None
        if value:
            parsed = float(value) if state.value_type in ("float", "double") else int(value, 0)
        if changed:
            return _ok(dynamic.scan_changed(key, limit=200000))
        return _ok(dynamic.scan_next(key, parsed))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def scan_results(key: str, limit: int = 500) -> str:
    """List the addresses currently held by a scan."""
    try:
        return _ok(STATE.dynamic().scan_results(key, limit=limit))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def pointer_scan(target: str, pid: int | None = None, max_depth: int = 3,
                 module: str = "", session: str = "default") -> str:
    """Find module+offset pointer chains that point at a target address."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        target_va = dynamic.reparse(p, str(target))
        return _ok(dynamic.pointer_scan(p, target_va, max_depth=max_depth,
                                       module=module or None))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def snapshot(va: str, size: int, pid: int | None = None, label: str = "",
             session: str = "default") -> str:
    """Take a memory snapshot."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok(dynamic.snapshot(p, dynamic.reparse(p, str(va)), int(size),
                                    label=label or None))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def diff(va: str, size: int, pid: int | None = None, timeout: float = 0.0,
         session: str = "default") -> str:
    """Show what changed in a range since now (or watch it for ``timeout`` seconds)."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok(dynamic.diff(p, base=dynamic.reparse(p, str(va)), size=int(size),
                                timeout=float(timeout)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def watch(va: str, value_type: str = "uint32", pid: int | None = None,
          timeout: float = 5.0, session: str = "default") -> str:
    """Poll one address until its value changes."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok(dynamic.watch_values(p, [dynamic.reparse(p, str(va))], value_type,
                                       timeout=float(timeout)))
    except Exception as exc:
        return _fail(exc)


# ---------------------------------------------------------------------------
# Physical / DMA-native tools (no operating system assumed)
# ---------------------------------------------------------------------------


def _physical(session: str | None = None) -> PhysicalBackend:
    backend = STATE.backend(session)
    if not isinstance(backend, PhysicalBackend):
        name = session or "default"
        raise InvalidArgument(
            f"session {name!r} uses the {backend.kind!r} backend; physical tools need "
            "session_open(backend='physical', device='<dump path>')"
        )
    return backend


@server.tool()
def physical_info(session: str = "default") -> str:
    """Geometry of the open physical image: segments, size, CR3, cache state."""
    try:
        return _ok(_physical(session).info())
    except Exception as exc:
        return _fail(exc)


@server.tool()
def physical_map(session: str = "default") -> str:
    """Physical address ranges present in the image."""
    try:
        return _ok([r.to_dict() for r in _physical(session).physical_map()])
    except Exception as exc:
        return _fail(exc)


@server.tool()
def physical_read(pa: str, size: int = 64, dump: bool = True, session: str = "default") -> str:
    """Read physical memory. Bytes outside every captured segment read as zeros."""
    try:
        backend = _physical(session)
        address = parse_address(pa)
        data = backend.read_physical(address, int(size))
        payload: dict[str, Any] = {"pa": hex(address), "size": len(data), "hex": data.hex()}
        if dump:
            payload["dump"] = hexdump(data, base=address)
        return _ok(payload)
    except Exception as exc:
        return _fail(exc)


@server.tool()
def physical_write(pa: str, data: str, session: str = "default") -> str:
    """Write physical memory (hex). This changes the image file on disk."""
    try:
        backend = _physical(session)
        address = parse_address(pa)
        payload = bytes.fromhex(data.replace(" ", "").replace("0x", ""))
        return _ok({"pa": hex(address), "written": backend.write_physical(address, payload)})
    except Exception as exc:
        return _fail(exc)


@server.tool()
def translate(va: str, cr3: str = "", levels: int = 4, session: str = "default") -> str:
    """Translate a virtual address through page tables (defaults to the session CR3)."""
    try:
        backend = _physical(session)
        address = parse_address(va)
        base = parse_address(cr3) if cr3 else None
        pa = backend.translate(address, cr3=base, levels=int(levels))
        used = hex(base) if base else (hex(backend.cr3) if backend.cr3 else None)
        return _ok({"va": hex(address), "pa": hex(pa) if pa is not None else None,
                    "mapped": pa is not None, "cr3": used})
    except Exception as exc:
        return _fail(exc)


@server.tool()
def virtual_read(va: str, size: int = 64, cr3: str = "", levels: int = 4,
                 strict: bool = True, dump: bool = True, session: str = "default") -> str:
    """Read virtual memory through page tables. strict=False zero-fills holes."""
    try:
        backend = _physical(session)
        address = parse_address(va)
        base = parse_address(cr3) if cr3 else None
        data = backend.read_virtual(address, int(size), cr3=base, levels=int(levels),
                                    strict=bool(strict))
        payload: dict[str, Any] = {"va": hex(address), "size": len(data), "hex": data.hex()}
        if dump:
            payload["dump"] = hexdump(data, base=address)
        return _ok(payload)
    except Exception as exc:
        return _fail(exc)


@server.tool()
def virtual_write(va: str, data: str, cr3: str = "", levels: int = 4,
                  session: str = "default") -> str:
    """Write virtual memory through page tables (hex)."""
    try:
        backend = _physical(session)
        address = parse_address(va)
        base = parse_address(cr3) if cr3 else None
        payload = bytes.fromhex(data.replace(" ", "").replace("0x", ""))
        return _ok({"va": hex(address),
                    "written": backend.write_virtual(address, payload, cr3=base,
                                                     levels=int(levels))})
    except Exception as exc:
        return _fail(exc)


@server.tool()
def walk(va: str, size: int, cr3: str = "", levels: int = 4, step: int = 0x1000,
         limit: int = 4096, session: str = "default") -> str:
    """Report which pages in a virtual range are present (no OS structures used)."""
    try:
        backend = _physical(session)
        base = parse_address(cr3) if cr3 else None
        pages = backend.walk(parse_address(va), int(size), cr3=base, levels=int(levels),
                             step=int(step), limit=int(limit))
        return _ok({"present": len(pages), "pages": pages})
    except Exception as exc:
        return _fail(exc)


@server.tool()
def physical_images(limit: int = 200, refresh: bool = False, session: str = "default") -> str:
    """Find PE images in physical memory by structure alone (no module list)."""
    try:
        hits = _physical(session).images(limit=int(limit), refresh=bool(refresh))
        return _ok([hit.to_dict() for hit in hits])
    except Exception as exc:
        return _fail(exc)


@server.tool()
def physical_scan(pattern: str, limit: int = 200, start: str = "", size: int = 0,
                  session: str = "default") -> str:
    """AOB-scan physical memory (``48 8B ?? E8``). Hits are physical addresses."""
    try:
        hits = _physical(session).scan(
            pattern,
            limit=int(limit),
            start=parse_address(start) if start else None,
            size=int(size) or None,
        )
        return _ok({"count": len(hits), "hits": hits})
    except Exception as exc:
        return _fail(exc)


@server.tool()
def capture_image(pa: str, key: str = "", size: int = 0, base: str = "",
                  session: str = "default") -> str:
    """Capture a PE found at a physical address and load it for static analysis.

    The loaded image is based at the PE ``ImageBase`` unless ``base`` overrides
    it, so reported addresses match the image's own view of itself.
    """
    try:
        backend = _physical(session)
        address = parse_address(pa)
        payload, base_va, hit = backend.capture_image(
            address, size=int(size) or None, base_va=parse_address(base) if base else None
        )
        image_key = key or f"phys_{hit.pa:x}"
        image = STATE.static.load_capture(image_key, payload, base_va)
        return _ok({"key": image_key, "hit": hit.to_dict(), "base": hex(base_va),
                    "summary": image.summary()})
    except Exception as exc:
        return _fail(exc)


# ---------------------------------------------------------------------------
# Static tools
# ---------------------------------------------------------------------------


@server.tool()
def load_file(path: str, key: str = "", base: str = "") -> str:
    """Load a PE file from disk for static analysis."""
    try:
        image = STATE.static.load_file(path, key=key or None,
                                       base=parse_address(base) if base else None)
        return _ok({"key": key or os.path.abspath(path), "summary": image.summary()})
    except Exception as exc:
        return _fail(exc)


@server.tool()
def capture_module(module: str, pid: int | None = None, key: str = "",
                   session: str = "default") -> str:
    """Capture a live module through DMA and load it for static analysis."""
    try:
        backend = STATE.backend(session)
        p = STATE.pid(pid, session)
        info = STATE.dynamic(session).resolve_module(p, module)
        data = backend.read(p, info.base, info.size)
        image_key = key or f"{p}:{info.name}"
        image = STATE.static.load_capture(image_key, data, info.base, path=info.path)
        return _ok({"key": image_key, "module": info.to_dict(), "summary": image.summary()})
    except Exception as exc:
        return _fail(exc)


@server.tool()
def images() -> str:
    """List images loaded for static analysis."""
    return _ok(STATE.static.keys())


@server.tool()
def unload_image(key: str) -> str:
    """Forget a loaded image."""
    return _ok({"unloaded": STATE.static.unload(key)})


@server.tool()
def image_summary(key: str) -> str:
    """Header/section/import/export summary of a loaded image."""
    try:
        return _ok(STATE.static.summary(key))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def sections(key: str) -> str:
    """Sections of a loaded image."""
    try:
        return _ok(STATE.static.sections(key))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def imports(key: str, module_filter: str = "") -> str:
    """Imports of a loaded image (optionally filtered by module)."""
    try:
        return _ok(STATE.static.imports(key, module=module_filter or None))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def exports(key: str) -> str:
    """Exports of a loaded image."""
    try:
        return _ok(STATE.static.exports(key))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def strings(key: str, min_length: int = 4, limit: int = 2000,
            include_code: bool = False, contains: str = "") -> str:
    """Extract strings; ``contains`` filters case-insensitively."""
    try:
        data = STATE.static.strings(key, min_length=min_length, limit=limit,
                                    include_code=include_code)
        if contains:
            needle = contains.lower()
            data = [item for item in data if needle in item["text"].lower()]
        return _ok(data)
    except Exception as exc:
        return _fail(exc)


@server.tool()
def functions(key: str, offset: int = 0, limit: int = 200) -> str:
    """List discovered functions with callers counts."""
    try:
        return _ok(STATE.static.functions(key, offset=offset, limit=limit))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def function_info(key: str, va: str) -> str:
    """Function containing an address."""
    try:
        return _ok(STATE.static.function_info(key, parse_address(va)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def disassemble(key: str, va: str = "", count: int = 40, function: bool = False) -> str:
    """Disassemble from an address, or a whole function when function=True."""
    try:
        return _ok(STATE.static.disassemble(
            key, parse_address(va) if va else None, count=int(count), function=function
        ))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def basic_blocks(key: str, va: str) -> str:
    """Basic blocks of the function containing an address."""
    try:
        return _ok(STATE.static.blocks(key, parse_address(va)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def xrefs_to(key: str, va: str, limit: int = 100, include_pointers: bool = True) -> str:
    """Cross references *to* an address."""
    try:
        return _ok(STATE.static.xrefs_to(key, parse_address(va), limit=limit,
                                        include_pointers=include_pointers))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def xrefs_from(key: str, va: str, limit: int = 200) -> str:
    """Cross references *from* an address."""
    try:
        return _ok(STATE.static.xrefs_from(key, parse_address(va), limit=limit))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def callers(key: str, va: str) -> str:
    """Functions that call the function containing ``va``."""
    try:
        return _ok(STATE.static.callers(key, parse_address(va)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def callees(key: str, va: str) -> str:
    """Functions called by the function containing ``va``."""
    try:
        return _ok(STATE.static.callees(key, parse_address(va)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def scan_pattern(key: str, pattern: str, limit: int = 500, executable_only: bool = False) -> str:
    """Scan a static image for an AOB pattern."""
    try:
        return _ok(STATE.static.scan(key, pattern, limit=limit, executable_only=executable_only))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def rtti(key: str, limit: int = 200) -> str:
    """MSVC RTTI classes and their vtables."""
    try:
        return _ok(STATE.static.rtti(key, limit=limit))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def static_read(key: str, va: str, size: int = 64) -> str:
    """Read bytes from a loaded image."""
    try:
        return _ok(STATE.static.read(key, parse_address(va), int(size)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def static_address_info(key: str, va: str) -> str:
    """Resolve an address inside a loaded image."""
    try:
        return _ok(STATE.static.address_info(key, parse_address(va)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def struct_layout(key: str, va: str, limit: int = 8000) -> str:
    """Infer candidate struct layouts from the memory operands a function uses.

    Every ``[rcx+0x10]`` observed becomes a field hypothesis at offset 0x10,
    sized by the access width.  Offsets are relative and the base is a *role*
    (arg0/arg1/...) or a register, because nothing proves which object the
    register holds.  Confirm hypotheses with ``read_typed`` against live memory.
    """
    try:
        return _ok(STATE.static.struct_layout(key, parse_address(va), limit=int(limit)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def globals_touched(key: str, va: str, limit: int = 2000) -> str:
    """Module globals (RIP-relative references) read or written by a function."""
    try:
        return _ok(STATE.static.globals_touched(key, parse_address(va), limit=int(limit)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def server_info() -> str:
    """Server version and state summary."""
    return _ok({"name": SERVER_NAME, "version": __version__, "sessions": STATE.manager.list(),
                "images": STATE.static.keys(), "emulators": sorted(_EMULATORS),
                "emulation_available": emulator_available()})


# ---------------------------------------------------------------------------
# Snapshot emulation (registers, stepping, watchpoints)
# ---------------------------------------------------------------------------


_EMULATORS: dict[str, Emulator] = {}


def _emulator(image_key: str) -> Emulator:
    emu = _EMULATORS.get(image_key)
    if emu is None:
        raise PhantomError(
            f"no emulator for {image_key!r}; call `emu_create` first"
        )
    return emu


@server.tool()
def emu_available() -> str:
    """Whether snapshot emulation (Unicorn) is installed."""
    return _ok({"available": emulator_available()})


@server.tool()
def emu_create(key: str, rip: str = "", rsp: str = "", stack_size: int = 0x10000) -> str:
    """Create an emulator over a loaded image (optionally seeding rip/rsp)."""
    try:
        image = STATE.static.get(key)
        regs: dict[str, int] = {}
        if rip:
            regs["rip"] = parse_address(rip)
        if rsp:
            regs["rsp"] = parse_address(rsp)
        emu = emulator_for(image, regs=regs)
        _EMULATORS[key] = emu
        return _ok(emu.snapshot.state())
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_regs(key: str, set: str = "") -> str:
    """Read (or set with ``rax=0x10,rcx=5``) emulator registers."""
    try:
        emu = _emulator(key)
        if set:
            values: dict[str, int] = {}
            for pair in set.split(","):
                if not pair.strip():
                    continue
                name, _, raw = pair.partition("=")
                values[name.strip()] = parse_address(raw)
            emu.write_regs(values)
        return _ok({k: hex(v) for k, v in emu.read_regs().items()})
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_step(key: str, count: int = 1) -> str:
    """Single-step the emulator (count instructions)."""
    try:
        return _ok(_emulator(key).step(int(count)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_run(key: str, until: str = "", max_steps: int = 200000) -> str:
    """Run until an address (``until``) or until the step budget is exhausted."""
    try:
        emu = _emulator(key)
        if until:
            return _ok(emu.run_until(parse_address(until), max_steps=int(max_steps)))
        return _ok(emu.run(max_steps=int(max_steps)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_read(key: str, va: str, size: int = 16) -> str:
    """Read emulator memory."""
    try:
        emu = _emulator(key)
        address = parse_address(va)
        data = emu.read(address, int(size))
        return _ok({"va": hex(address), "hex": data.hex(), "size": len(data)})
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_write(key: str, va: str, data: str) -> str:
    """Write emulator memory (hex)."""
    try:
        emu = _emulator(key)
        address = parse_address(va)
        emu.write(address, bytes.fromhex(data.replace(" ", "")))
        return _ok({"va": hex(address), "written": len(data.replace(" ", "")) // 2})
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_watch(key: str, va: str, kind: str = "write", size: int = 8) -> str:
    """Watch an emulator memory range for reads and/or writes."""
    try:
        emu = _emulator(key)
        address = parse_address(va)
        emu.watchpoint(address, kind=kind, size=int(size))
        return _ok({"watching": hex(address), "kind": kind, "size": size})
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_events(key: str, limit: int = 200) -> str:
    """Accesses recorded by emulator watchpoints."""
    try:
        return _ok(_emulator(key).watchpoints(limit=limit))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_call(key: str, va: str, args: str = "", max_steps: int = 200000) -> str:
    """Call a function in the emulator (x64 Microsoft calling convention)."""
    try:
        emu = _emulator(key)
        parsed = [parse_address(piece) for piece in args.split(",") if piece.strip()]
        return _ok(emu.call(parse_address(va), parsed, max_steps=int(max_steps)))
    except Exception as exc:
        return _fail(exc)


def main() -> None:
    """Run the MCP server over stdio."""
    server.run()


if __name__ == "__main__":
    main()
