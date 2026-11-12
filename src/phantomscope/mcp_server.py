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
from .errors import InvalidArgument, NotFound, PhantomError
from .physical import PhysicalBackend
from .utils import hexdump, parse_address, parse_hex_bytes

SERVER_NAME = "phantomscope"

INSTRUCTIONS = """\
phantomscope is a DMA reverse-engineering toolkit.

Typical workflow
----------------
1. ``session_open`` (device="fpga" for a PCILeech FPGA, or a dump path).
2. ``processes`` to find a PID (or use ``attach`` with a name).
3. ``modules`` / ``regions`` / ``threads`` / ``callstack`` to orient, and
   ``handles`` / ``heaps`` / ``kernel_modules`` when the backend has them.
4. ``read`` (with dump=True) / ``read_typed`` / ``dump_region`` for memory,
   ``scan_aob`` / ``scan_value`` / ``scan_next`` / ``pointer_scan`` for discovery,
   ``write`` / ``patch_list`` / ``patch_restore`` for edits (journaled).
5. ``capture_module`` to hand a live module's bytes to the static analyser,
   then ``disassemble`` / ``functions`` / ``xrefs_to`` / ``basic_blocks``, and
   ``struct_layout`` / ``globals_touched`` to infer what the code expects its
   pointers to point at.
6. ``decompile`` for pseudo-C of one function, with ``api_calls`` and
   ``string_xrefs`` for the names it does not have.  ``rename_function`` and
   ``set_comment`` make those names stick: later calls report them.
7. ``fingerprint`` / ``find_similar`` / ``match_functions`` / ``diff_images``
   to recognise code across addresses and builds, and ``packing_report`` /
   ``crypto_constants`` / ``search_immediates`` for triage.
8. ``emu_create`` over a loaded image to snapshot-emulate it: ``emu_step``,
   ``emu_run``, ``emu_watch`` and ``emu_call`` stand in for breakpoints,
   which DMA cannot provide.  ``emu_stubs`` first when the code calls imports.

Static-only workflows (PE files) can start at ``load_file``.

For a raw physical image with no operating system involved, open
``session_open(backend="physical", device="<dump>")`` and use the physical
tools: ``physical_info`` / ``physical_map`` / ``physical_read`` /
``physical_write`` (addresses are physical), ``translate`` /
``virtual_read`` / ``virtual_write`` / ``walk`` (x86-64 page-table walking
with a CR3), ``physical_images`` (find PEs by structure alone) and
``capture_image`` (hand a discovered PE to the static engine).

Every dynamic tool needs a session; every static tool needs a loaded image
key (``images`` lists them).  Static images and emulators are scoped to the
session that captured them, so pass ``session="<name>"`` when several targets
are open; a bare key is still resolved against every engine.
"""


class _Context:
    """Per-process state shared by all tools.

    Every session owns its static engine, so images captured from one target
    cannot overwrite another's.  Static-only workflows (``load_file`` on a PE
    from disk) use a standalone engine that outlives any session.
    """

    def __init__(self) -> None:
        self.manager = SessionManager()
        self.standalone = StaticEngine()
        #: Emulators over images in the standalone engine (no session open).
        self.standalone_emulators: dict[str, Emulator] = {}

    def session(self, name: str | None = None) -> Session:
        return self.manager.get(name)

    def dynamic(self, name: str | None = None) -> DynamicEngine:
        session = self.session(name)
        return session.dynamic  # type: ignore[return-value]

    def backend(self, name: str | None = None) -> MemoryBackend:
        return self.session(name).backend

    def static(self, name: str | None = None) -> StaticEngine:
        """Engine belonging to ``name`` (default session when omitted).

        Falls back to the standalone engine when no session is open, which is
        what makes ``load_file`` usable without a DMA target.
        """
        target = name or self.manager.default
        if target is None:
            return self.standalone
        return self.manager.get(target).static

    def engine_for(self, key: str) -> StaticEngine:
        """Engine that owns ``key``; the default engine when nobody does."""
        for _name, engine in self.static_engines():
            if key in engine.images:
                return engine
        return self.static()

    def emulator_map(self, session: str | None = None) -> dict[str, Emulator]:
        """Emulators belonging to ``session``; the standalone map when none is open."""
        target = session or self.manager.default
        if target is None:
            return self.standalone_emulators
        return self.manager.get(target).emulators

    def emulator_map_for(self, key: str, session: str | None = None) -> dict[str, Emulator]:
        """Registry matching the engine that owns ``key``.

        Keeps an emulator next to the image it was built from, so ``load_file``
        without a session (standalone engine) does not leak emulators into a
        session that happens to be the default.
        """
        if session:
            return self.session(session).emulators
        engine = self.engine_for(key)
        if engine is self.standalone:
            return self.standalone_emulators
        for name, candidate in self.static_engines():
            if candidate is engine and name:
                return self.manager.get(name).emulators
        return self.emulator_map(None)

    def emulator_keys(self) -> list[str]:
        """Every emulator key in play, across sessions and the standalone engine."""
        keys = set(self.standalone_emulators)
        for session in self.manager.all():
            keys.update(session.emulators)
        return sorted(keys)

    def static_engines(self) -> list[tuple[str, StaticEngine]]:
        """Default session first, then the others, then the standalone engine."""
        sessions = self.manager.all()
        ordered = sorted(sessions, key=lambda s: s.name != self.manager.default)
        return [(s.name, s.static) for s in ordered] + [("", self.standalone)]

    def clear_static(self) -> None:
        """Drop every loaded image and emulator (tests and ``session_close``)."""
        for session in self.manager.all():
            session.static.images.clear()
            session.emulators.clear()
        self.standalone.images.clear()
        self.standalone_emulators.clear()

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


def _static_for(key: str, session: str = "") -> StaticEngine:
    """Engine holding ``key``.

    An explicit ``session`` always wins.  Otherwise every engine is searched, so
    a key captured in a named session stays reachable from a plain
    ``disassemble(key=...)`` call.
    """
    if session:
        return STATE.static(session)
    return STATE.engine_for(key)


def _claim_key(key: str, target: StaticEngine) -> None:
    """Refuse to reuse an image key that another engine already owns."""
    for name, engine in STATE.static_engines():
        if engine is target:
            continue
        if key in engine.images:
            where = f"session {name!r}" if name else "the standalone engine"
            raise InvalidArgument(
                f"image key {key!r} is already used in {where}; "
                "pass a different key or close that session first"
            )


def _drop_emulator(key: str) -> None:
    """Forget emulators built over an image that is being unloaded."""
    for session in STATE.manager.all():
        session.emulators.pop(key, None)
    STATE.standalone_emulators.pop(key, None)


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
# Kernel / handle / heap tools
# ---------------------------------------------------------------------------


@server.tool()
def kernel_modules(session: str = "default") -> str:
    """Kernel modules (drivers) loaded on the target, when the backend has a kernel view."""
    try:
        return _ok([m.to_dict() for m in STATE.backend(session).kernel_modules()])
    except Exception as exc:
        return _fail(exc)


@server.tool()
def kernel_processes(session: str = "default") -> str:
    """Processes seen by the kernel, including ones hidden from the user-mode list."""
    try:
        return _ok([p.to_dict() for p in STATE.backend(session).kernel_processes()])
    except Exception as exc:
        return _fail(exc)


@server.tool()
def handles(pid: int | None = None, filter: str = "", session: str = "default") -> str:
    """Handles open in a process; ``filter`` matches the type or name, case-insensitively."""
    try:
        entries = STATE.backend(session).list_handles(STATE.pid(pid, session))
        if filter:
            needle = filter.lower()
            entries = [
                entry for entry in entries
                if any(needle in str(value).lower() for value in entry.values())
            ]
        return _ok(entries)
    except Exception as exc:
        return _fail(exc)


@server.tool()
def heaps(pid: int | None = None, session: str = "default") -> str:
    """Heaps of a process."""
    try:
        return _ok(STATE.backend(session).list_heaps(STATE.pid(pid, session)))
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
def scan_strings(needle: str = "", min_length: int = 6, encoding: str = "both",
                 limit: int = 500, module_filter: str = "", pid: int | None = None,
                 session: str = "default") -> str:
    """Find readable strings in *live* memory — what the target built at run time.

    ``strings`` only reads an image on disk.  A URL after a redirect, a decrypted
    key, a JSON payload assembled on the heap exist only here.

    ``encoding="both"`` covers ASCII and UTF-16LE; wide strings are stored with a
    lower-case-only convention on Windows, so scanning only ASCII misses most
    user-visible text.
    """
    try:
        dynamic = STATE.dynamic(session)
        return _ok(dynamic.scan_strings(
            STATE.pid(pid, session), needle, min_length=int(min_length),
            limit=int(limit), encoding=encoding,
            region_filter=module_filter or None,
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
def scan_results(key: str, limit: int = 500, session: str = "default") -> str:
    """List the addresses currently held by a scan."""
    try:
        return _ok(STATE.dynamic(session).scan_results(key, limit=limit))
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
def trace_changes(va: str, size: int, samples: int = 8, interval: float = 0.02,
                  limit: int = 64, pid: int | None = None,
                  session: str = "default") -> str:
    """Poll a range and report every byte that moved, as hex and as typed values.

    This is the DMA answer to a memory breakpoint: nothing can be stopped, so the
    range is sampled and diffed.  Runs name the changed field, how many samples
    caught a new value, and the same bytes read as int32/uint32/float/int64/uint64/
    double, which is usually enough to tell a flag from a counter from a timer.
    """
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok(dynamic.trace_changes(p, dynamic.reparse(p, str(va)), int(size),
                                         samples=int(samples), interval=float(interval),
                                         limit=int(limit)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def trace_value(va: str, value_type: str = "uint32", samples: int = 8,
                interval: float = 0.02, pid: int | None = None,
                session: str = "default") -> str:
    """Time series for one typed value: the counter/timer/health-bar view."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok(dynamic.trace_value(p, dynamic.reparse(p, str(va)), value_type,
                                       samples=int(samples), interval=float(interval)))
    except Exception as exc:
        return _fail(exc)



@server.tool()
def read_object(va: str, size: int = 128, fields: str = "", pid: int | None = None,
                session: str = "default") -> str:
    """Dump one object: hexdump, aligned qwords with pointer validity, typed fields.

    ``fields`` takes ``"0x0:int32,0x8:pointer,0x10:char[16]"`` and decodes exactly
    those offsets, so a guessed layout can be checked instead of eyeballed.
    """
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok(dynamic.read_object(p, dynamic.reparse(p, str(va)), int(size),
                                       fields=fields or None))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def read_array(base: str, stride: int, count: int, fields: str = "", follow: bool = False,
               object_size: int = 64, limit: int = 128, pid: int | None = None,
               session: str = "default") -> str:
    """Read ``count`` objects ``stride`` bytes apart (``follow`` for ``Entity**``)."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok(dynamic.read_array(p, dynamic.reparse(p, str(base)), int(stride),
                                      int(count), fields=fields or None,
                                      follow=bool(follow), object_size=int(object_size),
                                      limit=int(limit)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def infer_struct(va: str, size: int = 64, stride: int = 0, count: int = 1, align: int = 8,
                 pid: int | None = None, session: str = "default") -> str:
    """Infer a field layout from sampled values and print a C declaration.

    ``count`` objects at ``stride`` are compared: a qword that is a mapped address
    every time is reported as a pointer, one whose high dword is always zero as
    int32, and fields that differ between objects are marked ``varies``.
    """
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok(dynamic.infer_struct(p, dynamic.reparse(p, str(va)), int(size),
                                        stride=int(stride) or None, count=int(count),
                                        align=int(align)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def detect_container(va: str, element_size: int = 0, pid: int | None = None,
                     session: str = "default") -> str:
    """Decide whether an address holds a std::vector, TArray, std::string, or other."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok(dynamic.detect_container(p, dynamic.reparse(p, str(va)),
                                            element_size=int(element_size) or None))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def expand_container(va: str, element_size: int = 0, fields: str = "", limit: int = 64,
                     pid: int | None = None, session: str = "default") -> str:
    """Detect a container and read its elements in one call (the entity-list workflow)."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok(dynamic.expand_container(p, dynamic.reparse(p, str(va)),
                                            element_size=int(element_size) or None,
                                            fields=fields or None, limit=int(limit)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def resolve_pointer_chain(base: str, offsets: str, value_type: str = "",
                          read_size: int = 0, pid: int | None = None,
                          session: str = "default") -> str:
    """Walk a pointer path and report every hop plus the final value.

    ``base`` is ``game.exe+0x1a2b`` or an address, ``offsets`` is ``"0x10,0x38,0x8"``:
    each offset is added before the next dereference and the last one selects the
    field.  A broken hop is reported with its address instead of a plausible zero.
    """
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        chain = [parse_address(piece) for piece in str(offsets).split(",") if piece.strip()]
        return _ok(dynamic.resolve_pointer_chain(p, str(base), chain,
                                                 value_type=value_type or None,
                                                 read_size=int(read_size)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def pointer_chain_replay(candidates: str, value_type: str = "", limit: int = 10,
                         pid: int | None = None, session: str = "default") -> str:
    """Re-run chains from ``pointer_scan`` (JSON) and keep the ones that resolve."""
    try:
        payload = json.loads(candidates)
        if isinstance(payload, dict):
            payload = payload.get("chains") or payload.get("result") or []
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok(dynamic.replay_pointer_chains(p, list(payload),
                                                 value_type=value_type or None,
                                                 limit=int(limit)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def snapshot_module(module: str, label: str = "", pid: int | None = None,
                    session: str = "default") -> str:
    """Snapshot every mapped region of a module (baseline for ``diff_module``)."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok(dynamic.snapshot_module(p, module, label=label or None))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def diff_module(module: str, snapshot_id: int = 0, limit: int = 200,
                pid: int | None = None, session: str = "default") -> str:
    """Compare a module's regions against a ``snapshot_module`` baseline."""
    try:
        dynamic = STATE.dynamic(session)
        p = STATE.pid(pid, session)
        return _ok(dynamic.diff_module(p, module, snapshot_id=int(snapshot_id) or None,
                                       limit=int(limit)))
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
    """Physical address ranges: the dump's segments, or the target's RAM map."""
    try:
        return _ok([r.to_dict() for r in STATE.backend(session).physical_map()])
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
    """Write bytes into a raw physical *dump file* on disk.

    Not a write to a live target: the physical backend backs a dump file, so this
    edits that file in place.  Use ``write`` for a live process.
    """
    try:
        backend = _physical(session)
        address = parse_address(pa)
        payload = bytes.fromhex(data.replace(" ", "").replace("0x", ""))
        return _ok({"pa": hex(address), "written": backend.write_physical(address, payload),
                    "target": "dump_file", "note": "modifies the image on disk, not a live target"})
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
        engine = STATE.static(session)
        _claim_key(image_key, engine)
        image = engine.load_capture(image_key, payload, base_va)
        return _ok({"key": image_key, "hit": hit.to_dict(), "base": hex(base_va),
                    "summary": image.summary()})
    except Exception as exc:
        return _fail(exc)


# ---------------------------------------------------------------------------
# Static tools
# ---------------------------------------------------------------------------


@server.tool()
def load_file(path: str, key: str = "", base: str = "", session: str = "") -> str:
    """Load a PE file from disk for static analysis.

    Files loaded without ``session`` go into the standalone engine, so a
    static-only workflow never depends on which DMA session happens to be open.
    """
    try:
        engine = STATE.static(session) if session else STATE.standalone
        image_key = key or os.path.abspath(path)
        _claim_key(image_key, engine)
        image = engine.load_file(
            path, key=image_key, base=parse_address(base) if base else None
        )
        return _ok({"key": image_key, "summary": image.summary()})
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
        engine = STATE.static(session)
        _claim_key(image_key, engine)
        image = engine.load_capture(image_key, data, info.base, path=info.path)
        return _ok({"key": image_key, "module": info.to_dict(), "summary": image.summary()})
    except Exception as exc:
        return _fail(exc)


@server.tool()
def export_module(module: str, path: str, pid: int | None = None, raw: bool = False,
                  session: str = "default") -> str:
    """Dump a live module to a PE file that IDA, Ghidra and pefile will open.

    The last mile of unpacking: capture the module, then write it somewhere useful.
    A memory buffer is RVA-indexed, so writing it out verbatim gives a file whose
    section headers no longer match where the bytes are — every tool rejects it.
    This demaps it: headers stay, each section moves from its virtual address to
    its declared raw offset.

    ``raw=True`` keeps the mapped layout instead, for byte-exact captures.
    """
    try:
        backend = STATE.backend(session)
        p = STATE.pid(pid, session)
        info = STATE.dynamic(session).resolve_module(p, module)
        engine = STATE.static(session)
        temporary = f"export:{p}:{info.name}"
        image = engine.load_capture(temporary, backend.read(p, info.base, info.size),
                                    info.base, path=info.path)
        try:
            result = image.save(path, raw=raw)
        finally:
            engine.unload(temporary)
        result.update({"module": info.name, "captured_size": info.size})
        return _ok(result)
    except Exception as exc:
        return _fail(exc)


@server.tool()
def save_image(key: str, path: str, raw: bool = False, session: str = "") -> str:
    """Write an already-loaded image to disk (same demap as ``export_module``)."""
    try:
        return _ok(_static_for(key, session).save_image(key, path, raw=raw))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def patch_apply(key: str, va: str, bytes: str, note: str = "",
                session: str = "") -> str:
    """Overwrite bytes in a loaded image, remembering the original for rollback.

    The static twin of ``write``: patch the *image* (which is where the code you
    disassembled actually lives), then ``save_image`` to demap it into a working
    file.  The cached function index is invalidated, so ``disassemble`` and
    ``decompile`` show the patched bytes immediately rather than the old ones.

    ``bytes`` takes hex: ``"EB"``, ``"EB 1C"`` or ``"EB1C"``.  A conditional
    branch is usually the target — ``74``/``75`` (jz/jnz) to ``EB`` (jmp) skips the
    failure path without changing instruction length.
    """
    try:
        data = parse_hex_bytes(bytes)
        engine = _static_for(key, session)
        return _ok(engine.apply_patch(key, parse_address(va), data, note=note or None))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def static_patch_list(session: str = "") -> str:
    """Every static image patch made through this engine, oldest first."""
    try:
        rows: list[dict] = []
        for name, engine in STATE.static_engines():
            for index, record in enumerate(engine.patch_list()):
                rows.append({**record, "session": name or None, "index": index})
        return _ok(rows)
    except Exception as exc:
        return _fail(exc)


@server.tool()
def static_patch_restore(key: str = "", index: int = -1, all: bool = False,
                         session: str = "") -> str:
    """Undo one static patch by index, or every outstanding patch with ``all=True``.

    ``key`` selects the image; without it the engine that owns any patch is used.
    """
    try:
        engine = _static_for(key, session) if key else STATE.static(session or None)
        return _ok(engine.patch_restore(None if index < 0 else index, all=bool(all)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def images(session: str = "") -> str:
    """List images loaded for static analysis (all engines when ``session`` is empty)."""
    if session:
        try:
            return _ok(STATE.static(session).keys())
        except Exception as exc:
            return _fail(exc)
    keys: list[str] = []
    for _name, engine in STATE.static_engines():
        for key in engine.keys():
            if key not in keys:
                keys.append(key)
    return _ok(sorted(keys))


@server.tool()
def unload_image(key: str, session: str = "") -> str:
    """Forget a loaded image and any emulator built over it."""
    removed = _static_for(key, session).unload(key)
    if removed:
        _drop_emulator(key)
    return _ok({"unloaded": removed})


@server.tool()
def image_summary(key: str, session: str = "") -> str:
    """Header/section/import/export summary of a loaded image."""
    try:
        return _ok(_static_for(key, session).summary(key))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def sections(key: str, session: str = "") -> str:
    """Sections of a loaded image."""
    try:
        return _ok(_static_for(key, session).sections(key))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def imports(key: str, module_filter: str = "", session: str = "") -> str:
    """Imports of a loaded image (optionally filtered by module)."""
    try:
        return _ok(_static_for(key, session).imports(key, module=module_filter or None))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def exports(key: str, session: str = "") -> str:
    """Exports of a loaded image."""
    try:
        return _ok(_static_for(key, session).exports(key))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def strings(key: str, min_length: int = 4, limit: int = 2000,
            include_code: bool = False, contains: str = "", session: str = "") -> str:
    """Extract strings; ``contains`` filters case-insensitively."""
    try:
        data = _static_for(key, session).strings(key, min_length=min_length, limit=limit,
                                                 include_code=include_code)
        if contains:
            needle = contains.lower()
            data = [item for item in data if needle in item["text"].lower()]
        return _ok(data)
    except Exception as exc:
        return _fail(exc)


@server.tool()
def functions(key: str, offset: int = 0, limit: int = 200, session: str = "") -> str:
    """List discovered functions with callers counts."""
    try:
        return _ok(_static_for(key, session).functions(key, offset=offset, limit=limit))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def function_info(key: str, va: str, session: str = "") -> str:
    """Function containing an address."""
    try:
        return _ok(_static_for(key, session).function_info(key, parse_address(va)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def disassemble(key: str, va: str = "", count: int = 40, function: bool = False,
                session: str = "") -> str:
    """Disassemble from an address, or a whole function when function=True."""
    try:
        return _ok(_static_for(key, session).disassemble(
            key, parse_address(va) if va else None, count=int(count), function=function
        ))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def basic_blocks(key: str, va: str, session: str = "") -> str:
    """Basic blocks of the function containing an address."""
    try:
        return _ok(_static_for(key, session).blocks(key, parse_address(va)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def xrefs_to(key: str, va: str, limit: int = 100, include_pointers: bool = True,
             session: str = "") -> str:
    """Cross references *to* an address."""
    try:
        return _ok(_static_for(key, session).xrefs_to(
            key, parse_address(va), limit=limit, include_pointers=include_pointers
        ))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def xrefs_from(key: str, va: str, limit: int = 200, session: str = "") -> str:
    """Cross references *from* an address."""
    try:
        return _ok(_static_for(key, session).xrefs_from(key, parse_address(va), limit=limit))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def callers(key: str, va: str, session: str = "") -> str:
    """Functions that call the function containing ``va``."""
    try:
        return _ok(_static_for(key, session).callers(key, parse_address(va)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def callees(key: str, va: str, session: str = "") -> str:
    """Functions called by the function containing ``va``."""
    try:
        return _ok(_static_for(key, session).callees(key, parse_address(va)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def scan_pattern(key: str, pattern: str, limit: int = 500, executable_only: bool = False,
                 session: str = "") -> str:
    """Scan a static image for an AOB pattern."""
    try:
        return _ok(_static_for(key, session).scan(
            key, pattern, limit=limit, executable_only=executable_only
        ))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def rtti(key: str, limit: int = 200, session: str = "") -> str:
    """MSVC RTTI classes and their vtables."""
    try:
        return _ok(_static_for(key, session).rtti(key, limit=limit))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def static_read(key: str, va: str, size: int = 64, session: str = "") -> str:
    """Read bytes from a loaded image."""
    try:
        return _ok(_static_for(key, session).read(key, parse_address(va), int(size)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def static_address_info(key: str, va: str, session: str = "") -> str:
    """Resolve an address inside a loaded image: section, function, symbol, flags.

    The static counterpart of ``address_info``; use it when the address came from
    an analysis result rather than from a live process.
    """
    try:
        return _ok(_static_for(key, session).address_info(key, parse_address(va)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def struct_layout(key: str, va: str, limit: int = 8000, session: str = "") -> str:
    """Infer candidate struct layouts from the memory operands a function uses.

    Every ``[rcx+0x10]`` observed becomes a field hypothesis at offset 0x10,
    sized by the access width.  Offsets are relative and the base is a *role*
    (arg0/arg1/...) or a register, because nothing proves which object the
    register holds.  Confirm hypotheses with ``read_typed`` against live memory.
    """
    try:
        return _ok(_static_for(key, session).struct_layout(
            key, parse_address(va), limit=int(limit)
        ))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def live_struct_layout(key: str, function: str, object_va: str, pid: int | None = None,
                       size: int = 64, stride: int = 0, count: int = 8, align: int = 4,
                       session: str = "") -> str:
    """Combine a function's field accesses with the live values at those offsets.

    ``struct_layout`` knows which offsets exist and how wide the accesses are, but
    not what is in them.  ``infer_struct`` knows what is in them, but not which
    offsets the code cares about.  This runs both and merges them: every offset is
    confirmed by code *and* typed by data, padding is dropped, a dword that reads as
    a sane float in every sample is declared ``float``, adjacent floats are grouped
    into a vector, and offsets seen in only one of the two are listed separately
    instead of being silently dropped.

    ``key`` is a loaded image (found in any engine), ``function`` is any address
    inside the function, and ``object_va`` is a live instance of the object that
    function's first argument points at.  ``session`` selects the live target; the
    image does not have to live in that session, so a sample loaded from disk works
    against whatever is attached.
    """
    try:
        static = STATE.engine_for(key)
        dynamic = STATE.dynamic(session or None)
        p = STATE.pid(pid, session or None)
        inferred = dynamic.infer_struct(p, dynamic.reparse(p, str(object_va)), int(size),
                                        stride=int(stride) or None, count=int(count),
                                        align=int(align))
        return _ok({
            "object": inferred["va"],
            "samples": inferred["samples"],
            "layouts": static.merge_layout(key, parse_address(function), inferred),
            "inferred_c_struct": inferred["c_struct"],
        })
    except Exception as exc:
        return _fail(exc)


@server.tool()
def globals_touched(key: str, va: str, limit: int = 2000, session: str = "") -> str:
    """Module globals (RIP-relative references) read or written by a function."""
    try:
        return _ok(_static_for(key, session).globals_touched(
            key, parse_address(va), limit=int(limit)
        ))
    except Exception as exc:
        return _fail(exc)


# ---------------------------------------------------------------------------
# Pseudo-C recovery, annotations
# ---------------------------------------------------------------------------


@server.tool()
def decompile(key: str, va: str, include_comments: bool = True, max_blocks: int = 1200,
              session: str = "") -> str:
    """Lift one function to readable pseudo-C.

    Control flow is rebuilt from the basic-block graph: dominators, natural loops
    and if/else joins become ``while`` / ``if`` statements instead of ``goto``,
    ``cmp`` + ``jcc`` pairs become conditions, ``arg0..arg3`` name the incoming
    register arguments, imports and string references are resolved through the
    image, and registers that hold ``rbp``-relative slots become locals.  Every
    line keeps the original instruction as a trailing comment, so the output can
    be checked against ``disassemble`` instead of trusted.

    Heuristics are stated in the response: ``confidence`` drops when blocks are
    unreachable, the graph is irreducible, or instructions stay unmodelled
    (SSE, string ops), and ``notes`` says why.  Pair with ``rename_function`` —
    the annotated name is used by later calls.
    """
    try:
        return _ok(_static_for(key, session).decompile(
            key, parse_address(va), include_comments=bool(include_comments),
            max_blocks=int(max_blocks),
        ))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def rename_function(key: str, va: str, name: str, session: str = "") -> str:
    """Name a function; every later tool reports that name instead of ``sub_x``.

    Names persist to ``<file>.phantomscope.json`` next to a PE loaded from disk,
    and live for the session otherwise (a memory capture has no local file).  The
    identifier must look like a symbol: ``decrypt_config``, ``?f@@YAXH@Z``.
    """
    try:
        return _ok(_static_for(key, session).rename_function(key, parse_address(va), name))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def set_comment(key: str, va: str, text: str, session: str = "") -> str:
    """Attach a comment to an address; ``disassemble`` shows it inline."""
    try:
        return _ok(_static_for(key, session).set_comment(key, parse_address(va), text))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def annotations(key: str, session: str = "") -> str:
    """List the names, comments and notes recorded for an image."""
    try:
        return _ok(_static_for(key, session).annotation_list(key))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def clear_annotations(key: str, va: str = "", session: str = "") -> str:
    """Drop the annotations for one address, or all of them when ``va`` is empty."""
    try:
        engine = _static_for(key, session)
        target = parse_address(va) if va else None
        return _ok(engine.clear_annotations(key, target))
    except Exception as exc:
        return _fail(exc)


# ---------------------------------------------------------------------------
# Import / string cross references
# ---------------------------------------------------------------------------


@server.tool()
def api_calls(key: str, va: str = "", limit: int = 2000, session: str = "") -> str:
    """Imported APIs called in an image (or in one function), grouped by API.

    Resolves ``call [rip+iat]`` and the ``mov reg,[iat]; call reg`` thunk form, so
    a stripped binary still tells you it talks to ``kernel32!CreateFileW``.  This
    is the fast way to classify an unknown function: crypto, network, registry,
    process injection.
    """
    try:
        return _ok(_static_for(key, session).api_calls(
            key, parse_address(va) if va else None, limit=int(limit)
        ))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def api_sites(key: str, va: str = "", limit: int = 2000, session: str = "") -> str:
    """Every API reference site with its address, function and reference kind."""
    try:
        return _ok(_static_for(key, session).api_sites(
            key, parse_address(va) if va else None, limit=int(limit)
        ))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def find_api(key: str, needle: str, limit: int = 200, session: str = "") -> str:
    """Functions that call an API matching ``needle`` (case-insensitive)."""
    try:
        return _ok(_static_for(key, session).find_api(key, needle, limit=int(limit)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def string_xrefs(key: str, contains: str = "", va: str = "", min_length: int = 4,
                 limit: int = 200, include_code: bool = True, session: str = "") -> str:
    """Strings and the code addresses that reference them.

    Narrow with ``contains`` (substring) or point at one string with ``va``.  A
    "licence expired" string with one caller is a much better lead than the caller
    list of an unnamed function.
    """
    try:
        return _ok(_static_for(key, session).string_refs(
            key, contains=contains, va=parse_address(va) if va else None,
            min_length=int(min_length), limit=int(limit), include_code=bool(include_code),
        ))
    except Exception as exc:
        return _fail(exc)


# ---------------------------------------------------------------------------
# Fingerprints, matching and diffing
# ---------------------------------------------------------------------------


@server.tool()
def fingerprint(key: str, va: str, session: str = "") -> str:
    """Structural fingerprint of a function (normalised hash, constants, imports).

    Relative branch targets and immediates are abstracted, so the same function
    hashes the same at another address or in another build; the immediates are
    kept separately in ``constants``.
    """
    try:
        return _ok(_static_for(key, session).fingerprint(key, parse_address(va)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def find_similar(key: str, va: str, limit: int = 10, min_similarity: float = 0.5,
                 session: str = "") -> str:
    """Functions in the same image that look like the one at ``va``.

    Similarity is the Jaccard index over mnemonic trigrams: explainable, and good
    at finding the four copies of the same routine a compiler inlined.
    """
    try:
        return _ok(_static_for(key, session).find_similar(
            key, parse_address(va), limit=int(limit), min_similarity=float(min_similarity)
        ))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def match_functions(left: str, right: str, min_similarity: float = 0.6, limit: int = 400,
                    session: str = "") -> str:
    """Match the functions of two loaded images (hash first, shape second)."""
    try:
        return _ok(_static_for(left, session).match_images(
            left, right, min_similarity=float(min_similarity), limit=int(limit)
        ))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def diff_images(left: str, right: str, min_similarity: float = 0.6,
                session: str = "") -> str:
    """Structural diff of two builds: identical, similar, removed and added code.

    Load both versions (``load_file`` twice), then this tells you exactly which
    functions changed — the shortest path from "new game build" to "the function
    they patched".
    """
    try:
        return _ok(_static_for(left, session).diff_images(
            left, right, min_similarity=float(min_similarity)
        ))
    except Exception as exc:
        return _fail(exc)


# ---------------------------------------------------------------------------
# Triage: packing, crypto constants, immediates
# ---------------------------------------------------------------------------


@server.tool()
def packing_report(key: str, session: str = "") -> str:
    """Evidence for packing or virtualisation, with a 0-10 score.

    Checks section entropy, writable+executable sections, sections with no file
    data, the import count, how much code the analyser actually recovered, TLS
    callbacks, entry-point placement and overlay data.  Each hit carries its
    weight and a one-line reason, so the verdict can be argued with.
    """
    try:
        return _ok(_static_for(key, session).packing_report(key))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def crypto_constants(key: str, limit: int = 40, session: str = "") -> str:
    """Locate known crypto/hash tables and round constants by value.

    AES S-box and its inverse, the CRC-32 table, MD5/SHA initial states, TEA and
    xxHash primes, FNV offsets, MurmurHash constants, base64 and hex alphabets.
    A hit means the bytes are there — treat it as a lead, not a proof.
    """
    try:
        return _ok(_static_for(key, session).crypto_constants(key, limit=int(limit)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def search_immediates(key: str, value: str, width: int = 4, limit: int = 200,
                      session: str = "") -> str:
    """Where a number is used: instruction immediates and stored data.

    Pass ``value`` as hex or decimal (``0x9e3779b9``, ``-1``, ``1033``).
    ``width`` picks the stored size (4 or 8).  This is how you find the
    ``cmp eax, 0x1e`` behind a trial limit or the constant in a hash loop.
    """
    try:
        parsed = parse_address(value)
        return _ok(_static_for(key, session).search_immediates(
            key, parsed, width=int(width), limit=int(limit)
        ))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def server_info() -> str:
    keys: list[str] = []
    for _name, engine in STATE.static_engines():
        for key in engine.keys():
            if key not in keys:
                keys.append(key)
    return _ok({"name": SERVER_NAME, "version": __version__, "sessions": STATE.manager.list(),
                "images": sorted(keys),
                "session_images": {name: engine.keys()
                                   for name, engine in STATE.static_engines() if name},
                "emulators": STATE.emulator_keys(),
                "emulation_available": emulator_available()})


# ---------------------------------------------------------------------------
# Snapshot emulation (registers, stepping, watchpoints)
# ---------------------------------------------------------------------------


def _emulators(session: str | None = None, key: str = "") -> dict[str, Emulator]:
    """Emulator registry that goes with the image ``key`` (or with ``session``)."""
    if key:
        return STATE.emulator_map_for(key, session or None)
    return STATE.emulator_map(session or None)


def _emulator(image_key: str, session: str | None = None) -> Emulator:
    emu = _emulators(session, image_key).get(image_key)
    if emu is None:
        where = f" in session {session!r}" if session else ""
        raise NotFound(f"no emulator for {image_key!r}{where}; call `emu_create` first")
    return emu


@server.tool()
def emu_available() -> str:
    """Whether snapshot emulation (Unicorn) is installed."""
    return _ok({"available": emulator_available()})


@server.tool()
def emu_create(key: str, rip: str = "", rsp: str = "", stack_size: int = 0x10000,
               stubs: bool = False, trace: bool = False, session: str = "") -> str:
    """Create an emulator over a loaded image (optionally seeding rip/rsp).

    ``stubs=True`` installs an import stub for every IAT slot up front, which is
    what lets ``emu_call`` run a real function that talks to the OS.
    ``trace=True`` starts recording executed instructions and taken edges (see
    ``emu_coverage``); it is off by default because a hook per instruction is slow.
    """
    try:
        image = _static_for(key, session).get(key)
        regs: dict[str, int] = {}
        if rip:
            regs["rip"] = parse_address(rip)
        if rsp:
            regs["rsp"] = parse_address(rsp)
        emu = emulator_for(image, regs=regs, stack_size=int(stack_size),
                           auto_stubs=bool(stubs), trace=bool(trace))
        previous = _emulators(session, key).get(key)
        if previous is not None:
            # Unicorn holds a native engine per instance; release it now instead
            # of leaving it to the collector during a later mem_map.
            previous.close()
        _emulators(session, key)[key] = emu
        state = emu.snapshot.state()
        state["stubs"] = len(emu.stubs())
        state["tracing"] = emu.coverage()["tracing"]
        return _ok(state)
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_regs(key: str, set: str = "", session: str = "") -> str:
    """Read (or set with ``rax=0x10,rcx=5``) emulator registers."""
    try:
        emu = _emulator(key, session)
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
def emu_step(key: str, count: int = 1, session: str = "") -> str:
    """Single-step the emulator (count instructions)."""
    try:
        return _ok(_emulator(key, session).step(int(count)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_run(key: str, until: str = "", max_steps: int = 200000, session: str = "") -> str:
    """Run until an address (``until``) or until the step budget is exhausted."""
    try:
        emu = _emulator(key, session)
        if until:
            return _ok(emu.run_until(parse_address(until), max_steps=int(max_steps)))
        return _ok(emu.run(max_steps=int(max_steps)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_read(key: str, va: str, size: int = 16, session: str = "") -> str:
    """Read emulator memory."""
    try:
        emu = _emulator(key, session)
        address = parse_address(va)
        data = emu.read(address, int(size))
        return _ok({"va": hex(address), "hex": data.hex(), "size": len(data)})
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_write(key: str, va: str, data: str, session: str = "") -> str:
    """Write emulator memory (hex)."""
    try:
        emu = _emulator(key, session)
        address = parse_address(va)
        emu.write(address, bytes.fromhex(data.replace(" ", "")))
        return _ok({"va": hex(address), "written": len(data.replace(" ", "")) // 2})
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_watch(key: str, va: str, kind: str = "write", size: int = 8,
              session: str = "") -> str:
    """Watch an emulator memory range for reads and/or writes."""
    try:
        emu = _emulator(key, session)
        address = parse_address(va)
        emu.watchpoint(address, kind=kind, size=int(size))
        return _ok({"watching": hex(address), "kind": kind, "size": size})
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_events(key: str, limit: int = 200, session: str = "") -> str:
    """Accesses recorded by emulator watchpoints."""
    try:
        return _ok(_emulator(key, session).watchpoints(limit=limit))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_call(key: str, va: str, args: str = "", max_steps: int = 200000,
             session: str = "") -> str:
    """Call a function in the emulator (x64 Microsoft calling convention).

    Imported functions fault unless their IAT slots were redirected: call
    ``emu_stubs`` first (or ``emu_create(stubs=True)``) so ``call kernel32!X``
    returns a value instead of stopping on an unmapped fetch.
    """
    try:
        emu = _emulator(key, session)
        parsed = [parse_address(piece) for piece in args.split(",") if piece.strip()]
        return _ok(emu.call(parse_address(va), parsed, max_steps=int(max_steps)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_stubs(key: str, returns: str = "", default: int = 0, session: str = "") -> str:
    """Redirect every import slot to a generated stub, so the code can keep running.

    A snapshot holds the image, not the module it imports from, so
    ``call qword ptr [rip+iat]`` would fault.  This rewrites each IAT slot to a
    ``mov eax, imm; ret`` stub in a mapped page and logs every hit.

    ``returns`` sets per-API return values: ``"Sleep=0,GetTickCount=0x64"`` or
    ``"kernel32.dll!CreateFileW=0x40"``; unlisted imports return ``default``.
    Driving a return value is how you take the success path through a check
    without patching the binary.
    """
    try:
        emu = _emulator(key, session)
        wanted: dict[str, int] = {}
        for pair in returns.split(","):
            if not pair.strip():
                continue
            name, _, raw = pair.partition("=")
            if not raw:
                raise InvalidArgument(f"expected name=value, got {pair!r}")
            wanted[name.strip()] = parse_address(raw)
        return _ok(emu.install_import_stubs(returns=wanted, default=parse_address(default)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_calls(key: str, limit: int = 200, session: str = "") -> str:
    """Imported functions the emulator actually called, with argument registers."""
    try:
        return _ok(_emulator(key, session).import_calls(limit=int(limit)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_stub_list(key: str, session: str = "") -> str:
    """Installed import stubs with the value each one returns."""
    try:
        return _ok(_emulator(key, session).stubs())
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_close(key: str, session: str = "") -> str:
    """Release an emulator and its native engine.

    Worth calling when you are done with a large image: unicorn holds memory per
    instance, and a session that creates emulators in a loop will grow until they
    are closed.
    """
    try:
        emulators = _emulators(session, key)
        emu = emulators.pop(key, None)
        if emu is None:
            raise NotFound(f"no emulator for key {key!r}")
        return _ok(emu.close())
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_trace(key: str, action: str = "start", max_addresses: int = 200000,
              session: str = "") -> str:
    """Turn instruction/edge recording on, off, or reset it.

    recording costs a callback per instruction, so it is opt-in: enable it when
    the question is *which path did the run take*, not when you need a value.
    """
    try:
        emu = _emulator(key, session)
        kind = action.strip().lower()
        if kind == "start":
            return _ok(emu.start_trace(max_addresses=int(max_addresses)))
        if kind == "stop":
            return _ok(emu.stop_trace())
        if kind == "reset":
            return _ok(emu.reset_trace())
        raise InvalidArgument("action must be start, stop or reset")
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_coverage(key: str, hot: int = 20, session: str = "") -> str:
    """What the emulated run executed: unique instructions, hot spots, branch forks.

    ``forks`` are the addresses that had more than one successor — i.e. the branch
    decisions actually taken, which answers "did the check pass" and "which case
    of the switch ran".
    """
    try:
        return _ok(_emulator(key, session).coverage(hot=int(hot)))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_reached(key: str, addresses: str, session: str = "") -> str:
    """Which of the listed addresses the emulated run actually reached."""
    try:
        wanted = [parse_address(piece) for piece in str(addresses).split(",") if piece.strip()]
        return _ok(_emulator(key, session).reached(wanted))
    except Exception as exc:
        return _fail(exc)


@server.tool()
def emu_faults(key: str, limit: int = 20, session: str = "") -> str:
    """Bad accesses seen in the emulator: unmapped read/write/fetch with rip and address."""
    try:
        return _ok(_emulator(key, session).faults(limit=int(limit)))
    except Exception as exc:
        return _fail(exc)


def main() -> None:
    """Run the MCP server over stdio."""
    server.run()


if __name__ == "__main__":
    main()
