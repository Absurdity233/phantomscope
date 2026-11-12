"""Dynamic analysis on top of a memory backend.

The engine provides the operations that are *possible* over DMA, and is honest
about the ones that are not:

* memory read / write with a patch journal (every write is reversible),
* module and region enumeration, VA-to-module resolution,
* thread listing and callstacks,
* typed value scanning with narrowing (first scan / next scan),
* AOB scanning inside a live process,
* pointer-chain resolution from a static base to a heap address,
* snapshots and diffs (the "cheat table"-style workflow),
* live structure recovery: object dumps, stride arrays, field inference and
  ``std::vector`` / ``TArray`` expansion (:mod:`.structures`),
* write tracing by sampling, the substitute for memory breakpoints (:mod:`.trace`),
* pointer paths you can replay: scan → resolve → read the field (:mod:`.pointer`),

Snapshot emulation (register context, single stepping) lives in
:mod:`phantomscope.dynamic.emulator` and is optional.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from .. import utils
from ..backend import MemoryBackend
from ..errors import BackendError, InvalidArgument, NotFound, Unavailable
from ..models import (
    ModuleInfo,
    PatchRecord,
    ProcessInfo,
    Region,
    ScanHit,
    SnapshotRecord,
    StackFrame,
    ThreadInfo,
)
from ..analysis.scan import parse_pattern, scan_bytes
from . import pointer as chains
from . import structures, trace

MAX_SCAN_BYTES = 512 * 1024 * 1024
DEFAULT_SCAN_CHUNK = 4 * 1024 * 1024

#: Bytes that continue a printable ASCII run (tab is common in config blobs).
_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09}


def _iter_strings(data: bytes, unit: int, min_length: int):
    """Yield printable runs from ``data``, one code unit at a time.

    ``unit=2`` walks UTF-16LE and requires the high byte of every character to be
    zero — that is what distinguishes a real wide string from the same bytes read
    as garbage, and it is how every wide string on Windows is stored.

    The wide walk tries *both* byte alignments.  A string is only aligned to two
    relative to the allocation it was built in, and a heap buffer does not
    generally start at an even offset inside the region we happened to read, so an
    even-only walk silently misses roughly half of all wide strings.
    """
    length = len(data)
    phases = (0,) if unit == 1 else (0, 1)
    seen: set[int] = set()
    for phase in phases:
        index = phase
        start = -1
        while index + unit <= length:
            low = data[index]
            ok = low in _PRINTABLE and (unit == 1 or data[index + 1] == 0)
            if ok:
                if start < 0:
                    start = index
                index += unit
                continue
            if start >= 0 and (index - start) // unit >= min_length and start not in seen:
                seen.add(start)
                yield {"offset": start,
                       "length": (index - start) // unit,
                       "text": data[start:index:unit].decode("ascii", "replace")}
            start = -1
            index += unit
        if start >= 0 and (length - start) // unit >= min_length and start not in seen:
            seen.add(start)
            yield {"offset": start,
                   "length": (length - start) // unit,
                   "text": data[start:length:unit].decode("ascii", "replace")}


@dataclass
class ScanState:
    """Persistent state for narrowing scans."""
    pid: int
    value_type: str
    addresses: list[int]
    created: float
    label: str | None = None


@dataclass
class Snapshot:
    record: SnapshotRecord
    data: bytes = b""


class DynamicEngine:
    def __init__(self, backend: MemoryBackend) -> None:
        self.backend = backend
        self._patches: list[PatchRecord] = []
        self._snapshots: dict[int, Snapshot] = {}
        self._scans: dict[str, ScanState] = {}
        self._module_snaps: dict[int, dict] = {}
        self._next_patch = 1
        self._next_snapshot = 1
        self._next_module_snap = 1

    # -- helpers -----------------------------------------------------------
    def _read(self, pid: int, va: int, size: int) -> bytes:
        if size <= 0:
            return b""
        return self.backend.read(pid, va, size)

    def _regions(self, pid: int) -> list[Region]:
        return self.backend.list_regions(pid)

    def _module_for(self, pid: int, va: int) -> ModuleInfo | None:
        return self.backend.module_for_va(pid, va)

    # -- discovery ---------------------------------------------------------
    def list_processes(self, *, name: str | None = None) -> list[dict]:
        processes = self.backend.list_processes()
        if name:
            needle = name.lower()
            processes = [p for p in processes if needle in p.name.lower()]
        return [p.to_dict() for p in processes]

    def process_info(self, pid: int) -> dict:
        proc = self.backend.find_process(pid)
        if proc is None:
            raise NotFound(f"no such process: {pid}")
        out = proc.to_dict()
        try:
            out["modules"] = len(self.backend.list_modules(pid))
        except Unavailable:
            pass
        try:
            out["threads"] = len(self.backend.list_threads(pid))
        except Unavailable:
            pass
        try:
            regions = self._regions(pid)
            out["regions"] = len(regions)
            out["mapped_bytes"] = sum(r.size for r in regions)
        except Unavailable:
            pass
        return out

    def list_modules(self, pid: int, *, name: str | None = None) -> list[dict]:
        modules = self.backend.list_modules(pid)
        if name:
            needle = name.lower()
            modules = [m for m in modules if needle in m.name.lower()]
        return [m.to_dict() for m in modules]

    def resolve_module(self, pid: int, name: str) -> ModuleInfo:
        needle = name.lower()
        for module in self.backend.list_modules(pid):
            if module.name.lower() == needle:
                return module
        for module in self.backend.list_modules(pid):
            if needle in module.name.lower():
                return module
        raise NotFound(f"module {name!r} is not loaded in pid {pid}")

    # -- address translation ----------------------------------------------
    def address_info(self, pid: int, va: int) -> dict:
        info: dict = {"pid": pid, "va": hex(va)}
        module = self._module_for(pid, va)
        if module:
            info["module"] = module.name
            info["module_base"] = hex(module.base)
            info["module_offset"] = f"{va - module.base:#x}"
        for region in self._regions(pid):
            if region.contains(va):
                info["region"] = region.to_dict()
                info["readable"] = "r" in region.protection.lower()
                info["writable"] = "w" in region.protection.lower()
                info["executable"] = "x" in region.protection.lower()
                break
        try:
            frame = self.backend.symbolize(pid, va)
            if frame:
                info["symbol"] = frame.to_dict()
        except Unavailable:
            pass
        return info

    def reparse(self, pid: int, expression: str) -> int:
        """Convert ``module+0x1234`` or plain hex/decimal to a VA."""
        text = expression.strip()
        if "+" in text:
            module_name, _, offset = text.rpartition("+")
            module = self.resolve_module(pid, module_name)
            return module.base + utils.parse_address(offset, name="offset")
        return utils.parse_address(text)

    # -- public accessors for the analysis helpers -------------------------
    # `structures`, `trace` and `pointer` need read/region/module lookups but not
    # the rest of this class; these thin wrappers keep them out of the private
    # attributes instead of copying the logic.
    def read_bytes(self, pid: int, va: int, size: int) -> bytes:
        return self._read(pid, va, size)

    def regions(self, pid: int) -> list[Region]:
        return self._regions(pid)

    def module_for(self, pid: int, va: int) -> ModuleInfo | None:
        return self._module_for(pid, va)

    # -- memory ------------------------------------------------------------
    def read(self, pid: int, va: int, size: int, *, dump: bool = False) -> dict:
        data = self._read(pid, va, size)
        out = {"pid": pid, "va": hex(va), "size": len(data), "hex": data.hex()}
        if dump:
            out["dump"] = utils.hexdump(data, va)
        return out

    def read_typed(self, pid: int, va: int, value_type: str) -> dict:
        size = utils.value_type_size(value_type)
        data = self._read(pid, va, size)
        if len(data) < size:
            raise BackendError(f"short read at {va:#x}")
        value = utils.unpack_value(data, value_type)
        return {"pid": pid, "va": hex(va), "type": value_type, "value": value,
                "hex": data.hex()}

    def write(self, pid: int, va: int, *, data: str | None = None,
              value: str | int | float | None = None, value_type: str | None = None,
              note: str | None = None) -> dict:
        if data is not None:
            payload = utils.parse_hex_bytes(data)
        elif value is not None and value_type:
            payload = utils.pack_value(value, value_type)
        else:
            raise InvalidArgument("provide either `data` (hex) or `value` + `value_type`")
        if not payload:
            raise InvalidArgument("refusing to write zero bytes")
        original = self._read(pid, va, len(payload))
        written = self.backend.write(pid, va, payload)
        record = PatchRecord(
            id=self._next_patch,
            pid=pid,
            va=va,
            size=written,
            original=original.hex(),
            current=payload.hex(),
            note=note,
            created=time.time(),
        )
        self._next_patch += 1
        self._patches.append(record)
        return record.to_dict()

    def patches(self, *, pid: int | None = None) -> list[dict]:
        return [p.to_dict() for p in self._patches if pid is None or p.pid == pid]

    def restore_patch(self, patch_id: int) -> dict:
        record = next((p for p in self._patches if p.id == patch_id), None)
        if record is None:
            raise NotFound(f"no patch with id {patch_id}")
        if record.restored:
            raise InvalidArgument(f"patch {patch_id} was already restored")
        self.backend.write(record.pid, record.va, bytes.fromhex(record.original))
        record.restored = True
        return record.to_dict()

    def restore_all(self, *, pid: int | None = None) -> dict:
        restored = []
        for record in self._patches:
            if record.restored or (pid is not None and record.pid != pid):
                continue
            try:
                self.backend.write(record.pid, record.va, bytes.fromhex(record.original))
                record.restored = True
                restored.append(record.id)
            except Exception:
                continue
        return {"restored": restored, "count": len(restored)}

    # -- memory dumps ------------------------------------------------------
    def dump_region(self, pid: int, base: int, size: int, *, chunk: int = 0x100000) -> bytes:
        if size <= 0:
            raise InvalidArgument("size must be positive")
        out = bytearray()
        offset = 0
        while offset < size:
            current = min(chunk, size - offset)
            try:
                out.extend(self._read(pid, base + offset, current))
            except BackendError:
                out.extend(b"\x00" * current)
            offset += current
        return bytes(out)

    # -- threads -----------------------------------------------------------
    def threads(self, pid: int) -> list[dict]:
        return [t.to_dict() for t in self.backend.list_threads(pid)]

    def callstack(self, pid: int, tid: int, *, symbolize: bool = True) -> list[dict]:
        frames = self.backend.thread_callstack(pid, tid)
        if symbolize:
            for frame in frames:
                if frame.symbol or frame.function:
                    continue
                try:
                    resolved = self.backend.symbolize(pid, frame.va)
                except Unavailable:
                    resolved = None
                if resolved:
                    frame.module = frame.module or resolved.module
                    frame.offset = frame.offset if frame.offset is not None else resolved.offset
                    frame.symbol = resolved.symbol
        return [f.to_dict() for f in frames]

    # -- scanning ----------------------------------------------------------
    def _scan_targets(self, pid: int, *, region_filter: str | None = None,
                      readable_only: bool = True) -> list[Region]:
        regions = self._regions(pid)
        needle = (region_filter or "").lower()
        out: list[Region] = []
        for region in regions:
            prot = region.protection.lower()
            if readable_only and "r" not in prot:
                continue
            if needle and needle not in (region.module or "").lower() \
                    and needle not in (region.tag or "").lower():
                continue
            if region.size <= 0 or region.size > MAX_SCAN_BYTES:
                continue
            out.append(region)
        return out

    def scan_strings(self, pid: int, needle: str = "", *, min_length: int = 6,
                     limit: int = 500, encoding: str = "ascii",
                     region_filter: str | None = None,
                     max_bytes: int = MAX_SCAN_BYTES) -> dict:
        """Find readable strings in *live* memory, optionally containing ``needle``.

        ``strings`` on the static engine only sees what is on disk.  Anything the
        target builds at run time — a URL after a redirect, a decrypted key, a JSON
        payload assembled in a heap buffer — exists only here.

        ``encoding`` accepts ``ascii``, ``utf16`` or ``both``; ``utf16`` is worth
        checking separately because Windows stores almost every user-visible string
        that way, and an ASCII-only scan misses all of it.
        """
        wanted = needle.lower()
        units: list[tuple[str, int]] = []
        if encoding in ("ascii", "both"):
            units.append(("ascii", 1))
        if encoding in ("utf16", "both"):
            units.append(("utf16", 2))
        if not units:
            raise InvalidArgument("encoding must be ascii, utf16 or both")

        out: list[dict] = []
        scanned = 0
        regions = self._scan_targets(pid, region_filter=region_filter)
        for region in regions:
            if scanned >= max_bytes or len(out) >= limit:
                break
            try:
                data = self._read(pid, region.base, region.size)
            except Exception:
                continue
            scanned += len(data)
            for kind, unit in units:
                for hit in _iter_strings(data, unit, min_length):
                    if wanted and wanted not in hit["text"].lower():
                        continue
                    hit.update({"va": hex(region.base + hit.pop("offset")),
                                "encoding": kind})
                    if region.module:
                        hit["module"] = region.module
                    out.append(hit)
                    if len(out) >= limit:
                        break
                if len(out) >= limit:
                    break
        out.sort(key=lambda row: int(row["va"], 16))
        return {"pid": pid, "count": len(out), "scanned_bytes": scanned,
                "encoding": encoding, "matches": out}

    def scan_aob(self, pid: int, pattern: str, *, limit: int = 200,
                 region_filter: str | None = None, max_bytes: int = MAX_SCAN_BYTES) -> list[dict]:
        tokens = parse_pattern(pattern)
        hits: list[ScanHit] = []
        scanned = 0
        for region in self._scan_targets(pid, region_filter=region_filter):
            if scanned >= max_bytes:
                break
            data = self._read(pid, region.base, region.size)
            scanned += len(data)
            module = region.module
            for address in scan_bytes(data, tokens, base=region.base, limit=limit - len(hits)):
                hits.append(
                    ScanHit(
                        va=address,
                        module=module,
                        region_base=region.base,
                        region_size=region.size,
                        preview=data[address - region.base : address - region.base + 24].hex(" "),
                    )
                )
                if len(hits) >= limit:
                    return [h.to_dict() for h in hits]
        return [h.to_dict() for h in hits]

    def scan_value(self, pid: int, value: int | float, value_type: str, *,
                   label: str | None = None, limit: int = 200_000,
                   region_filter: str | None = None) -> dict:
        """First scan: every address holding ``value`` of ``value_type``."""
        needle = utils.pack_value(value, value_type)
        size = len(needle)
        addresses: list[int] = []
        for region in self._scan_targets(pid, region_filter=region_filter):
            if len(addresses) >= limit:
                break
            data = self._read(pid, region.base, region.size)
            offset = data.find(needle)
            while offset != -1:
                addresses.append(region.base + offset)
                if len(addresses) >= limit:
                    break
                offset = data.find(needle, offset + 1)
        state = ScanState(
            pid=pid,
            value_type=value_type,
            addresses=addresses,
            created=time.time(),
            label=label,
        )
        key = label or f"scan:{pid}:{int(state.created)}"
        self._scans[key] = state
        return {"key": key, "pid": pid, "type": value_type, "count": len(addresses),
                "addresses": [hex(a) for a in addresses[:200]]}

    def scan_next(self, key: str, value: int | float | None = None, *,
                  changed: bool = False, unchanged: bool = False,
                  increased: bool = False, decreased: bool = False,
                  limit: int = 200_000) -> dict:
        """Narrow an existing scan.

        ``value`` keeps addresses whose current value equals it.  ``increased`` /
        ``decreased`` compare against each address's *own* previous value, which is
        what makes them usable when you never knew the number in the first place —
        the common case: the target drifts, so there is no single value to compare
        a thousand candidates against.

        ``unchanged`` keeps addresses that still hold what they held last pass,
        which is how you drop the noise without knowing any of the values.
        ``changed`` is the opposite and, like the two above, needs a baseline:
        ``scan_next(changed=True)`` with no baseline captures one and returns
        everything, so the natural loop is capture → let the target move → narrow.
        """
        state = self._scans.get(key)
        if state is None:
            raise NotFound(f"unknown scan {key!r}")
        size = utils.value_type_size(state.value_type)
        previous = getattr(state, "previous", None) or {}
        if (increased or decreased or unchanged or changed) and not previous:
            current_values = {}
            for address in state.addresses:
                try:
                    current_values[address] = utils.unpack_value(
                        self._read(state.pid, address, size), state.value_type
                    )
                except Exception:
                    continue
            state.previous = current_values  # type: ignore[attr-defined]
            return {"key": key, "pid": state.pid, "type": state.value_type,
                    "count": len(state.addresses),
                    "addresses": [hex(a) for a in state.addresses[:200]],
                    "baseline": True,
                    "hint": "values captured; let the target change, then call again"}
        remaining: list[int] = []
        current_values: dict[int, Any] = {}
        for address in state.addresses:
            try:
                data = self._read(state.pid, address, size)
                current = utils.unpack_value(data, state.value_type)
            except Exception:
                continue
            current_values[address] = current
            if value is not None and current != value:
                continue
            before = previous.get(address)
            if increased and (before is None or not current > before):
                continue
            if decreased and (before is None or not current < before):
                continue
            if unchanged and before is not None and current != before:
                continue
            if changed and before is not None and current == before:
                continue
            remaining.append(address)
            if len(remaining) >= limit:
                break
        state.addresses = remaining
        state.previous = current_values  # type: ignore[attr-defined]
        return {"key": key, "pid": state.pid, "type": state.value_type,
                "count": len(remaining), "addresses": [hex(a) for a in remaining[:200]]}

    def scan_changed(self, key: str, *, limit: int = 200_000) -> dict:
        """Keep only addresses whose value changed since the previous narrowing pass."""
        state = self._scans.get(key)
        if state is None:
            raise NotFound(f"unknown scan {key!r}")
        size = utils.value_type_size(state.value_type)
        previous = getattr(state, "previous", None)
        if previous is None:
            previous = {}
            for address in state.addresses:
                try:
                    previous[address] = utils.unpack_value(
                        self._read(state.pid, address, size), state.value_type
                    )
                except Exception:
                    continue
            state.previous = previous  # type: ignore[attr-defined]
            return {"key": key, "pid": state.pid, "type": state.value_type,
                    "changed": 0, "hint": "values captured; call scan_next(changed=True) again"}
        remaining: list[int] = []
        current_values: dict[int, Any] = {}
        for address in state.addresses:
            try:
                value = utils.unpack_value(self._read(state.pid, address, size), state.value_type)
            except Exception:
                continue
            current_values[address] = value
            if previous.get(address) != value:
                remaining.append(address)
                if len(remaining) >= limit:
                    break
        state.addresses = remaining
        state.previous = current_values  # type: ignore[attr-defined]
        return {"key": key, "pid": state.pid, "type": state.value_type,
                "count": len(remaining), "addresses": [hex(a) for a in remaining[:200]]}

    def scan_results(self, key: str, *, limit: int = 500) -> dict:
        state = self._scans.get(key)
        if state is None:
            raise NotFound(f"unknown scan {key!r}")
        return {"key": key, "pid": state.pid, "type": state.value_type,
                "count": len(state.addresses),
                "addresses": [hex(a) for a in state.addresses[:limit]]}

    # -- pointer chains ----------------------------------------------------
    def pointer_scan(self, pid: int, target_va: int, *, max_depth: int = 3,
                     limit: int = 20, module: str | None = None,
                     include_readonly: bool = True) -> list[dict]:
        """Find static-base + offset chains that resolve to ``target_va``.

        At each depth every candidate region is searched for pointer-sized
        values equal to an address found at the previous depth.  This is the
        vectorised form of the classic manual pointer scan; chains rooted in a
        module are reported first because those are the ones that survive a
        restart.
        """
        regions = [r for r in self._regions(pid) if r.size > 0]
        if module:
            needle = module.lower()
            regions = [r for r in regions if needle in (r.module or "").lower()
                       or needle in (r.tag or "").lower()]
            if not regions:
                raise NotFound(f"no region matching module {module!r}")
        if not include_readonly:
            regions = [r for r in regions if "w" in r.protection.lower()]

        by_depth: list[list[tuple[Region, int]]] = []
        current = [target_va]
        seen_slots: set[int] = set()
        for _depth in range(max_depth):
            found: list[tuple[Region, int]] = []
            for region in regions:
                if region.size > 64 * 1024 * 1024:
                    continue
                try:
                    data = self._read(pid, region.base, region.size)
                except Exception:
                    continue
                for address in current:
                    needle = struct.pack("<Q", address)
                    position = data.find(needle)
                    while position != -1:
                        slot = region.base + position
                        if slot not in seen_slots:
                            seen_slots.add(slot)
                            found.append((region, slot))
                        if len(found) >= 2000:
                            break
                        position = data.find(needle, position + 8)
                    if len(found) >= 2000:
                        break
                if len(found) >= 2000:
                    break
            if not found:
                break
            by_depth.append(found)
            current = [slot for _region, slot in found[:400]]

        if not by_depth:
            return []
        # ``by_depth[0]`` holds slots that point at the target, ``by_depth[1]``
        # holds slots that point at *those* slots, and so on.  A chain therefore
        # starts at the deepest level and reads forward: the outermost slot, then
        # each slot it pointed at, ending at the target.  Building it by walking
        # backwards from every leaf costs a read per candidate per level and, worse,
        # silently produced nothing whenever a level had more than a handful of
        # candidates — the reverse link was never the thing being searched for.
        chains: list[dict] = []
        for depth_index in range(len(by_depth) - 1, -1, -1):
            for region, slot in by_depth[depth_index][: max(1, limit)]:
                path = [(region, slot)]
                cursor = slot
                walked = True
                for level in range(depth_index - 1, -1, -1):
                    try:
                        nxt = struct.unpack("<Q", self._read(pid, cursor, 8))[0]
                    except Exception:
                        walked = False
                        break
                    parent = next(
                        (item for item in by_depth[level] if item[1] == nxt), None
                    )
                    if parent is None:
                        walked = False
                        break
                    path.append(parent)
                    cursor = parent[1]
                if not walked:
                    continue
                # No reversal: ``path[0]`` is the slot from the *deepest* level,
                # i.e. the outermost one, which is where a chain has to start.
                chain = [
                    {
                        "region": item_region.module or item_region.tag or hex(item_region.base),
                        "region_base": hex(item_region.base),
                        "offset": hex(item_slot - item_region.base),
                        "slot": hex(item_slot),
                    }
                    for item_region, item_slot in path
                ]
                chains.append(
                    {
                        "target": hex(target_va),
                        "depth": len(chain),
                        "module_anchored": bool(path and path[0][0].module),
                        "static_base": chain[0]["region"],
                        "offsets": [item["offset"] for item in chain],
                        "chain": chain,
                    }
                )
                if len(chains) >= limit:
                    break
            if len(chains) >= limit:
                break
        chains.sort(key=lambda item: (not item["module_anchored"], item["depth"]))
        return chains

    # -- snapshots ---------------------------------------------------------
    def snapshot(self, pid: int, base: int, size: int, *, label: str | None = None) -> dict:
        data = self._read(pid, base, size)
        record = SnapshotRecord(
            id=self._next_snapshot,
            pid=pid,
            base=base,
            size=len(data),
            created=time.time(),
        )
        self._next_snapshot += 1
        self._snapshots[record.id] = Snapshot(record=record, data=data)
        out = record.to_dict()
        if label:
            out["label"] = label
        return out

    def diff(self, pid: int, *, region: Region | None = None, base: int | None = None,
             size: int | None = None, snapshot_id: int | None = None,
             timeout: float = 0.0, interval: float = 0.05,
             limit: int = 200) -> list[dict]:
        """Compare memory against a snapshot, or watch it for changes.

        With ``snapshot_id`` (or without it, using the newest snapshot that
        covers the same range) changes are measured against that snapshot.  If
        no snapshot exists the current bytes are used as the baseline, and
        ``timeout`` turns the call into a change watcher.
        """
        if region is not None:
            base, size = region.base, region.size
        if base is None or size is None:
            raise InvalidArgument("provide either a region or base+size")

        baseline: bytes | None = None
        if snapshot_id is not None:
            snap = self._snapshots.get(int(snapshot_id))
            if snap is None:
                raise NotFound(f"no snapshot with id {snapshot_id}")
            baseline = snap.data
        else:
            for snapshot in reversed(list(self._snapshots.values())):
                if snapshot.record.base == base and snapshot.record.size >= size:
                    baseline = snapshot.data[:size]
                    break
        if baseline is None:
            baseline = self._read(pid, base, size)

        if timeout <= 0:
            return self._diff_bytes(base, baseline, self._read(pid, base, size), limit)

        deadline = time.time() + timeout
        while time.time() < deadline:
            changes = self._diff_bytes(base, baseline, self._read(pid, base, size), limit)
            if changes:
                return changes
            time.sleep(interval)
        return []

    @staticmethod
    def _diff_bytes(base: int, before: bytes, after: bytes, limit: int) -> list[dict]:
        changes: list[dict] = []
        length = min(len(before), len(after))
        index = 0
        while index < length and len(changes) < limit:
            if before[index] == after[index]:
                index += 1
                continue
            start = index
            while index < length and before[index] != after[index]:
                index += 1
            changes.append(
                {
                    "va": hex(base + start),
                    "offset": hex(start),
                    "old": before[start:index].hex(),
                    "new": after[start:index].hex(),
                }
            )
        return changes

    # -- pointer paths -----------------------------------------------------
    def resolve_pointer_chain(self, pid: int, base: str | int, offsets: list,
                              *, value_type: str | None = None,
                              read_size: int = 0) -> dict:
        """Walk a pointer path (``module+0x10``, ``[0x10, 0x38, 0x8]``) and read the field.

        See :mod:`phantomscope.dynamic.pointer` for the two offset conventions: a
        hand-written chain adds every offset, a chain from ``pointer_scan`` is
        replayed with :meth:`replay_pointer_chains`.
        """
        return chains.resolve(self, pid, base, offsets, value_type=value_type,
                              read_size=read_size)

    def replay_pointer_chains(self, pid: int, candidates: list[dict], *,
                              value_type: str | None = None, limit: int = 10) -> list[dict]:
        """Re-run chains from ``pointer_scan`` and report which still resolve."""
        return chains.resolve_many(self, pid, candidates, value_type=value_type, limit=limit)

    # -- live structures ---------------------------------------------------
    def read_object(self, pid: int, va: int, size: int = 0x80, *,
                    fields: str | dict | None = None) -> dict:
        """One object: hexdump, qwords with pointer validity, typed fields."""
        return structures.read_object(self, pid, va, size, fields=fields)

    def read_array(self, pid: int, base: int, stride: int, count: int, *,
                   fields: str | dict | None = None, follow: bool = False,
                   object_size: int = 0x40, limit: int = 128) -> dict:
        """``count`` objects at ``stride`` bytes, or an array of pointers when ``follow``."""
        return structures.read_array(self, pid, base, stride, count, fields=fields,
                                     follow=follow, object_size=object_size, limit=limit)

    def infer_struct(self, pid: int, va: int, size: int = 0x40, *,
                     stride: int | None = None, count: int = 1,
                     align: int = 8) -> dict:
        """Infer field layout from sampled values, and print a C declaration."""
        return structures.infer_struct(self, pid, va, size, stride=stride,
                                       count=count, align=align)

    def detect_container(self, pid: int, va: int, *,
                         element_size: int | None = None) -> dict:
        """Which container layout fits the bytes at ``va`` (vector / TArray / string)."""
        return structures.detect_container(self, pid, va, element_size=element_size)

    def expand_container(self, pid: int, va: int, *, element_size: int | None = None,
                         fields: str | dict | None = None, limit: int = 64) -> dict:
        """Detect a container and read its elements in one call.

        This is the entity-list workflow: point it at a manager object and get the
        elements back, with the layout guess and its evidence attached.
        """
        detected = structures.detect_container(self, pid, va, element_size=element_size)
        primary = detected.get("primary")
        if primary is None:
            detected["elements"] = []
            detected["note"] = "no container layout fits these bytes; try read_object"
            return detected
        if "(SSO" in primary["kind"] or "(heap)" in primary["kind"]:
            detected["elements"] = []
            detected["value"] = primary.get("value")
            return detected

        size = primary.get("element_size") or (primary.get("element_size_candidates") or [8])[0]
        count = primary.get("count") or 0
        if not count:
            detected["elements"] = []
            detected["note"] = "container is empty (count 0)"
            return detected
        data_va = int(str(primary["data_va"]), 16)
        detected["elements"] = structures.read_array(
            self, pid, data_va, int(size), int(count), fields=fields, limit=limit
        )["objects"]
        detected["element_size"] = size
        detected["element_count"] = min(int(count), limit)
        return detected

    # -- change tracing ----------------------------------------------------
    def trace_changes(self, pid: int, base: int, size: int, *, samples: int = 8,
                      interval: float = 0.02, limit: int = 64) -> dict:
        """Poll a range and report what changed, how often, and as what type."""
        return trace.trace_changes(self, pid, base, size, samples=samples,
                                   interval=interval, limit=limit)

    def trace_value(self, pid: int, va: int, value_type: str, *, samples: int = 8,
                    interval: float = 0.02) -> dict:
        """Time series for one typed value (counters, timers, health bars)."""
        return trace.trace_value(self, pid, va, value_type, samples=samples,
                                 interval=interval)

    def sample_matrix(self, pid: int, va: int, width: int = 8, rows: int = 16,
                      stride: int = 8, *, interval: float = 0.02) -> dict:
        """A grid of typed cells read twice — a quick "is this an object" view."""
        return trace.sample_matrix(self, pid, va, width, rows, stride, interval=interval)

    # -- module snapshots --------------------------------------------------
    def snapshot_module(self, pid: int, name: str, *, label: str | None = None) -> dict:
        """Snapshot every mapped region of a module.

        Whole-module snapshots are what make ``diff_module`` useful: static data
        (a decrypted config, an unlocked table) changes in place, and a region
        snapshot taken before the trigger is the only baseline that proves it.
        """
        module = self.resolve_module(pid, name)
        regions = [r for r in self._regions(pid) if module.base <= r.base < module.end]
        if not regions:
            raise NotFound(f"no mapped regions for module {module.name!r}")
        entries = []
        for region in regions:
            if region.size <= 0:
                continue
            record = self.snapshot(pid, region.base, region.size)
            entries.append({"snapshot_id": record["id"], "base": hex(region.base),
                            "size": region.size, "protection": region.protection})
        entry = {"id": self._next_module_snap, "pid": pid, "module": module.name,
                 "base": hex(module.base), "label": label, "created": time.time(),
                 "regions": entries}
        self._next_module_snap += 1
        self._module_snaps[entry["id"]] = entry
        return entry

    def diff_module(self, pid: int, name: str, *, snapshot_id: int | None = None,
                    limit: int = 200) -> dict:
        """Compare a module's regions against a ``snapshot_module`` baseline."""
        module = self.resolve_module(pid, name)
        candidates = [item for item in self._module_snaps.values()
                      if item["pid"] == pid and item["module"].lower() == module.name.lower()
                      and (snapshot_id is None or item["id"] == snapshot_id)]
        if not candidates:
            raise NotFound(f"no module snapshot for {module.name!r}; call snapshot_module first")
        baseline = candidates[-1]
        changes: list[dict] = []
        for region in baseline["regions"]:
            snap = self._snapshots.get(int(region["snapshot_id"]))
            if snap is None:
                continue
            try:
                current = self._read(pid, snap.record.base, snap.record.size)
            except BackendError:
                continue
            for change in self._diff_bytes(snap.record.base, snap.data, current,
                                           limit - len(changes)):
                change["region"] = region["base"]
                changes.append(change)
            if len(changes) >= limit:
                break
        return {"pid": pid, "module": module.name, "snapshot_id": baseline["id"],
                "label": baseline.get("label"), "regions_compared": len(baseline["regions"]),
                "changed_bytes": sum(len(bytes.fromhex(c["new"])) for c in changes),
                "changes": changes, "truncated": len(changes) >= limit}

    # -- convenience -------------------------------------------------------
    def module_bytes(self, pid: int, name: str) -> bytes:
        module = self.resolve_module(pid, name)
        return self._read(pid, module.base, module.size)

    def watch_values(self, pid: int, addresses: Iterable[int], value_type: str,
                     *, timeout: float = 5.0, interval: float = 0.1,
                     limit: int = 50) -> list[dict]:
        """Poll a set of addresses until their values change."""
        size = utils.value_type_size(value_type)
        watched = list(addresses)
        initial: dict[int, Any] = {}
        for address in watched:
            try:
                initial[address] = utils.unpack_value(self._read(pid, address, size), value_type)
            except Exception:
                initial[address] = None
        deadline = time.time() + timeout
        events: list[dict] = []
        while time.time() < deadline:
            for address in watched:
                try:
                    current = utils.unpack_value(self._read(pid, address, size), value_type)
                except Exception:
                    continue
                if initial.get(address) != current:
                    events.append(
                        {
                            "va": hex(address),
                            "old": initial.get(address),
                            "new": current,
                            "type": value_type,
                        }
                    )
                    initial[address] = current
                    if len(events) >= limit:
                        return events
            time.sleep(interval)
        return events
