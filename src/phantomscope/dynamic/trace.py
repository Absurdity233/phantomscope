"""Sampling-based change tracing: the DMA substitute for a memory breakpoint.

A hardware write watchpoint needs the CPU to stop, and over DMA nothing stops.
What is available is *polling*: read the same range repeatedly and diff
consecutive samples.  That does not tell you which instruction wrote the value,
but it does answer the questions that usually come first:

* is this field written at all while the game idles?
* how often does it change, and does it flip between two values (a flag) or march
  monotonically (a counter, a timer, a health value)?
* which neighbouring bytes move together, i.e. which 4/8-byte field is the real
  variable inside a 0x100-byte blob?
* what did the values look like as ``int32`` / ``uint64`` / ``float`` rather than
  as hex?

The implementation is deliberately cheap: consecutive samples are compared with
``bytes`` equality per chunk (a memcmp) and the per-byte loop only runs for the
chunks that actually differ.  Change tracing is therefore limited by DMA read
bandwidth, not by Python.
"""

from __future__ import annotations

import struct
import time

from .. import utils
from ..errors import BackendError, InvalidArgument

#: Polling more than this per call is a scan, not a trace; use `scan_value`.
MAX_TRACE_BYTES = 8 * 1024 * 1024
CHUNK = 64 * 1024


def _read(engine, pid: int, base: int, size: int) -> bytes:
    return engine.read_bytes(pid, base, size)


def _interpret(oldest: bytearray, newest: bytearray, base: int, start: int) -> list[dict]:
    """Typed readings of the *aligned* window containing a changed run.

    A field whose value goes 100 -> 42 only changes one byte, so interpreting the
    run itself would be useless; the meaningful reading is the aligned dword/qword
    around it.  Windows that did not actually change are dropped.
    """
    out: list[dict] = []
    for size, types in ((4, ("int32", "uint32", "float")), (8, ("int64", "uint64", "double"))):
        origin = ((base + start) // size) * size - base
        if origin < 0 or origin + size > len(oldest):
            continue
        before = bytes(oldest[origin : origin + size])
        after = bytes(newest[origin : origin + size])
        if before == after:
            continue
        for kind in types:
            try:
                out.append({
                    "type": kind,
                    "width": size,
                    "va": hex(base + origin),
                    "first": utils.unpack_value(before, kind),
                    "last": utils.unpack_value(after, kind),
                })
            except Exception:
                continue
    return out


def _monotonic(oldest: bytearray, newest: bytearray, base: int, start: int) -> str | None:
    """Did the surrounding value only increase / only decrease across the window?"""
    for size, types in ((4, ("int32", "float")), (8, ("int64", "double"))):
        origin = ((base + start) // size) * size - base
        if origin < 0 or origin + size > len(oldest):
            continue
        before_raw = bytes(oldest[origin : origin + size])
        after_raw = bytes(newest[origin : origin + size])
        if before_raw == after_raw:
            continue
        for kind in types:
            try:
                before = utils.unpack_value(before_raw, kind)
                after = utils.unpack_value(after_raw, kind)
            except Exception:
                continue
            if before == after:
                continue
            return f"{kind}: {'increased' if after > before else 'decreased'} {before!r} -> {after!r}"
    return None


def trace_changes(engine, pid: int, base: int, size: int, *, samples: int = 8,
                  interval: float = 0.02, limit: int = 64) -> dict:
    """Poll ``base..base+size`` ``samples`` times and report what moved.

    Returns contiguous changed runs, each with how many of the samples changed it,
    the first and last value, and typed interpretations.  A run that changes in
    every sample is being written continuously; one that changes once is an event.
    """
    if size <= 0:
        raise InvalidArgument("size must be positive")
    if size > MAX_TRACE_BYTES:
        raise InvalidArgument(f"range is {size} bytes (limit {MAX_TRACE_BYTES}); poll a smaller window")
    if samples < 2:
        raise InvalidArgument("samples must be at least 2 (one sample cannot show a change)")
    samples = min(int(samples), 1000)

    first = _read(engine, pid, base, size)
    if not first:
        raise BackendError(f"nothing readable at {base:#x}")
    size = len(first)
    previous = first
    counts = bytearray(size)
    oldest = bytearray(first)
    newest = bytearray(first)
    started = time.time()
    observed = 1

    for _index in range(samples - 1):
        if interval > 0:
            time.sleep(interval)
        current = _read(engine, pid, base, size)
        if len(current) != size:
            break
        observed += 1
        for offset in range(0, size, CHUNK):
            before = previous[offset : offset + CHUNK]
            after = current[offset : offset + CHUNK]
            if before == after:
                continue
            for index, (old, new) in enumerate(zip(before, after)):
                if old != new:
                    counts[offset + index] = min(255, counts[offset + index] + 1)
                    newest[offset + index] = new
        previous = current

    runs: list[dict] = []
    index = 0
    while index < size and len(runs) < limit:
        if not counts[index]:
            index += 1
            continue
        start = index
        while index < size and counts[index]:
            index += 1
        end = index
        run_size = end - start
        run_counts = counts[start:end]
        run_first = bytes(oldest[start:end])
        run_last = bytes(newest[start:end])
        entry: dict = {
            "va": hex(base + start),
            "offset": hex(start),
            "size": run_size,
            "changes": max(run_counts),
            "first": run_first.hex(),
            "last": run_last.hex(),
            "monotonic": _monotonic(oldest, newest, base, start),
            "flips": _flips(run_first, run_last, run_size),
            "interpretations": _interpret(oldest, newest, base, start),
        }
        try:
            entry.update(engine.address_info(pid, base + start))
        except Exception:
            pass
        runs.append(entry)

    changed = sum(1 for count in counts if count)
    return {
        "pid": pid,
        "base": hex(base),
        "size": size,
        "samples": observed,
        "interval": interval,
        "duration": round(time.time() - started, 3),
        "changed_bytes": changed,
        "written_continuously": sum(1 for count in counts if count >= max(2, observed - 1)),
        "runs": runs,
        "truncated": len(runs) >= limit,
        "notes": [
            "polling cannot name the writing instruction; it shows what changed and how often",
            "`changes` is how many of the samples found a new value in that byte",
            "`written_continuously` counts bytes that moved in (almost) every sample: active updates",
        ],
    }


def _flips(first: bytes, last: bytes, size: int) -> int:
    """Count differing bits, which distinguishes a flag from a counter."""
    return sum(bin(a ^ b).count("1") for a, b in zip(first, last))


def trace_value(engine, pid: int, va: int, value_type: str, *, samples: int = 8,
                interval: float = 0.02) -> dict:
    """Poll one typed value and return the time series (for counters and timers)."""
    size = utils.value_type_size(value_type)
    if samples < 2:
        raise InvalidArgument("samples must be at least 2")
    series: list[dict] = []
    started = time.time()
    for index in range(min(int(samples), 5000)):
        data = _read(engine, pid, va, size)
        if len(data) < size:
            raise BackendError(f"short read at {va:#x}")
        series.append({"sample": index, "t": round(time.time() - started, 3),
                       "value": utils.unpack_value(data, value_type)})
        if index < samples - 1 and interval > 0:
            time.sleep(interval)
    values = [row["value"] for row in series]
    numeric = [value for value in values if isinstance(value, (int, float))]
    deltas = [round(b - a, 6) for a, b in zip(numeric, numeric[1:])]
    return {
        "pid": pid,
        "va": hex(va),
        "type": value_type,
        "samples": len(series),
        "series": series,
        "changed": len(set(values)) > 1,
        "distinct": len(set(values)),
        "min": min(numeric) if numeric else None,
        "max": max(numeric) if numeric else None,
        "deltas": deltas[:32],
        "constant": len(set(values)) == 1,
    }


def sample_matrix(engine, pid: int, va: int, width: int = 8, rows: int = 16,
                  stride: int = 8, *, interval: float = 0.02) -> dict:
    """Read a grid of qwords a few times — a quick "what looks like an object" view.

    Useful before :func:`infer_struct`: if a column never changes it is probably a
    shared pointer or a constant; a column that changes on every sample is live
    state.
    """
    if width not in (4, 8):
        raise InvalidArgument("width must be 4 or 8")
    if rows <= 0 or rows > 512:
        raise InvalidArgument("rows must be between 1 and 512")
    try:
        regions = engine.regions(pid)
    except Exception:
        regions = []
    columns = []
    for _ in range(2):
        snapshot = []
        for row in range(rows):
            data = engine.read_bytes(pid, va + row * stride, width)
            snapshot.append(int.from_bytes(data, "little") if len(data) == width else None)
        columns.append(snapshot)
        if interval > 0:
            time.sleep(interval)
    table = []
    for row in range(rows):
        cell = {"offset": hex(row * stride), "first": columns[0][row], "second": columns[1][row]}
        cell["changed"] = cell["first"] != cell["second"]
        if isinstance(cell["first"], int):
            cell["hex"] = hex(cell["first"])
            cell["float"] = struct.unpack("<f", cell["first"].to_bytes(width, "little")[:4])[0]
            # A column of mapped addresses is a pointer column; that is the first
            # thing to look for when deciding whether this really is an object.
            cell["pointer"] = any(region.contains(cell["first"]) for region in regions) \
                if cell["first"] else False
        table.append(cell)
    return {
        "pid": pid,
        "va": hex(va),
        "width": width,
        "stride": stride,
        "rows": table,
        "changed_rows": sum(1 for row in table if row["changed"]),
    }
