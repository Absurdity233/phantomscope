"""Reading live objects: arrays, layout inference and container detection.

A DMA read gives you bytes.  Real reverse engineering needs *structures*: the
entity list behind a pointer, the fields of one object, the ``std::vector`` the
code is iterating.  Those structures are not in the binary (they are heap
allocations), so they have to be recovered from the live process:

* :func:`read_object` — one object as hexdump, qwords and typed fields.
* :func:`read_array` — ``count`` objects at ``stride`` bytes, optionally following
  an array of pointers (``Entity**``) to the objects they point at.
* :func:`infer_struct` — field widths and types inferred from *samples*, plus a
  C declaration you can paste into a header.
* :func:`detect_container` — decide whether an address holds an MSVC
  ``std::vector``, an Unreal ``TArray``, an SSO ``std::string`` or a plain
  pointer/count/capacity triple, and expand it.

Honesty rules that shape the code below:

* A layout guess is reported with the evidence that produced it and with the
  alternatives that fit equally well; nothing is presented as a type the memory
  does not prove.
* An unreadable page is an error with an address, not zeros.
* Samples beat single reads: one object cannot distinguish a pointer from an
  integer that happens to look like one, four objects usually can.
"""

from __future__ import annotations

import math
import struct

from .. import utils
from ..errors import BackendError, InvalidArgument

#: Element sizes worth trying when expanding a container.  12/20/24/40/56 are
#: common 3D vector / matrix strides; the rest are the natural alignments.
ELEMENT_SIZES = (1, 2, 4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64)
MAX_ARRAY_OBJECTS = 4096
MAX_INFER_SAMPLES = 64

_CTYPE = {
    "int8": "int8_t",
    "uint8": "uint8_t",
    "int16": "int16_t",
    "uint16": "uint16_t",
    "int32": "int32_t",
    "uint32": "uint32_t",
    "int64": "int64_t",
    "uint64": "uint64_t",
    "float": "float",
    "double": "double",
    "pointer": "void *",
    "zero": "uint8_t",
}


# -- field specifications ---------------------------------------------------
def parse_fields(spec: str | dict | None) -> dict[int, str]:
    """Parse ``"0x0:int32,0x8:pointer,0x10:char[16]"`` into ``{offset: type}``.

    Accepts a dict (``{"0x0": "int32"}``) too, so an MCP client can send either
    a compact string or real JSON.
    """
    if not spec:
        return {}
    out: dict[int, str] = {}
    items = spec.items() if isinstance(spec, dict) else (
        part.split(":", 1) for part in str(spec).split(",") if part.strip()
    )
    for key, value in items:
        kind = str(value).strip()
        if kind.startswith("char[") or kind.startswith("hex["):
            pass
        elif kind not in _CTYPE and kind not in utils.VALUE_TYPE_SIZES:
            raise InvalidArgument(f"unknown field type {kind!r}")
        out[utils.parse_address(key, name="field offset")] = kind
    return out


def _field_size(kind: str) -> int:
    if kind in utils.VALUE_TYPE_SIZES:
        return utils.VALUE_TYPE_SIZES[kind]
    if kind == "pointer":
        return 8
    if kind == "zero":
        return 8
    if "[" in kind and kind.endswith("]"):
        try:
            return int(kind[kind.index("[") + 1 : -1])
        except ValueError as exc:
            raise InvalidArgument(f"bad field type {kind!r}") from exc
    raise InvalidArgument(f"unknown field type {kind!r}")


def _decode_field(data: bytes, kind: str) -> object:
    if kind in utils.VALUE_TYPE_SIZES:
        return utils.unpack_value(data, kind)
    if kind in ("pointer", "zero"):
        return int.from_bytes(data[:8], "little")
    if kind.startswith("char["):
        length = _field_size(kind)
        raw = data[:length].split(b"\x00", 1)[0]
        return raw.decode("utf-8", "replace")
    if kind.startswith("hex["):
        return data[: _field_size(kind)].hex(" ")
    raise InvalidArgument(f"unknown field type {kind!r}")


# -- region helpers ---------------------------------------------------------
def _regions(engine, pid: int):
    try:
        return engine.regions(pid)
    except Exception:
        return []


def _mapped(regions, va: int, size: int = 1) -> bool:
    return any(region.contains(va) and region.contains(va + size - 1) for region in regions)


def _mapped_or_edge(regions, va: int) -> bool:
    """Mapped, or exactly one-past-the-end of a region.

    A container's ``end`` / ``capacity`` pointers legitimately point past the last
    element, so requiring them to be *inside* a region would reject every vector
    that is exactly full — the common case.
    """
    for region in regions:
        if region.contains(va) or va == region.end:
            return True
    return False


def _period(data: bytes, regions) -> int | None:
    """Smallest repeat period of "qword here is a mapped pointer", in bytes.

    A ``std::vector<Entity>`` full of structs has a recognisable rhythm — three
    integers then a pointer, repeated — and that rhythm *is* the element size.
    Data with no pointers in it yields ``None`` (nothing to learn from), which is
    why the caller can always pass ``element_size`` explicitly.
    """
    qwords = len(data) // 8
    if qwords < 4:
        return None
    flags = []
    for index in range(qwords):
        value = int.from_bytes(data[index * 8 : index * 8 + 8], "little")
        flags.append(1 if value and _mapped(regions, value) else 0)
    if not any(flags):
        return None
    for period in range(1, qwords // 2 + 1):
        if all(flags[index] == flags[index % period] for index in range(qwords)):
            return period * 8
    return None


def _context(engine, pid: int, va: int) -> dict:
    try:
        info = engine.address_info(pid, va)
    except Exception:
        return {}
    out = {}
    if info.get("module"):
        out["module"] = info["module"]
        out["module_offset"] = info["module_offset"]
    if info.get("region"):
        out["region_base"] = hex(info["region"]["base"])
        out["protection"] = info["region"].get("protection")
    return out


# -- single object ---------------------------------------------------------
def _scan_runs(data: bytes, minimum: int = 4) -> list[dict]:
    """Printable runs anywhere in the buffer, with their offsets.

    ``ascii`` in the object dump stops at the first zero byte, which is useless in
    a struct full of integers; a name field three dwords in only shows up here.
    """
    out: list[dict] = []
    index = 0
    size = len(data)
    while index < size:
        if 32 <= data[index] < 127:
            end = index
            while end < size and 32 <= data[end] < 127:
                end += 1
            if end - index >= minimum:
                out.append({"offset": hex(index), "length": end - index,
                            "text": data[index:end].decode("ascii", "replace")})
            index = end
        else:
            index += 1
    return out


def read_object(engine, pid: int, va: int, size: int = 0x80, *,
                fields: str | dict | None = None) -> dict:
    """Dump one object: hexdump, aligned qwords with pointer validity, typed fields."""
    if size <= 0 or size > 0x100000:
        raise InvalidArgument("size must be between 1 and 1 MiB")
    data = engine.read_bytes(pid, va, size)
    if not data:
        raise BackendError(f"nothing readable at {va:#x}")
    regions = _regions(engine, pid)

    qwords = []
    for offset in range(0, len(data) - 7, 8):
        value = int.from_bytes(data[offset : offset + 8], "little")
        entry = {"offset": hex(offset), "value": hex(value)}
        if value and _mapped(regions, value):
            entry["points_to"] = hex(value)
            entry["pointer_ok"] = True
            entry.update({f"target_{k}": v for k, v in _context(engine, pid, value).items()
                          if k in ("module", "module_offset")})
        qwords.append(entry)

    out: dict = {
        "pid": pid,
        "va": hex(va),
        "size": len(data),
        "hexdump": utils.hexdump(data, va),
        "ascii": utils.printable_ascii(data, limit=len(data)),
        "strings": _scan_runs(data, 4),
        "qwords": qwords,
    }
    out.update(_context(engine, pid, va))

    spec = parse_fields(fields)
    if spec:
        typed = []
        for offset, kind in sorted(spec.items()):
            if offset + _field_size(kind) > len(data):
                typed.append({"offset": hex(offset), "type": kind, "error": "beyond the object"})
                continue
            chunk = data[offset : offset + _field_size(kind)]
            typed.append({"offset": hex(offset), "type": kind, "value": _decode_field(chunk, kind)})
        out["fields"] = typed
    return out


# -- arrays ----------------------------------------------------------------
def read_array(engine, pid: int, base: int, stride: int, count: int, *,
               fields: str | dict | None = None, follow: bool = False,
               object_size: int = 0x40, limit: int = 128) -> dict:
    """Read ``count`` objects ``stride`` bytes apart.

    ``follow`` treats the array as an array of *pointers* (``Entity**``) and
    dumps ``object_size`` bytes at each target instead — the usual shape of an
    entity list, a manager's object table, or a ``std::vector<Foo*>``.
    """
    if stride <= 0:
        raise InvalidArgument("stride must be positive")
    if count <= 0:
        raise InvalidArgument("count must be positive")
    wanted = min(count, limit, MAX_ARRAY_OBJECTS)
    item_size = 8 if follow else stride
    span = wanted * stride
    data = engine.read_bytes(pid, base, span)
    regions = _regions(engine, pid)
    spec = parse_fields(fields)

    objects: list[dict] = []
    for index in range(wanted):
        offset = index * stride
        chunk = data[offset : offset + item_size]
        if len(chunk) < item_size:
            objects.append({"index": index, "va": hex(base + offset), "error": "short read"})
            continue
        entry: dict = {"index": index, "va": hex(base + offset)}
        if follow:
            target = int.from_bytes(chunk[:8], "little")
            entry["pointer"] = hex(target)
            if not target or not _mapped(regions, target):
                entry["error"] = "pointer is null or not mapped"
                objects.append(entry)
                continue
            entry["target"] = hex(target)
            entry.update({f"target_{k}": v for k, v in _context(engine, pid, target).items()
                          if k in ("module", "module_offset")})
            payload = engine.read_bytes(pid, target, object_size)
            entry["size"] = len(payload)
            entry["hexdump"] = utils.hexdump(payload, target)
            if spec:
                entry["fields"] = [
                    {"offset": hex(off), "type": kind,
                     "value": _decode_field(payload[off : off + _field_size(kind)], kind)}
                    for off, kind in sorted(spec.items())
                    if off + _field_size(kind) <= len(payload)
                ]
        else:
            entry["hex"] = chunk.hex()
            if spec:
                entry["fields"] = [
                    {"offset": hex(off), "type": kind,
                     "value": _decode_field(chunk[off : off + _field_size(kind)], kind)}
                    for off, kind in sorted(spec.items())
                    if off + _field_size(kind) <= len(chunk)
                ]
        objects.append(entry)

    return {
        "pid": pid,
        "base": hex(base),
        "stride": stride,
        "count": len(data) // stride if stride else 0,
        "returned": len(objects),
        "requested": count,
        "truncated": len(objects) < count,
        "follow": follow,
        "objects": objects,
    }


# -- layout inference ------------------------------------------------------
def _plausible_float(raw: bytes) -> float | None:
    try:
        value = struct.unpack("<f", raw)[0]
    except struct.error:
        return None
    if not math.isfinite(value) or value == 0.0:
        return None
    if 1e-6 < abs(value) < 1e9:
        return value
    return None


def infer_struct(engine, pid: int, va: int, size: int = 0x40, *,
                 stride: int | None = None, count: int = 1,
                 align: int = 8) -> dict:
    """Infer field layout from one object or from ``count`` objects at ``stride``.

    Granularity is ``align`` bytes (8 by default) because that is what can be
    decided from values alone; a pair of ``int32`` fields inside one qword is
    reported as an alternative, not as two fields.  Set ``align=4`` to look at
    dwords, which is the right call for a packet or a struct of ints.
    """
    if size <= 0 or size > 0x10000:
        raise InvalidArgument("size must be between 1 and 64 KiB")
    if align not in (1, 2, 4, 8):
        raise InvalidArgument("align must be 1, 2, 4 or 8")
    samples = max(1, min(int(count), MAX_INFER_SAMPLES))
    step = stride or size
    notes: list[str] = []
    if stride and size > stride:
        # An element cannot be wider than the distance to the next one; without
        # this the inferred layout would bleed into the following records.
        notes.append(f"size clamped from {size:#x} to the stride {stride:#x}")
        size = stride

    blobs: list[bytes] = []
    for index in range(samples):
        blob = engine.read_bytes(pid, va + index * step, size)
        if len(blob) < size:
            break
        blobs.append(blob)
    if not blobs:
        raise BackendError(f"nothing readable at {va:#x}")

    regions = _regions(engine, pid)
    fields: list[dict] = []
    for offset in range(0, size - (8 if align == 8 else align) + 1, align):
        raw = 8 if align == 8 else align
        chunk_samples = [blob[offset : offset + raw] for blob in blobs]
        values = [int.from_bytes(chunk, "little") for chunk in chunk_samples]
        distinct = len(set(values))
        field: dict = {"offset": hex(offset), "size": raw, "varies": distinct > 1}
        if len(chunk_samples) > 1:
            field["samples"] = [hex(value) for value in values[:4]]

        if all(value == 0 for value in values):
            field.update({"type": "zero", "confidence": "certain",
                          "note": "always zero across the samples (padding or unused)"})
            fields.append(field)
            continue

        if all(value and _mapped(regions, value) for value in values):
            field.update({"type": "pointer", "confidence": "certain" if distinct > 1 or raw == 8 else "likely"})
            if distinct == 1:
                field["points_to"] = hex(values[0])
                field.update({f"target_{k}": v for k, v in _context(engine, pid, values[0]).items()
                              if k in ("module", "module_offset")})
            fields.append(field)
            continue

        if raw == 8:
            highs = [value >> 32 for value in values]
            lows = [value & 0xFFFFFFFF for value in values]
            if all(high == 0 for high in highs):
                signed = [low - 0x100000000 if low & 0x80000000 else low for low in lows]
                field.update({"type": "int32", "confidence": "likely",
                              "alternatives": [f"uint32 {lows[0]}" if distinct == 1
                                               else "uint32 (non-negative reading)"]})
                if any(v < 0 for v in signed) and any(v >= 0 for v in signed):
                    field["type"] = "int32"
                # A float that happens to be small is common; keep it visible.
                floats = [_plausible_float(chunk[:4]) for chunk in chunk_samples]
                if all(f is not None for f in floats):
                    field.setdefault("alternatives", []).append(f"float {floats[0]!r}")
                fields.append(field)
                continue
            floats = [_plausible_float(chunk[:4]) for chunk in chunk_samples]
            if all(f is not None for f in floats):
                field.update({"type": "float", "confidence": "likely",
                              "alternatives": [f"int64 {values[0]}" if distinct == 1 else "int64"]})
                fields.append(field)
                continue
            field.update({"type": "int64", "confidence": "likely"})
            if distinct == 1:
                field["value"] = values[0]
            fields.append(field)
            continue

        field.update({"type": f"int{raw * 8}", "confidence": "likely"})
        # A 4-byte field that reads as a plausible float at every sample is
        # exactly what a coordinate or a timer looks like; offering only int32
        # would make the caller read `0x41200000` as 1092616192 and move on.
        floats = [_plausible_float(chunk[:4]) for chunk in chunk_samples] if raw >= 4 else []
        if floats and all(f is not None for f in floats):
            field.setdefault("alternatives", []).append(f"float {floats[0]!r}")
        if raw < 8:
            # At align=4 a qword pointer splits into two int32 fields, which reads
            # like two plain integers.  Check the qword that starts here and say so.
            qwords = [int.from_bytes(blob[offset : offset + 8], "little") for blob in blobs
                      if offset + 8 <= len(blob)]
            if len(qwords) == len(blobs) and all(value and _mapped(regions, value)
                                                for value in qwords):
                field.setdefault("alternatives", []).append(
                    f"pointer (qword at {hex(offset)} spans {hex(offset)}..{hex(offset + 8)})"
                )
        if distinct == 1:
            field["value"] = values[0]
        fields.append(field)

    # Inline character arrays: printable across every sample, terminated inside
    # the object.  Reported separately because they overlap the aligned fields.
    texts = _find_cstrings(blobs, size)
    notes = [*notes] if notes else []
    notes.extend([
        "types come from values, not from debug info: `pointer` means the qword "
        "landed in a mapped region every time, `int32` means the high dword was zero",
    ])
    if samples > 1:
        notes.append(f"{samples} samples at stride {step:#x}; `varies` marks fields that "
                     "differ between objects (per-instance data)")
    else:
        notes.append("one sample: an integer that looks like a pointer cannot be ruled out; "
                     "repeat with count= to compare objects")
    if texts:
        notes.append("inline strings overlap the aligned fields above")

    return {
        "pid": pid,
        "va": hex(va),
        "size": size,
        "align": align,
        "stride": step,
        "samples": len(blobs),
        "fields": fields,
        "strings": texts,
        "c_struct": _c_struct(va, fields, texts),
        "notes": notes,
    }


def _find_cstrings(blobs: list[bytes], size: int) -> list[dict]:
    """String fields in a struct, tolerating a value that differs per object.

    Names, ids and paths legitimately differ between samples, so requiring the
    same text at the same offset in every object would hide exactly the field we
    are looking for.  A field counts when at least half the samples hold a C string
    there, and every distinct value seen is listed.
    """
    out: list[dict] = []
    index = 0
    while index < size:
        values: list[str] = []
        longest = 0
        for blob in blobs:
            byte = blob[index]
            if not (32 <= byte < 127):
                continue
            end = index
            while end < min(size, len(blob)) and 32 <= blob[end] < 127:
                end += 1
            if end - index >= 3 and end < len(blob) and blob[end] == 0:
                text = blob[index:end].decode("ascii", "replace")
                longest = max(longest, end - index)
                if text not in values:
                    values.append(text)
        if longest and len(values) * 2 >= len(blobs):
            out.append({"offset": hex(index), "length": longest,
                        "text": values[0], "values": values})
            index += longest
        else:
            index += 1
    return out


def _choose_element_size(requested: int | None, sizes: list[int], span: int,
                         payload: bytes, regions) -> tuple[int, str]:
    """Resolve the element size and say where the number came from.

    Three signals, strongest first: what the caller said, the repeat period of
    "this qword is a mapped pointer" inside the span (a vector of structs has one),
    and finally the widest natural alignment that divides the span.  The source is
    reported so a number derived from evidence is never confused with a default,
    and ``counts`` lists what every other candidate would give.
    """
    if requested is not None:
        if requested <= 0 or span % requested:
            raise InvalidArgument(
                f"element_size {requested} does not divide the span {span:#x}; "
                f"try one of {sizes[:8]}"
            )
        return requested, "explicit"
    period = _period(payload, regions) if payload else None
    if period and period in sizes:
        return period, "pointer_rhythm"
    for preferred in (8, 4):
        if preferred in sizes:
            return preferred, "alignment"
    return sizes[0], "alignment"


def _c_struct(va: int, fields: list[dict], strings: list[dict]) -> str:
    name = f"live_{va:x}"
    lines = [f"// inferred from live memory at {va:#x} (heuristic, no debug info)", f"struct {name} {{"]
    string_offsets = {int(item["offset"], 16) for item in strings}
    for field in fields:
        offset = int(field["offset"], 16)
        if offset in string_offsets:
            continue
        ctype = _CTYPE.get(field["type"], "uint8_t")
        if field["type"] == "zero":
            lines.append(f"    /* {offset:#04x} */ uint8_t pad_{offset:x}[8];")
            continue
        lines.append(f"    /* {offset:#04x} */ {ctype} field_{offset:x};")
    for item in strings:
        lines.append(f"    /* {int(item['offset'], 16):#04x} */ char text_{int(item['offset'], 16):x}"
                     f"[{item['length'] + 1}];")
    lines.append("};")
    return "\n".join(lines)


# -- containers ------------------------------------------------------------
def detect_container(engine, pid: int, va: int, *, element_size: int | None = None) -> dict:
    """Decide what the 0x40 bytes at ``va`` most likely are, and expand it.

    ``element_size`` overrides the guess: a ``std::vector<T>`` only stores a byte
    span, so the element size has to come from you (or from the code that
    allocated it).  Every size that divides the span is listed with its resulting
    count, so the guess is never the only number on offer.

    Every candidate is a *layout hypothesis* checked against the data: pointer
    fields must be mapped, ``begin <= end <= end_of_storage`` must hold, and the
    byte span must divide evenly by element sizes.  Fitting several hypotheses is
    normal (a ``std::string`` and a ``std::vector<char>`` look alike), so all
    that fit are returned with their evidence and the strongest is marked.
    """
    data = engine.read_bytes(pid, va, 0x40)
    if len(data) < 0x20:
        raise BackendError(f"nothing readable at {va:#x}")
    regions = _regions(engine, pid)
    qwords = [int.from_bytes(data[index : index + 8], "little") for index in range(0, 32, 8)]
    first, second, third, fourth = qwords

    candidates: list[dict] = []

    # std::vector<T> (MSVC): {begin, end, capacity}
    if _mapped(regions, first) and _mapped_or_edge(regions, second) and _mapped_or_edge(regions, third) \
            and first <= second <= third:
        span = second - first
        room = third - first
        sizes = [size for size in ELEMENT_SIZES
                 if (span % size == 0) and (room % size == 0)]
        if sizes:
            payload = b""
            if span:
                try:
                    payload = engine.read_bytes(pid, first, min(span, 0x1000))
                except Exception:
                    payload = b""
            chosen, source = _choose_element_size(element_size, sizes, span, payload, regions)
            candidates.append({
                "kind": "std::vector<T>",
                "layout": {"begin": hex(first), "end": hex(second), "capacity": hex(third)},
                "element_size": chosen,
                "element_size_source": source,
                "element_size_guessed": source == "alignment",
                "element_size_candidates": sizes,
                "count": span // chosen,
                "counts": {str(size): span // size for size in sizes[:8]},
                "data_va": hex(first),
                "confidence": "strong" if span and chosen >= 4 else "plausible",
                "evidence": f"three mapped pointers, begin<=end<=capacity, span {span:#x} "
                            f"and capacity {room:#x} divide by {sizes[:4]}",
            })

    # Unreal TArray<T>: {Data, ArrayNum(int32), ArrayMax(int32)}
    # The high dwords must be zero: a real pointer in the count slot is exactly
    # the false positive that makes a vector look like a TArray.
    num = second & 0xFFFFFFFF
    max_num = third & 0xFFFFFFFF
    if _mapped(regions, first) and (second >> 32) == 0 and (third >> 32) == 0 \
            and 0 < num <= 0x1000000 and num <= max_num <= 0x1000000:
        sizes = [size for size in ELEMENT_SIZES if num * size <= 0x1000000]
        candidates.append({
            "kind": "TArray<T> / {ptr, count, capacity}",
            "layout": {"data": hex(first), "count": num, "capacity": max_num},
            "element_size": element_size,
            "element_size_candidates": sizes[:6] if sizes else [],
            "count": num,
            "data_va": hex(first),
            "confidence": "strong" if num > 1 else "plausible",
            "evidence": f"data pointer is mapped and count {num} <= capacity {max_num}",
        })

    # std::string: MSVC lays this out as a union of a 16-byte inline buffer and a
    # heap pointer, followed by *two* size_t fields (size at +0x10, capacity at
    # +0x18).  Reading the size from +0x08 is the classic mistake: that qword is
    # still inline text in the SSO case.
    string_candidates = []
    for unit, kind in ((1, "std::string"), (2, "std::wstring")):
        length = third
        capacity = fourth
        if not (0 < length <= 0x100000 and length <= capacity <= 0x100000):
            continue
        sso_limit = 16 if unit == 1 else 8
        if length <= sso_limit:
            text = data[: length * unit]
            if text and all(32 <= byte < 127 or byte == 0 for byte in text):
                string_candidates.append({
                    "kind": f"{kind} (SSO, inline)",
                    "layout": {"inline": text.hex(" "), "length": length, "capacity": capacity},
                    "value": text[: length * unit].replace(b"\x00", b"").decode("ascii", "replace"),
                    "element_size_candidates": [unit],
                    "count": length,
                    "data_va": hex(va + 0x10),
                    "confidence": "strong",
                    "evidence": f"length {length} < small-string capacity and the bytes are printable",
                })
            continue
        if _mapped(regions, first) and _mapped(regions, first + length * unit - 1):
            payload = engine.read_bytes(pid, first, min(length * unit, 256))
            if payload and all(32 <= byte < 127 or byte == 0 for byte in payload):
                string_candidates.append({
                    "kind": f"{kind} (heap)",
                    "layout": {"data": hex(first), "length": length, "capacity": capacity},
                    "value": payload.split(b"\x00", 1)[0].decode("utf-8", "replace"),
                    "element_size_candidates": [unit],
                    "count": length,
                    "data_va": hex(first),
                    "confidence": "strong",
                    "evidence": f"data pointer mapped, length {length}, capacity {capacity}",
                })
    candidates.extend(string_candidates)

    # A bare pointer + two integers is still worth naming: it is what most
    # hand-rolled containers look like.
    if not candidates and _mapped(regions, first) and second <= 0x1000000 and third <= 0x1000000:
        candidates.append({
            "kind": "{ptr, count, capacity}",
            "layout": {"data": hex(first), "count": second, "capacity": third},
            "element_size_candidates": [],
            "count": second,
            "data_va": hex(first),
            "confidence": "weak",
            "evidence": "first qword is a mapped pointer and the next two are small integers",
        })

    out: dict = {
        "pid": pid,
        "va": hex(va),
        "qwords": [hex(value) for value in qwords],
        "candidates": candidates,
        "notes": [
            "layouts are checked against the data, not assumed: several can fit at once",
            "`element_size_source` says whether the size was explicit, inferred from the "
            "pointer rhythm of the elements, or merely the widest alignment that divides",
        ],
    }
    out.update(_context(engine, pid, va))
    if candidates:
        out["primary"] = candidates[0]
    return out
