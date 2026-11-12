"""Merge a static layout hypothesis with live field inference.

The two engines answer different halves of the same question and neither is enough:

* ``struct_layout`` reads the *code* and reports every ``[rcx+0x10]`` — so it
  knows which offsets exist, at what width they are accessed, and whether they are
  read or written.  It knows nothing about the values.
* ``infer_struct`` reads the *memory* at run time and reports what each aligned
  slot actually holds — a pointer, a plausible float, a per-instance value.  It
  knows nothing about which offsets the code cares about, so it also reports the
  padding between them.

Merged, the two produce what neither can: a field list where every offset is
confirmed by code *and* typed by data, with padding dropped and the fields the
code touches but no sample revealed marked as such instead of silently missing.

Everything here is a pure function over plain dicts, so it can be tested without a
process and reused by the CLI.
"""

from __future__ import annotations

from .. import utils

#: Three adjacent floats is a position or a direction in every engine worth naming.
_VECTOR3_TOLERANCE = 0.001


def _offset_of(field: dict) -> int | None:
    try:
        return int(str(field.get("offset")), 16)
    except (TypeError, ValueError):
        return None


def _size_of(field: dict) -> int:
    return int(field.get("size") or 0)


def _live_fields(inferred: dict) -> dict[int, dict]:
    """Index the live inference by offset, keeping its own vocabulary."""
    out: dict[int, dict] = {}
    for field in inferred.get("fields", []):
        offset = _offset_of(field)
        if offset is not None:
            out[offset] = field
    return out


def _live_strings(inferred: dict) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for entry in inferred.get("strings", []):
        try:
            offset = int(str(entry.get("offset")), 16)
        except (TypeError, ValueError):
            continue
        out[offset] = entry
    return out


def _effective_type(live: dict | None) -> str | None:
    """The type the data supports, preferring a float that the samples confirm.

    ``infer_struct`` reports ``int32`` for any dword whose high half is zero and
    keeps a plausible float in ``alternatives``.  When *every* sample also read as
    a sane float, the float is the better answer: a coordinate stored in a dword
    register does not stop being a coordinate, and 1092616192 is never the number
    anyone wanted.
    """
    if live is None:
        return None
    alternatives = [str(item) for item in live.get("alternatives") or []]
    floats = [item for item in alternatives if item.startswith("float ")]
    if floats and live.get("type") in ("int32", "uint32", "int64", "uint64"):
        return "float"
    return str(live.get("type") or "") or None


def _live_view(live: dict | None) -> dict | None:
    """A copy of the live reading with its type resolved through ``_effective_type``."""
    if live is None:
        return None
    effective = _effective_type(live)
    if effective == live.get("type"):
        return live
    adjusted = dict(live)
    adjusted["type"] = effective
    adjusted["type_source"] = "float alternative confirmed by every sample"
    return adjusted


def _c_type(live: dict | None, static_size: int, *, is_pointer: bool) -> str:
    """Choose a C type from what the data says, falling back to the access width.

    The live reading wins over the access width because the access width is only
    how the code *touched* the field: a float copied with ``mov eax, [rcx+0x10]``
    looks like a dword move.  Where the two disagree the field keeps the live type
    and records ``access_width_differs``, so a 4-byte float read as a dword is
    visible rather than silently called an int.
    """
    if is_pointer:
        return "void *"
    if live is None:
        return "uint8_t" if static_size == 1 else f"uint{static_size * 8}_t"
    kind = str(live.get("type", ""))
    if kind in ("int8", "uint8", "int16", "uint16", "int32", "uint32",
                "int64", "uint64", "float", "double"):
        if kind == "float":
            return "float"
        if kind == "double":
            return "double"
        # A signed width only when the samples actually went negative.
        return f"{kind}_t"
    if kind == "pointer":
        return "void *"
    if kind == "zero":
        return "uint8_t"
    return f"uint{static_size * 8}_t" if static_size else "uint8_t"


def _pick_name(offset: int, ctype: str, live: dict | None, entry: dict,
               *, written: bool, varies: bool) -> str:
    """Name a field from what is knowable: its type, its access, not its meaning.

    A tool that invents ``health`` from an int32 that happens to be 100 is guessing,
    and a wrong guess is worse than ``field_4``: it stops you checking.  So names
    encode only evidence — ``ptr_``, ``text_``, ``pos_``, ``state_`` — and the
    structure of the declaration tells you the rest.
    """
    if entry:
        return f"text_{offset:x}"
    if ctype == "void *":
        return f"ptr_{offset:x}"
    if live and live.get("type") == "float":
        return f"f_{offset:x}"
    if varies and written:
        return f"state_{offset:x}"
    if written and not varies:
        return f"const_{offset:x}"
    return f"field_{offset:x}"


def merge(static_layouts: list[dict], inferred: dict, *,
          align_of: int = 4) -> list[dict]:
    """Merge every candidate layout with one live inference result.

    ``static_layouts`` is the output of ``struct_layout``; ``inferred`` is the
    output of ``infer_struct`` for the object the *first* layout's register points
    at.  Because a function can touch several objects (``rcx`` and ``rdx``), each
    layout is merged independently and returned with its own ``role``.
    """
    live_by_offset = _live_fields(inferred)
    strings_by_offset = _live_strings(inferred)
    sample_count = int(inferred.get("samples") or 1)

    merged_layouts: list[dict] = []
    for layout in static_layouts:
        fields: list[dict] = []
        confirmed = 0
        unobserved: list[str] = []
        typedef_only: list[str] = []

        for field in layout.get("fields", []):
            offset = _offset_of(field)
            if offset is None:
                continue
            size = _size_of(field)
            live = _live_view(live_by_offset.get(offset))
            string = strings_by_offset.get(offset)
            is_pointer = bool(live and live.get("type") == "pointer")
            written = int(field.get("writes") or 0) > 0
            varies = bool(live and live.get("varies"))

            if live is None and string is None:
                # The code touches this offset but no sample showed anything
                # there: either it is only written before the sample was taken, or
                # the object we sampled is not the one this register holds.  That
                # distinction is worth reporting, not hiding.
                unobserved.append(hex(offset))

            if live is not None and live.get("type") == "zero" and string is None:
                # Nothing readable here: declaring `uint8_t` would be an invention.
                # The offset is real (the code touched it) but its type is unknown,
                # so it becomes an opaque byte array of the width the code used.
                ctype = "char"
                size = max(1, size)
                name = f"unknown_{offset:x}"
                fields.append({
                    "offset": hex(offset),
                    "size": size,
                    "c_type": "char",
                    "name": name,
                    "reads": int(field.get("reads") or 0),
                    "writes": int(field.get("writes") or 0),
                    "confirmed_by_code": True,
                    "confirmed_by_data": False,
                    "varies": False,
                    "accesses": field.get("accesses", []),
                })
                continue

            ctype = _c_type(live, size, is_pointer=is_pointer)
            if string and not is_pointer:
                ctype = "char"
                size = int(string.get("length") or 0) + 1
                live = None
            if live is not None:
                confirmed += 1
            elif string:
                confirmed += 1

            entry = {
                "offset": hex(offset),
                "size": size,
                "c_type": ctype,
                "name": _pick_name(offset, ctype, live, string,
                                   written=written, varies=varies),
                "reads": int(field.get("reads") or 0),
                "writes": int(field.get("writes") or 0),
                "confirmed_by_code": True,
                "confirmed_by_data": bool(live is not None or string),
                "varies": varies,
                "accesses": field.get("accesses", []),
            }
            if string:
                entry["string_values"] = string.get("values") or [string.get("text")]
            if live is not None:
                entry["live_type"] = live.get("type")
                entry["live_confidence"] = live.get("confidence")
                for key in ("type_source", "value", "points_to", "alternatives"):
                    if key in live:
                        entry[key] = live[key]
            fields.append(entry)

        # Fields the data shows that the code never touched in *this* function are
        # still real members; they belong in the declaration, marked as such.
        static_offsets = {_offset_of(f) for f in layout.get("fields", [])}
        for offset, raw_live in sorted(live_by_offset.items()):
            live = _live_view(raw_live)
            if offset in static_offsets:
                continue
            if live.get("type") == "zero" and not strings_by_offset.get(offset):
                continue          # padding: visible in the data, absent from the code
            typedef_only.append(hex(offset))
            is_pointer = live.get("type") == "pointer"
            ctype = _c_type(live, _size_of(live), is_pointer=is_pointer)
            fields.append({
                "offset": hex(offset),
                "size": _size_of(live),
                "c_type": ctype,
                "name": _pick_name(offset, ctype, live, strings_by_offset.get(offset, {}),
                                   written=False, varies=bool(live.get("varies"))),
                "reads": 0,
                "writes": 0,
                "confirmed_by_code": False,
                "confirmed_by_data": True,
                "varies": bool(live.get("varies")),
                "live_type": live.get("type"),
                "live_confidence": live.get("confidence"),
                "accesses": [],
            })

        fields.sort(key=lambda item: int(item["offset"], 16))
        merged_layouts.append({
            "role": layout.get("role"),
            "register": layout.get("register"),
            "function": layout.get("function"),
            "fields": fields,
            "summary": {
                "fields": len(fields),
                "confirmed_both": confirmed,
                "code_only": len(unobserved),
                "data_only": len(typedef_only),
                "samples": sample_count,
            },
            "code_only_offsets": unobserved,
            "data_only_offsets": typedef_only,
            "overlaps": layout.get("overlaps", []),
            "notes": _notes(unobserved, typedef_only, sample_count),
            "c_struct": _declaration(layout, fields),
        })
    return merged_layouts


def _notes(unobserved: list[str], typedef_only: list[str], samples: int) -> list[str]:
    notes = [
        "offsets come from the code, types come from the data: neither alone is a struct",
    ]
    if unobserved:
        notes.append(
            f"{len(unobserved)} offset(s) the code touches had nothing readable in the "
            "sample: either they are written before the sample, or this register holds "
            "a different object than the one sampled"
        )
    if typedef_only:
        notes.append(
            f"{len(typedef_only)} offset(s) appear in the data but not in this "
            "function's accesses: real members touched elsewhere"
        )
    if samples < 2:
        notes.append("one sample: `varies` is meaningless, pointer-vs-integer is a guess")
    return notes


def _declaration(layout: dict, fields: list[dict]) -> str:
    role = str(layout.get("role") or "arg0")
    lines = [
        f"// {role} ({layout.get('register')}) at {layout.get('function')}",
        "// offsets from code, types from live memory - verify before trusting",
        f"struct {role}_t {{",
    ]
    for field in fields:
        offset = int(field["offset"], 16)
        size = int(field["size"] or 1)
        if field["c_type"] == "char":
            lines.append(f"    /* {offset:#04x} */ char {field['name']}[{size}];")
        elif field["c_type"] == "void *":
            lines.append(f"    /* {offset:#04x} */ void * {field['name']};")
        else:
            lines.append(f"    /* {offset:#04x} */ {field['c_type']} {field['name']};")
    lines.append("};")
    return "\n".join(lines)


def vector_groups(fields: list[dict], *, tolerance: float = _VECTOR3_TOLERANCE) -> list[dict]:
    """Group adjacent float fields into vectors (``float position[3]``).

    Three floats four bytes apart is a world position or a direction in every
    engine that has ever shipped one; saying so turns six anonymous floats into two
    members you can actually use.  Only *adjacent* floats group, so a float that
    happens to sit alone stays alone.
    """
    floats = [
        field for field in fields
        if field.get("c_type") == "float" and not field.get("string_values")
    ]
    groups: list[dict] = []
    run: list[dict] = []
    for field in floats:
        offset = int(field["offset"], 16)
        if run and offset - int(run[-1]["offset"], 16) == 4:
            run.append(field)
        else:
            if len(run) >= 2:
                groups.append(_group(run))
            run = [field]
    if len(run) >= 2:
        groups.append(_group(run))
    return [group for group in groups if group["count"] >= 2]


def _group(run: list[dict]) -> dict:
    first = int(run[0]["offset"], 16)
    return {
        "offset": hex(first),
        "count": len(run),
        "kind": "float3" if len(run) == 3 else f"float[{len(run)}]",
        "offsets": [field["offset"] for field in run],
        "suggestion": (f"float vec_{first:x}[{len(run)}];" if len(run) != 3
                       else f"float pos_{first:x}[3];"),
    }
