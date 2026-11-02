"""String extraction, pattern scanning and RTTI/vtable discovery."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

from ..models import ScanHit
from .pe import PEImage

# ---------------------------------------------------------------------------
# Strings
# ---------------------------------------------------------------------------

_ASCII_RE = re.compile(rb"[\x20-\x7e\t\r\n]{4,}")
_WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def extract_strings(
    image: PEImage,
    *,
    min_length: int = 4,
    include_code: bool = False,
    limit: int = 20000,
) -> list[dict]:
    """ASCII and UTF-16LE strings with the virtual address of each one."""
    out: list[dict] = []
    for section in image.sections:
        if section.executable and not include_code:
            continue
        data = image.read(section.va, section.vsize)
        if not data:
            continue
        for match in _ASCII_RE.finditer(data):
            out.append(
                {
                    "va": section.va + match.start(),
                    "encoding": "ascii",
                    "text": match.group().decode("ascii", "replace"),
                    "section": section.name,
                }
            )
            if len(out) >= limit:
                return out
        for match in _WIDE_RE.finditer(data):
            out.append(
                {
                    "va": section.va + match.start(),
                    "encoding": "utf16",
                    "text": match.group().decode("utf-16le", "replace"),
                    "section": section.name,
                }
            )
            if len(out) >= limit:
                return out
    out.sort(key=lambda item: (item["va"], item["encoding"]))
    return out


# ---------------------------------------------------------------------------
# AOB patterns
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"^(?:[0-9a-fA-F]{2}|\?{1,2})$")


def parse_pattern(pattern: str) -> list[int | None]:
    """Parse ``"48 8B ?? 89"`` into tokens.  ``??`` matches any byte."""
    text = pattern.replace("\\x", " ").replace("0x", " ").strip()
    tokens: list[int | None] = []
    for raw in text.split():
        if raw in ("?", "??", "*"):
            tokens.append(None)
            continue
        if not _TOKEN_RE.match(raw):
            raise ValueError(f"invalid pattern token: {raw!r}")
        tokens.append(int(raw, 16))
    if not tokens:
        raise ValueError("empty pattern")
    return tokens


def scan_bytes(data: bytes, tokens: "str | bytes | list[int | None]", *, base: int = 0,
               limit: int = 1000, alignment: int = 1) -> list[int]:
    """Return absolute addresses of every match in ``data``.

    ``tokens`` may be a pattern string, raw bytes, or parsed tokens.
    """
    if isinstance(tokens, (str, bytes)):
        tokens = parse_pattern(tokens)
    n = len(tokens)
    if n == 0 or len(data) < n:
        return []
    anchors = [i for i, token in enumerate(tokens) if token is not None]
    if not anchors:
        step = max(alignment, n)
        return [base + offset for offset in range(0, len(data) - n + 1, step)][:limit]
    first = anchors[0]
    needle = bytes([tokens[first]])
    hits: list[int] = []
    position = data.find(needle, first)
    while position != -1:
        start = position - first
        ok = start >= 0 and start + n <= len(data)
        if ok and (base + start) % alignment == 0:
            for index, token in enumerate(tokens):
                if token is not None and data[start + index] != token:
                    ok = False
                    break
        if ok:
            hits.append(base + start)
            if len(hits) >= limit:
                break
        position = data.find(needle, position + 1)
    return hits


def scan_image(
    image: PEImage,
    pattern: str | bytes,
    *,
    limit: int = 500,
    sections: list[str] | None = None,
    executable_only: bool = False,
) -> list[ScanHit]:
    if isinstance(pattern, str):
        tokens = parse_pattern(pattern)
    else:
        tokens = list(pattern)
    wanted = {name.lower() for name in sections} if sections else None
    hits: list[ScanHit] = []
    for section in image.sections:
        if executable_only and not section.executable:
            continue
        if wanted is not None and section.name.lower() not in wanted:
            continue
        data = image.read(section.va, section.vsize)
        for address in scan_bytes(data, tokens, base=section.va, limit=limit - len(hits)):
            offset = address - section.va
            hits.append(
                ScanHit(
                    va=address,
                    module=image.path,
                    region_base=section.va,
                    region_size=section.vsize,
                    preview=data[offset : offset + 24].hex(" "),
                )
            )
            if len(hits) >= limit:
                return hits
    return hits


# ---------------------------------------------------------------------------
# RTTI / vtables
# ---------------------------------------------------------------------------

_MANGLED_NAME_RE = re.compile(rb"\.\?AV([A-Za-z0-9_@?$<>:,\-]{1,200})@@")


@dataclass
class RTTIType:
    name: str
    descriptor_va: int
    vtable_va: int | None = None
    functions: list[int] | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "descriptor_va": hex(self.descriptor_va),
            "vtable_va": hex(self.vtable_va) if self.vtable_va else None,
            "functions": [hex(f) for f in self.functions or []],
        }


def find_rtti(image: PEImage, *, limit: int = 500, max_scan_bytes: int = 8 * 1024 * 1024) -> list[RTTIType]:
    """Best-effort MSVC RTTI discovery (x64 layout).

    1. find ``.?AV<name>@@`` type-descriptor names in data sections;
    2. the descriptor begins 16 bytes before the name (vftable + spare);
    3. a complete object locator stores the descriptor VA/RVA at +0x0C;
    4. a vtable stores that locator pointer in the quadword before its first
       function slot.

    Both absolute VAs (memory images) and RVAs (files with relocations) are
    accepted, which is why every pointer is tested twice.
    """
    if not image.is_64:
        return []
    base = image.base
    end = base + image.size
    results: list[RTTIType] = []
    descriptors: list[tuple[int, str]] = []

    budget = max_scan_bytes
    for section in image.sections:
        if section.executable:
            continue
        data = image.read(section.va, section.vsize)
        budget -= len(data)
        for match in _MANGLED_NAME_RE.finditer(data):
            name = match.group(1).decode("ascii", "replace")
            descriptor_va = section.va + match.start() - 0x10
            descriptors.append((descriptor_va, name))
            if budget <= 0:
                break
        if budget <= 0:
            break

    def normalise(value: int) -> int | None:
        if base <= value < end:
            return value
        if 0 < value < image.size:
            return base + value
        return None

    for descriptor_va, name in descriptors[:limit]:
        found = None
        for section in image.sections:
            if section.executable:
                continue
            data = image.read(section.va, section.vsize)
            needle = struct.pack("<Q", descriptor_va)
            alt = struct.pack("<I", descriptor_va - base)
            position = data.find(needle)
            if position == -1:
                position = data.find(alt)
                if position == -1:
                    continue
                width = 4
            else:
                width = 8
            col_va = section.va + position - 0x0C
            if col_va < section.va:
                continue
            for vsec in image.sections:
                if vsec.executable:
                    continue
                vdata = image.read(vsec.va, vsec.vsize)
                for pointer in (struct.pack("<Q", col_va), struct.pack("<I", col_va - base)):
                    vpos = vdata.find(pointer)
                    if vpos != -1:
                        found = vsec.va + vpos + len(pointer)
                        break
                if found:
                    break
            if found:
                break
        if not found:
            results.append(RTTIType(name=name, descriptor_va=descriptor_va))
            continue
        functions: list[int] = []
        for index in range(64):
            chunk = image.read(found + index * 8, 8)
            if len(chunk) < 8:
                break
            value = normalise(int.from_bytes(chunk, "little"))
            if value is None or not image.is_executable_va(value):
                break
            functions.append(value)
        results.append(RTTIType(name=name, descriptor_va=descriptor_va, vtable_va=found, functions=functions))
    return results
