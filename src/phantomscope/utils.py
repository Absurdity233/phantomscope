"""Small parsing and formatting helpers used across the package."""

from __future__ import annotations

import re
import struct
from typing import Iterable

from .errors import InvalidArgument

_HEX_BYTES_RE = re.compile(r"^(?:0x)?([0-9a-fA-F]{2})(.*)$", re.S)


def parse_int(value: int | str | None, *, name: str = "value", default: int | None = None) -> int | None:
    """Parse ``123``, ``0x1234``, ``"0X1234"`` or ``"12h"`` into an int."""
    if value is None or value == "":
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, bool):  # bool is an int subclass; reject it explicitly
        raise InvalidArgument(f"{name} must be an integer")
    text = str(value).strip().replace("_", "")
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if text.lower().endswith("h") and re.fullmatch(r"[0-9a-fA-F]+h", text):
            return int(text[:-1], 16)
        return int(text, 10)
    except ValueError as exc:
        raise InvalidArgument(f"{name}: cannot parse integer from {value!r}") from exc


def parse_address(value: int | str, *, name: str = "address") -> int:
    """Like :func:`parse_int` but requires a value and allows ``module+0x10`` elsewhere."""
    result = parse_int(value, name=name)
    if result is None:
        raise InvalidArgument(f"{name} is required")
    return result


def parse_hex_bytes(value: str | bytes | bytearray, *, name: str = "data") -> bytes:
    """Parse hex input such as ``"48 8b ?? e8"`` (spaces optional) into bytes."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if not isinstance(value, str):
        raise InvalidArgument(f"{name} must be a hex string or bytes")
    text = value.strip()
    if not text:
        return b""
    text = text.replace("\\x", " ").replace("0x", " ").replace("0X", " ")
    text = re.sub(r"[\s,;:_-]+", "", text)
    if len(text) % 2:
        raise InvalidArgument(f"{name}: hex string has an odd number of nibbles")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise InvalidArgument(f"{name}: invalid hex string") from exc


def parse_int_list(values: Iterable[int | str] | None) -> list[int]:
    if not values:
        return []
    return [parse_address(v, name="offset") for v in values]


def hexdump(data: bytes, base: int = 0, *, width: int = 16, limit: int = 4096) -> str:
    """Classic hex + ASCII dump, capped at ``limit`` bytes."""
    view = data[:limit]
    lines: list[str] = []
    for offset in range(0, len(view), width):
        chunk = view[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + offset:016x}  {hex_part}  |{ascii_part}|")
    if len(data) > limit:
        lines.append(f"... ({len(data) - limit} more bytes)")
    return "\n".join(lines)


def preview_bytes(data: bytes, *, limit: int = 32) -> str:
    return " ".join(f"{b:02x}" for b in data[:limit])


def printable_ascii(data: bytes, *, limit: int = 64) -> str:
    out = []
    for b in data[:limit]:
        if b == 0:
            break
        out.append(chr(b) if 32 <= b < 127 else ".")
    return "".join(out)


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{size}B"


def unpack_value(data: bytes, value_type: str, offset: int = 0) -> int | float:
    """Unpack a typed value from ``data`` at ``offset``."""
    fmt = {
        "int8": "<b",
        "uint8": "<B",
        "int16": "<h",
        "uint16": "<H",
        "int32": "<i",
        "uint32": "<I",
        "int64": "<q",
        "uint64": "<Q",
        "float": "<f",
        "double": "<d",
    }.get(value_type)
    if fmt is None:
        raise InvalidArgument(f"unsupported value type: {value_type}")
    size = struct.calcsize(fmt)
    return struct.unpack_from(fmt, data, offset)[0]


VALUE_TYPE_SIZES = {
    "int8": 1,
    "uint8": 1,
    "int16": 2,
    "uint16": 2,
    "int32": 4,
    "uint32": 4,
    "int64": 8,
    "uint64": 8,
    "float": 4,
    "double": 8,
}


def value_type_size(value_type: str) -> int:
    try:
        return VALUE_TYPE_SIZES[value_type]
    except KeyError as exc:
        raise InvalidArgument(
            f"unsupported value type {value_type!r}; expected one of {sorted(VALUE_TYPE_SIZES)}"
        ) from exc


def pack_value(value: int | float, value_type: str) -> bytes:
    fmt = {
        "int8": "<b",
        "uint8": "<B",
        "int16": "<h",
        "uint16": "<H",
        "int32": "<i",
        "uint32": "<I",
        "int64": "<q",
        "uint64": "<Q",
        "float": "<f",
        "double": "<d",
    }.get(value_type)
    if fmt is None:
        raise InvalidArgument(f"unsupported value type: {value_type}")
    try:
        return struct.pack(fmt, value)
    except (struct.error, OverflowError) as exc:
        raise InvalidArgument(f"value {value!r} does not fit {value_type}") from exc
