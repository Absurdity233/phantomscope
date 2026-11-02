"""Parsing and formatting helpers."""

from __future__ import annotations

import pytest

from phantomscope.errors import InvalidArgument
from phantomscope.utils import (
    hexdump,
    human_size,
    pack_value,
    parse_address,
    parse_hex_bytes,
    parse_int,
    unpack_value,
    value_type_size,
)


def test_parse_int_forms():
    assert parse_int("0x10") == 16
    assert parse_int("16") == 16
    assert parse_int("10h") == 16
    assert parse_int(16) == 16
    assert parse_int("", default=3) == 3
    with pytest.raises(InvalidArgument):
        parse_int("nope")


def test_parse_address_requires_value():
    assert parse_address("0x140001000") == 0x140001000
    with pytest.raises(InvalidArgument):
        parse_address("")


def test_parse_hex_bytes_tolerates_separators():
    assert parse_hex_bytes("48 8b 05") == b"\x48\x8b\x05"
    assert parse_hex_bytes("0x48,0x8b") == b"\x48\x8b"
    assert parse_hex_bytes("488b") == b"\x48\x8b"
    assert parse_hex_bytes(b"\x90\x90") == b"\x90\x90"
    with pytest.raises(InvalidArgument):
        parse_hex_bytes("4")


def test_hexdump_layout():
    dump = hexdump(b"ABCD", base=0x1000)
    assert dump.startswith("0000000000001000")
    assert "|ABCD|" in dump


def test_typed_values_roundtrip():
    for value_type, value in [("uint8", 200), ("int32", -5), ("uint64", 2**63), ("float", 1.5)]:
        size = value_type_size(value_type)
        packed = pack_value(value, value_type)
        assert len(packed) == size
        assert unpack_value(packed, value_type) == pytest.approx(value)


def test_value_type_size_rejects_unknown():
    with pytest.raises(InvalidArgument):
        value_type_size("decimal")


def test_human_size():
    assert human_size(512) == "512B"
    assert human_size(2048) == "2.0KB"
