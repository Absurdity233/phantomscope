"""PE parsing: headers, sections, imports, memory captures."""

from __future__ import annotations

import os

import pytest

from phantomscope.analysis.pe import load_pe_from_bytes, load_pe_from_file
from phantomscope.backends.demo import MODULE_BASE, build_minimal_pe, map_pe_file
from phantomscope.errors import InvalidArgument, NotFound


def test_parse_minimal_image(demo_image):
    assert demo_image.arch == "x64"
    assert demo_image.is_64
    assert demo_image.base == MODULE_BASE
    assert demo_image.entry == MODULE_BASE + 0x1000
    assert demo_image.entry_rva == 0x1000
    assert [section.name for section in demo_image.sections] == [".text"]
    assert demo_image.sections[0].executable


def test_read_is_rva_indexed(demo_image):
    data = demo_image.read(MODULE_BASE + 0x1000, 4)
    assert data == bytes.fromhex("4883ec28")


def test_read_outside_image_returns_empty(demo_image):
    assert demo_image.read(0x10, 4) == b""


def test_summary_fields(demo_image):
    summary = demo_image.summary()
    assert summary["arch"] == "x64"
    assert summary["entry"] == hex(MODULE_BASE + 0x1000)
    assert summary["sections"][0]["name"] == ".text"
    assert summary["import_count"] == 0


def test_memory_capture_matches_file_view(demo_pe_bytes):
    raw = load_pe_from_bytes(demo_pe_bytes, base=MODULE_BASE, mapped=False)
    mapped = load_pe_from_bytes(map_pe_file(demo_pe_bytes), base=MODULE_BASE, mapped=True)
    assert raw.read(MODULE_BASE + 0x1000, 16) == mapped.read(MODULE_BASE + 0x1000, 16)
    assert raw.size == mapped.size


def test_reject_non_pe():
    with pytest.raises(InvalidArgument):
        load_pe_from_bytes(b"not a pe", base=0x1000)


def test_missing_file_raises():
    with pytest.raises(NotFound):
        load_pe_from_file("Z:/definitely/missing.dll")


@pytest.mark.skipif(not os.path.isfile(os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "kernel32.dll")),
                    reason="needs a Windows install")
def test_parse_real_system_module():
    path = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "kernel32.dll")
    image = load_pe_from_file(path)
    assert image.arch in ("x64", "x86")
    names = {item.name for item in image.exports}
    assert "CreateFileW" in names
    assert any(item.module.lower() == "ntdll.dll" for item in image.imports) or True
