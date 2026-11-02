"""Disassembly, function discovery and cross references."""

from __future__ import annotations

import pytest

from phantomscope.analysis.disasm import Disassembler
from phantomscope.analysis.index import CodeIndex, IndexCache
from phantomscope.analysis.scan import extract_strings, parse_pattern, scan_bytes, scan_image
from phantomscope.backends.demo import MODULE_BASE


def test_disassembler_classifies_control_flow(demo_image):
    disasm = Disassembler.for_image(demo_image)
    instructions = disasm.disassemble_range(demo_image, MODULE_BASE + 0x1000, 0x40)
    kinds = [insn.kind for insn in instructions[:5]]
    assert kinds[0] == "plain"
    assert kinds[1] == "call"
    assert instructions[1].target == MODULE_BASE + 0x1015
    assert "ret" in kinds


def test_basic_blocks_are_bounded(demo_image):
    disasm = Disassembler.for_image(demo_image)
    instructions = disasm.disassemble_range(demo_image, MODULE_BASE + 0x1000, 0x20)
    blocks = disasm.basic_blocks(instructions)
    assert blocks
    assert blocks[0].start == MODULE_BASE + 0x1000
    assert blocks[-1].end <= MODULE_BASE + 0x1020


def test_index_finds_entry_and_callee(demo_image):
    index = IndexCache().get(demo_image)
    assert demo_image.entry in index.function_starts
    assert MODULE_BASE + 0x1015 in index.function_starts
    entry = index.function(demo_image.entry)
    assert entry is not None
    assert entry.source == "entry"


def test_index_callers_and_callees(demo_image):
    index = IndexCache().get(demo_image)
    callees = index.callees(demo_image.entry)
    assert MODULE_BASE + 0x1015 in callees
    callers = index.callers(MODULE_BASE + 0x1015)
    assert demo_image.entry in callers


def test_index_xrefs_contain_the_call(demo_image):
    index = IndexCache().get(demo_image)
    xrefs = index.xrefs_to(MODULE_BASE + 0x1015)
    assert any(xref.kind == "call" and xref.from_va == demo_image.entry + 4 for xref in xrefs)


def test_function_disassembly_stops_at_ret(demo_image):
    index = IndexCache().get(demo_image)
    instructions = index.disassemble_function(demo_image.entry)
    assert instructions[-1].mnemonic == "ret"
    assert instructions[0].va == demo_image.entry


def test_blocks_for_is_cached(demo_image):
    index = IndexCache().get(demo_image)
    first = index.blocks_for(demo_image.entry)
    second = index.blocks_for(demo_image.entry)
    assert first is second


def test_parse_pattern_wildcards():
    tokens = parse_pattern("48 8b ?? e8")
    assert tokens[0] == 0x48
    assert tokens[2] is None


def test_scan_bytes_with_wildcards():
    data = bytes.fromhex("488b0d00000000488b0500000000")
    hits = scan_bytes(data, "48 8b ?? 00")
    assert 0 in hits


def test_scan_image_is_rva_based(demo_image):
    hits = scan_image(demo_image, "48 83 ec 28")
    assert hits
    assert hits[0].va == demo_image.entry


def test_extract_strings_skips_code_by_default(demo_image):
    assert extract_strings(demo_image, min_length=4) == []
