"""Struct layout inference and module-global discovery."""

from __future__ import annotations

import pytest

from phantomscope.analysis.index import IndexCache
from phantomscope.analysis.structs import (
    ARG_ROLES,
    globals_touched,
    infer_layout,
)
from phantomscope.backends.demo import MODULE_BASE, build_struct_demo_pe, build_minimal_pe
from phantomscope.analysis.pe import load_pe_from_bytes

STRUCT_FN = MODULE_BASE + 0x1030


@pytest.fixture()
def struct_index():
    image = load_pe_from_bytes(build_struct_demo_pe(), base=MODULE_BASE, mapped=False)
    return IndexCache().get(image)


@pytest.fixture()
def demo_index():
    image = load_pe_from_bytes(build_minimal_pe(), base=MODULE_BASE, mapped=False)
    return IndexCache().get(image)


def test_layout_groups_accesses_by_role(struct_index):
    layouts = infer_layout(struct_index, STRUCT_FN)
    assert len(layouts) == 1
    layout = layouts[0]
    assert layout.role == "arg0"
    assert layout.register == "rcx"
    assert layout.function == STRUCT_FN


def test_layout_offsets_and_sizes(struct_index):
    layout = infer_layout(struct_index, STRUCT_FN)[0]
    fields = {f.offset: f for f in layout.fields}
    assert sorted(fields) == [0x8, 0xC, 0x10, 0x14, 0x18]
    assert fields[0x8].size == 8     # mov rdx, [rcx+8]
    assert fields[0x10].size == 4    # mov eax, [rcx+0x10]
    assert fields[0x14].size == 4


def test_layout_marks_reads_and_writes(struct_index):
    fields = {f.offset: f for f in infer_layout(struct_index, STRUCT_FN)[0].fields}
    assert fields[0x10].reads == 1 and fields[0x10].writes == 0
    assert fields[0x14].writes == 1 and fields[0x14].reads == 0
    assert fields[0xC].reads == 1     # cmp [rcx+0xc], 0 is a read


def test_layout_span_covers_last_field(struct_index):
    layout = infer_layout(struct_index, STRUCT_FN)[0]
    # Span is the total extent from the lowest to the highest observed field.
    assert layout.min_offset == 0x8
    assert layout.span == (0x18 + 4) - 0x8


def test_layout_keeps_instruction_evidence(struct_index):
    layout = infer_layout(struct_index, STRUCT_FN)[0]
    field = next(f for f in layout.fields if f.offset == 0x10)
    assert field.accesses[0].va == STRUCT_FN
    assert "rcx + 0x10" in field.accesses[0].text
    assert field.accesses[0].mnemonic == "mov"


def test_layout_reports_wide_overlap(struct_index):
    layout = infer_layout(struct_index, STRUCT_FN)[0]
    # The 8-byte read at 0x8 covers 0xc, which is called out but not fatal.
    assert layout.overlaps
    assert "0x8" in layout.overlaps[0]


def test_layout_ignores_stack_and_globals(demo_index):
    # The demo entry function only touches the stack and a RIP-relative global.
    assert infer_layout(demo_index, MODULE_BASE + 0x1000) == []


def test_globals_touched_finds_rip_relative_targets(demo_index):
    refs = globals_touched(demo_index, MODULE_BASE + 0x1015)
    targets = {ref.target for ref in refs}
    assert MODULE_BASE + 0x1080 in targets
    reads = [r for r in refs if r.access == "read"]
    writes = [r for r in refs if r.access == "write"]
    assert reads and writes
    assert reads[0].size == 4


def test_globals_touched_empty_for_struct_function(struct_index):
    # struct_update only uses register-relative operands.
    assert globals_touched(struct_index, STRUCT_FN) == []


def test_arg_roles_cover_microsoft_x64_registers():
    assert ARG_ROLES["rcx"] == "arg0"
    assert ARG_ROLES["r8d"] == "arg2"
    assert ARG_ROLES["r9w"] == "arg3"
