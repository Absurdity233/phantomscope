"""Pseudo-C recovery: structure, conditions, names and honest confidence."""

from __future__ import annotations

import pytest

from phantomscope.analysis.index import IndexCache
from phantomscope.analysis.pe import load_pe_from_bytes
from phantomscope.analysis.pseudo import decompile
from phantomscope.backends.demo import (
    MODULE_BASE,
    build_api_demo_pe,
    build_flow_demo_pe,
)


@pytest.fixture()
def flow_index():
    image = load_pe_from_bytes(build_flow_demo_pe(), base=MODULE_BASE, path="flow", mapped=False)
    return IndexCache().get(image)


def text_of(result: dict) -> str:
    return result["text"]


def test_loop_is_rebuilt_as_while_with_break(flow_index):
    result = decompile(flow_index, MODULE_BASE + 0x1000)
    text = text_of(result)
    assert len(result["loops"]) == 1
    assert "while (1) {" in text
    # The header's `test ecx, ecx; jle` guards the loop, and the latch breaks out.
    assert "if (arg0 > 0) {" in text
    assert "eax += arg0;" in text
    assert "if (ecx == 0) break;" in text
    assert "return eax;" in text
    assert result["confidence"] in ("high", "medium")


def test_signature_matches_the_arguments_the_body_uses(flow_index):
    result = decompile(flow_index, MODULE_BASE + 0x1000)
    header = text_of(result).splitlines()[0]
    assert header == "// int32_t sub_1000(int64_t arg0)"
    assert result["signature"].startswith("int32_t sub_1000(")


def test_if_else_with_two_returns(flow_index):
    text = text_of(decompile(flow_index, MODULE_BASE + 0x1020))
    assert "if (arg0 > 5) {" in text
    assert "eax = 0x64;" in text
    assert "eax = 7;" in text
    assert text.count("return eax;") == 2


def test_internal_calls_are_named(flow_index):
    result = decompile(flow_index, MODULE_BASE + 0x1040)
    assert "sub_1000();" in text_of(result)
    assert "sub_1020();" in text_of(result)
    assert len(result["calls"]) == 2


def test_imports_and_strings_are_resolved_in_the_body():
    image = load_pe_from_bytes(build_api_demo_pe(), base=MODULE_BASE, path="api", mapped=False)
    index = IndexCache().get(image)
    result = decompile(index, MODULE_BASE + 0x1000)
    text = text_of(result)
    assert 'rcx = "demo-secret-key";' in text
    assert "KERNEL32.dll!Sleep();" in text
    assert "KERNEL32.dll!GetTickCount();" in text
    assert set(result["imports"]) == {"KERNEL32.dll!Sleep", "KERNEL32.dll!GetTickCount"}


def test_result_shape_is_stable(flow_index):
    result = decompile(flow_index, MODULE_BASE + 0x1000)
    for key in ("function", "name", "signature", "text", "blocks", "instructions",
                "loops", "calls", "imports", "strings", "writes_memory",
                "unmodelled", "confidence", "notes"):
        assert key in result
    assert result["function"] == hex(MODULE_BASE + 0x1000)


def test_comments_can_be_turned_off(flow_index):
    plain = decompile(flow_index, MODULE_BASE + 0x1000, include_comments=False)["text"]
    body = plain.splitlines()[2:]
    assert not any("  //" in line for line in body)
    # the signature header stays: it is the result, not a comment about the code
    assert plain.startswith("// int32_t sub_1000")


def test_address_between_functions_resolves_to_the_containing_one(flow_index):
    inside = decompile(flow_index, MODULE_BASE + 0x1024)
    assert inside["function"] == hex(MODULE_BASE + 0x1020)


def test_non_executable_address_is_refused_with_a_reason(flow_index):
    from phantomscope.errors import Unavailable

    with pytest.raises(Unavailable):
        decompile(flow_index, 0x1000)
