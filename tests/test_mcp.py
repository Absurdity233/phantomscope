"""The MCP surface: tools are plain functions, so exercise them directly."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from phantomscope import mcp_server as mcp
from phantomscope.backends.demo import DEMO_PID, HEAP_BASE, MODULE_BASE, build_minimal_pe


@pytest.fixture(autouse=True)
def clean_state():
    mcp.STATE.manager.reset()
    mcp.STATE.static.images.clear()
    yield
    mcp.STATE.manager.reset()
    mcp.STATE.static.images.clear()


def load(payload: str) -> dict:
    return json.loads(payload)


def test_session_open_with_mock():
    result = load(mcp.session_open(device="mock", backend="mock"))
    assert result["kind"] == "mock"
    assert result["processes"] == 1


def test_attach_and_process_tools():
    mcp.session_open(device="mock", backend="mock")
    attached = load(mcp.attach("demo_target"))
    assert attached["attached"]["pid"] == DEMO_PID
    listed = load(mcp.processes())
    assert listed[0]["pid"] == DEMO_PID
    modules = load(mcp.modules())
    assert modules[0]["name"] == "demo_target.exe"


def test_read_write_patch_cycle():
    mcp.session_open(device="mock", backend="mock")
    mcp.attach(str(DEMO_PID))
    read = load(mcp.read_typed(va=hex(HEAP_BASE + 0x120), value_type="int32"))
    assert read["value"] == 100

    written = load(mcp.write(va=hex(HEAP_BASE + 0x120), value="250", value_type="int32",
                             note="mcp-test"))
    assert written["id"] == 1

    patched = load(mcp.read_typed(va=hex(HEAP_BASE + 0x120), value_type="int32"))
    assert patched["value"] == 250

    journal = load(mcp.patch_list())
    assert len(journal) == 1

    restored = load(mcp.patch_restore(patch_id=written["id"]))
    assert restored["restored"] is True
    assert load(mcp.read_typed(va=hex(HEAP_BASE + 0x120), value_type="int32"))["value"] == 100


def test_scan_tools():
    mcp.session_open(device="mock", backend="mock")
    mcp.attach(str(DEMO_PID))
    scan = load(mcp.scan_value("100", "int32", label="health"))
    assert scan["count"] >= 1
    narrowed = load(mcp.scan_next("health", "100"))
    assert narrowed["count"] >= 1
    results = load(mcp.scan_results("health"))
    assert results["count"] >= 1


def test_aob_tool():
    mcp.session_open(device="mock", backend="mock")
    mcp.attach(str(DEMO_PID))
    hits = load(mcp.scan_aob("48 83 ec 28"))
    assert hits and hits[0]["va"] == MODULE_BASE + 0x1000


def test_static_tools_after_capture(tmp_path):
    mcp.session_open(device="mock", backend="mock")
    mcp.attach(str(DEMO_PID))
    captured = load(mcp.capture_module("demo_target.exe", key="cap"))
    assert captured["key"] == "cap"
    assert captured["summary"]["arch"] == "x64"

    summary = load(mcp.image_summary("cap"))
    assert summary["entry"] == hex(MODULE_BASE + 0x1000)

    instructions = load(mcp.disassemble("cap", "", count=4))
    assert instructions[0]["mnemonic"] == "sub"

    functions = load(mcp.functions("cap"))
    assert any(item["source"] == "entry" for item in functions)

    callees = load(mcp.callees("cap", hex(MODULE_BASE + 0x1000)))
    assert hex(MODULE_BASE + 0x1015) in callees

    assert load(mcp.basic_blocks("cap", hex(MODULE_BASE + 0x1000)))


def test_load_file_tool(tmp_path, demo_pe_bytes):
    target = tmp_path / "demo.exe"
    target.write_bytes(demo_pe_bytes)
    loaded = load(mcp.load_file(str(target), key="file-demo"))
    assert loaded["summary"]["arch"] == "x64"
    assert load(mcp.images()) == ["file-demo"]
    assert load(mcp.unload_image("file-demo"))["unloaded"] is True


def test_session_close_all():
    mcp.session_open(device="mock", backend="mock")
    closed = load(mcp.session_close(None))
    assert closed["closed"] == "all"
    assert load(mcp.session_list()) == []


def test_errors_are_reported_as_json():
    payload = load(mcp.read("0x1000"))  # no session open
    assert payload["error"] in ("invalid_argument", "unavailable", "not_found")


def test_server_info_lists_tools_state():
    info = load(mcp.server_info())
    assert info["name"] == "phantomscope"
    assert "images" in info


@pytest.mark.asyncio
async def test_tool_registry_is_complete():
    tools = await mcp.server.list_tools()
    names = {tool.name for tool in tools}
    for expected in (
        "session_open", "processes", "modules", "read", "write", "scan_aob",
        "load_file", "capture_module", "disassemble", "xrefs_to", "rtti",
        "emu_create", "emu_step", "emu_watch",
        "physical_info", "physical_read", "translate", "virtual_read", "walk",
        "physical_images", "capture_image",
        "struct_layout", "globals_touched",
    ):
        assert expected in names


def test_struct_layout_tool(tmp_path):
    from phantomscope.backends.demo import MODULE_BASE, build_struct_demo_pe

    target = tmp_path / "struct.exe"
    target.write_bytes(build_struct_demo_pe())
    load(mcp.load_file(str(target), key="structdemo"))

    layouts = load(mcp.struct_layout("structdemo", hex(MODULE_BASE + 0x1030)))
    assert layouts[0]["role"] == "arg0"
    assert [f["offset"] for f in layouts[0]["fields"]] == ["0x8", "0xc", "0x10", "0x14", "0x18"]

    # Any address inside the function resolves to its start first.
    same = load(mcp.struct_layout("structdemo", hex(MODULE_BASE + 0x1033)))
    assert same == layouts

    # The entry function touches only the stack and a global, so no layout.
    assert load(mcp.struct_layout("structdemo", hex(MODULE_BASE + 0x1004))) == []


def test_globals_touched_tool(tmp_path):
    from phantomscope.backends.demo import MODULE_BASE, build_minimal_pe

    target = tmp_path / "globals.exe"
    target.write_bytes(build_minimal_pe())
    load(mcp.load_file(str(target), key="globals"))

    refs = load(mcp.globals_touched("globals", hex(MODULE_BASE + 0x1015)))
    assert any(ref["target"] == hex(MODULE_BASE + 0x1080) for ref in refs)


def test_physical_tools_reject_a_non_physical_session():
    mcp.session_open(device="mock", backend="mock")
    payload = load(mcp.physical_info())
    assert payload["error"] == "invalid_argument"
    assert "physical" in payload["message"]


def test_physical_session_end_to_end(tmp_path, demo_pe_bytes):
    """Open a dump through the physical backend and analyse a discovered PE."""
    from phantomscope.backends.demo import map_pe_file
    from tests.test_physical import _build_dump, PE_PA

    dump = _build_dump(tmp_path / "mcp.raw", map_pe_file(demo_pe_bytes))
    opened = load(mcp.session_open(backend="physical", device=dump))
    assert opened["kind"] == "physical"

    info = load(mcp.physical_info())
    assert info["kind"] == "physical"
    assert info["mapped_bytes"] == 0x40_0000

    assert load(mcp.physical_read(hex(PE_PA), 2, dump=False))["hex"] == "4d5a"

    hits = load(mcp.physical_images())
    assert [hit["pa"] for hit in hits] == [hex(PE_PA)]

    translated = load(mcp.translate("0x7ff600001000", "0x200000"))
    assert translated["mapped"] is True
    assert translated["pa"] == "0x101000"

    walked = load(mcp.walk("0x7ff600000000", 0x3000, "0x200000"))
    assert walked["present"] == 3

    captured = load(mcp.capture_image(hex(PE_PA), key="physmcp"))
    assert captured["summary"]["arch"] == "x64"
    assert captured["summary"]["entry"] == "0x7ff600001000"

    instructions = load(mcp.disassemble("physmcp", "", count=3))
    assert instructions[0]["mnemonic"] == "sub"
    assert load(mcp.functions("physmcp"))[0]["source"] == "entry"
