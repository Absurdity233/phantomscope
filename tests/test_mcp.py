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
    mcp.STATE.clear_static()
    yield
    mcp.STATE.manager.reset()
    mcp.STATE.clear_static()


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


def test_scan_results_is_session_scoped():
    mcp.session_open(device="mock", backend="mock", name="a")
    mcp.session_open(device="mock", backend="mock", name="b")
    mcp.attach(str(DEMO_PID), session="a")
    assert load(mcp.scan_value("100", "int32", label="hp", session="a"))["count"] >= 1
    # The scan lives in session a, so session b cannot see it.
    assert load(mcp.scan_results("hp", session="b"))["error"] == "not_found"
    assert load(mcp.scan_results("hp", session="a"))["count"] >= 1


def test_static_images_are_per_session(tmp_path, demo_pe_bytes):
    target = tmp_path / "demo.exe"
    target.write_bytes(demo_pe_bytes)
    mcp.session_open(device="mock", backend="mock", name="a")
    mcp.session_open(device="mock", backend="mock", name="b")
    mcp.attach(str(DEMO_PID), session="a")
    mcp.attach(str(DEMO_PID), session="b")

    load(mcp.capture_module("demo_target.exe", key="cap", session="a"))
    assert load(mcp.images(session="a")) == ["cap"]
    assert load(mcp.images(session="b")) == []

    # A bare key still resolves to whichever engine owns it.
    assert load(mcp.image_summary("cap"))["arch"] == "x64"

    # Loading a file without a session lands in the standalone engine.
    load(mcp.load_file(str(target), key="disk"))
    assert "disk" not in load(mcp.images(session="a"))
    assert load(mcp.images(session="b")) == []


def test_kernel_and_handle_tools():
    mcp.session_open(device="mock", backend="mock")
    mcp.attach(str(DEMO_PID))

    kernel = load(mcp.kernel_modules())
    assert [m["name"] for m in kernel] == ["ntoskrnl.exe", "demo_driver.sys"]
    assert load(mcp.kernel_processes())[0]["pid"] == DEMO_PID

    all_handles = load(mcp.handles())
    assert len(all_handles) == 2
    files = load(mcp.handles(filter="file"))
    assert [h["type"] for h in files] == ["File"]
    assert load(mcp.heaps())[0]["va"] == HEAP_BASE


def test_unload_image_drops_its_emulator():
    mcp.session_open(device="mock", backend="mock")
    mcp.attach(str(DEMO_PID))
    load(mcp.capture_module("demo_target.exe", key="cap"))
    load(mcp.emu_create(key="cap"))
    assert load(mcp.emu_step(key="cap", count=1))["to"]

    assert load(mcp.unload_image("cap"))["unloaded"] is True
    assert load(mcp.emu_step(key="cap", count=1))["error"] == "not_found"


def test_image_key_collision_across_sessions_is_refused(tmp_path, demo_pe_bytes):
    target = tmp_path / "demo.exe"
    target.write_bytes(demo_pe_bytes)
    mcp.session_open(device="mock", backend="mock", name="a")
    mcp.session_open(device="mock", backend="mock", name="b")
    mcp.attach(str(DEMO_PID), session="a")
    mcp.attach(str(DEMO_PID), session="b")

    load(mcp.capture_module("demo_target.exe", key="cap", session="a"))
    clash = load(mcp.capture_module("demo_target.exe", key="cap", session="b"))
    assert clash["error"] == "invalid_argument"
    assert "already used" in clash["message"]


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
        "kernel_modules", "kernel_processes", "handles", "heaps",
        # reverse-engineering depth added on top of the original surface
        "decompile", "api_calls", "api_sites", "find_api", "string_xrefs",
        "fingerprint", "find_similar", "match_functions", "diff_images",
        "packing_report", "crypto_constants", "search_immediates",
        "rename_function", "set_comment", "annotations", "clear_annotations",
        "emu_stubs", "emu_calls", "emu_stub_list",
        # dynamic analysis depth: structure recovery, tracing, emulator coverage
        "read_object", "read_array", "infer_struct", "detect_container",
        "expand_container", "resolve_pointer_chain", "pointer_chain_replay",
        "snapshot_module", "diff_module", "trace_changes", "trace_value",
        "emu_trace", "emu_coverage", "emu_reached", "emu_faults",
        "emu_close", "scan_strings", "export_module", "save_image",
        "patch_apply", "static_patch_list", "static_patch_restore",
        "live_struct_layout",
    ):
        assert expected in names
    assert len(names) >= 112


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

def test_decompile_and_naming_tools(tmp_path):
    from phantomscope.backends.demo import build_flow_demo_pe

    target = tmp_path / "flow.dll"
    target.write_bytes(build_flow_demo_pe())
    load(mcp.load_file(str(target), key="flowmcp"))

    lifted = load(mcp.decompile("flowmcp", hex(MODULE_BASE + 0x1000)))
    assert "while (1) {" in lifted["text"]
    assert lifted["confidence"] in ("high", "medium")

    renamed = load(mcp.rename_function("flowmcp", hex(MODULE_BASE + 0x1000), "sum_loop"))
    assert renamed["name"] == "sum_loop"
    assert renamed["saved"] is True
    assert any(row.get("name") == "sum_loop" for row in load(mcp.functions("flowmcp")))

    commented = load(mcp.set_comment("flowmcp", hex(MODULE_BASE + 0x1000), "counts down ecx"))
    assert commented["saved"] is True
    listing = load(mcp.annotations("flowmcp"))
    assert listing["counts"] == {"functions": 1, "comments": 1, "notes": 0}

    assert load(mcp.clear_annotations("flowmcp"))["removed"] == 2


def test_api_string_and_triage_tools(tmp_path):
    from phantomscope.backends.demo import build_api_demo_pe

    target = tmp_path / "api.dll"
    target.write_bytes(build_api_demo_pe())
    load(mcp.load_file(str(target), key="apimcp"))

    calls = load(mcp.api_calls("apimcp"))
    assert {row["name"] for row in calls} == {"Sleep", "GetTickCount"}
    assert load(mcp.api_sites("apimcp"))[0]["slot"] == hex(MODULE_BASE + 0x1030)
    assert load(mcp.find_api("apimcp", "GetTick"))["sites"][0]["apis"] == ["KERNEL32.dll!GetTickCount"]

    strings = load(mcp.string_xrefs("apimcp", contains="secret"))
    assert strings["strings"][0]["text"] == "demo-secret-key"
    assert strings["strings"][0]["refs"][0]["from"] == hex(MODULE_BASE + 0x100F)

    triage = load(mcp.packing_report("apimcp"))
    assert 0 <= triage["score"] <= 10
    assert load(mcp.crypto_constants("apimcp")) == []

    immediates = load(mcp.search_immediates("apimcp", "0xa"))
    assert "mov ecx, 0xa" in [row["text"] for row in immediates["code"]]


def test_fingerprint_and_diff_tools(tmp_path):
    from phantomscope.backends.demo import build_flow_demo_pe

    left = tmp_path / "build_a.dll"
    right = tmp_path / "build_b.dll"
    left.write_bytes(build_flow_demo_pe())
    right.write_bytes(build_flow_demo_pe())
    load(mcp.load_file(str(left), key="build_a"))
    load(mcp.load_file(str(right), key="build_b"))

    row = load(mcp.fingerprint("build_a", hex(MODULE_BASE + 0x1000)))
    assert row["function"] == hex(MODULE_BASE + 0x1000)

    matched = load(mcp.match_functions("build_a", "build_b"))
    assert matched["count"] >= 3
    assert all(m["kind"] == "identical" for m in matched["matches"])

    diff = load(mcp.diff_images("build_a", "build_b"))
    assert diff["counts"]["identical"] >= 3
    assert diff["counts"]["removed"] == 0


def test_emulator_stub_tools(tmp_path):
    from phantomscope.backends.demo import build_api_demo_pe

    target = tmp_path / "emustub.dll"
    target.write_bytes(build_api_demo_pe())
    load(mcp.load_file(str(target), key="emustub"))
    created = load(mcp.emu_create(key="emustub", stubs=True))
    assert created["stubs"] == 2

    result = load(mcp.emu_call(key="emustub", va=hex(MODULE_BASE + 0x1000), max_steps=5000))
    assert result["reason"] == "returned"
    calls = load(mcp.emu_calls(key="emustub"))
    assert [call["api"] for call in calls] == ["KERNEL32.dll!Sleep", "KERNEL32.dll!GetTickCount"]
    assert load(mcp.emu_stub_list(key="emustub"))[0]["returns"] == "0x0"


def test_live_structure_tools():
    mcp.session_open(device="mock", backend="mock")
    mcp.attach(str(DEMO_PID))

    chain = load(mcp.resolve_pointer_chain(base=hex(HEAP_BASE + 0x1E0), offsets="0,8",
                                           value_type="uint32"))
    assert chain["value"] == 0xDEADBEEF
    assert chain["depth"] == 2

    obj = load(mcp.read_object(va=hex(HEAP_BASE + 0x120), size=0x20,
                              fields="0x0:int32,0x10:char[8]"))
    assert [field["value"] for field in obj["fields"]] == [100, "PLAYER01"]

    rows = load(mcp.read_array(base=hex(HEAP_BASE + 0x1C0), stride=8, count=4, follow=True,
                               object_size=0x20, fields="0x0:int32"))
    assert [row["fields"][0]["value"] for row in rows["objects"]] == [1, 2, 3, 4]

    inferred = load(mcp.infer_struct(va=hex(HEAP_BASE + 0x100), size=0x20, align=8))
    assert inferred["c_struct"].startswith("// inferred from live memory")
    # The qword at +0x100 is the vtable-ish pointer the demo wrote.
    assert any(field["type"] == "pointer" for field in inferred["fields"])




def test_live_container_tools():
    mcp.session_open(device="mock", backend="mock")
    mcp.attach(str(DEMO_PID))

    detected = load(mcp.detect_container(va=hex(HEAP_BASE + 0x180)))
    assert detected["primary"]["kind"] == "std::vector<T>"
    assert detected["primary"]["element_size"] == 0x20

    expanded = load(mcp.expand_container(va=hex(HEAP_BASE + 0x180),
                                        fields="0x0:int32,0x8:char[8]"))
    assert expanded["element_count"] == 4
    assert expanded["elements"][0]["fields"][1]["value"] == "alpha"


def test_trace_and_module_snapshot_tools():
    mcp.session_open(device="mock", backend="mock")
    mcp.attach(str(DEMO_PID))

    traced = load(mcp.trace_changes(va=hex(HEAP_BASE + 0x100), size=0x40, samples=2,
                                    interval=0.0))
    assert traced["samples"] == 2
    assert traced["changed_bytes"] == 0

    series = load(mcp.trace_value(va=hex(HEAP_BASE + 0x120), value_type="int32", samples=2,
                                  interval=0.0))
    assert series["constant"] is True

    baseline = load(mcp.snapshot_module(module="demo_target.exe", label="t"))
    assert baseline["regions"]
    mcp.write(va=hex(MODULE_BASE + 0x1010), data="90909090")
    diff = load(mcp.diff_module(module="demo_target.exe"))
    assert diff["changed_bytes"] == 4
    assert diff["snapshot_id"] == baseline["id"]


def test_emulator_coverage_tools(tmp_path):
    from phantomscope.backends.demo import build_flow_demo_pe

    target = tmp_path / "flow.exe"
    target.write_bytes(build_flow_demo_pe())
    load(mcp.load_file(str(target), key="flowcov"))
    created = load(mcp.emu_create(key="flowcov", stubs=True, trace=True))
    assert created["tracing"] is True

    result = load(mcp.emu_call(key="flowcov", va=hex(MODULE_BASE + 0x1000), args="3",
                               max_steps=5000))
    assert result["reason"] == "returned"

    coverage = load(mcp.emu_coverage(key="flowcov"))
    assert coverage["unique_instructions"] > 4
    assert coverage["forks"]

    reached = load(mcp.emu_reached(key="flowcov",
                                  addresses=f"{MODULE_BASE + 0x1000:#x},{MODULE_BASE + 0x1800:#x}"))
    assert reached["count_reached"] == 1
    assert load(mcp.emu_faults(key="flowcov")) == []

    stopped = load(mcp.emu_trace(key="flowcov", action="stop"))
    assert stopped["tracing"] is False
    assert load(mcp.emu_trace(key="flowcov", action="reset"))["reset"] is True


def test_live_struct_layout_tool(tmp_path):
    from phantomscope.backends.demo import ARENA_BASE, build_struct_demo_pe

    target = tmp_path / "structmerge.exe"
    target.write_bytes(build_struct_demo_pe())
    load(mcp.load_file(str(target), key="merge"))

    mcp.session_open(device="mock", backend="mock")
    mcp.attach(str(DEMO_PID))

    result = load(mcp.live_struct_layout(
        key="merge", function=hex(MODULE_BASE + 0x1030), object_va=hex(ARENA_BASE),
        size=0x20, stride=0x20, count=4, align=4))
    layouts = result["layouts"]
    assert layouts
    assert layouts[0]["role"] == "arg0"

    # Offsets the code touches are all present, and the string at +0x8 became a
    # char array rather than an integer.
    field_offsets = [field["offset"] for field in layouts[0]["fields"]]
    for expected in ("0x8", "0xc", "0x10", "0x14", "0x18"):
        assert expected in field_offsets
    text = next(f for f in layouts[0]["fields"] if f["offset"] == "0x8")
    assert text["c_type"] == "char"
    assert text["name"] == "text_8"

    # The raw inference is included so the caller can compare the two views.
    assert result["inferred_c_struct"].startswith("// inferred from live memory")
    assert "struct arg0_t" in layouts[0]["c_struct"]
