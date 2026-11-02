"""Dynamic engine against the mock backend: memory, patches, scans, threads."""

from __future__ import annotations

import pytest

from phantomscope.backends.demo import DEMO_PID, HEAP_BASE, MODULE_BASE, PLAYER_NAME_OFFSET
from phantomscope.errors import InvalidArgument, NotFound


def test_process_enumeration(dynamic):
    processes = dynamic.list_processes(name="demo")
    assert len(processes) == 1
    assert processes[0]["pid"] == DEMO_PID


def test_process_info_counts(dynamic):
    info = dynamic.process_info(DEMO_PID)
    assert info["modules"] == 1
    assert info["threads"] == 2
    assert info["mapped_bytes"] > 0


def test_modules_and_address_info(dynamic):
    modules = dynamic.list_modules(DEMO_PID)
    assert modules[0]["name"] == "demo_target.exe"
    info = dynamic.address_info(DEMO_PID, MODULE_BASE + 0x1000)
    assert info["module"] == "demo_target.exe"
    assert info["executable"] is True


def test_read_typed_and_write(dynamic):
    read = dynamic.read_typed(DEMO_PID, HEAP_BASE + 0x120, "int32")
    assert read["value"] == 100
    patch = dynamic.write(DEMO_PID, HEAP_BASE + 0x120, value=250, value_type="int32", note="test")
    assert patch["original"] == "64000000"
    assert dynamic.read_typed(DEMO_PID, HEAP_BASE + 0x120, "int32")["value"] == 250
    dynamic.restore_patch(patch["id"])
    assert dynamic.read_typed(DEMO_PID, HEAP_BASE + 0x120, "int32")["value"] == 100


def test_write_requires_payload(dynamic):
    with pytest.raises(InvalidArgument):
        dynamic.write(DEMO_PID, HEAP_BASE)


def test_restore_missing_patch(dynamic):
    with pytest.raises(NotFound):
        dynamic.restore_patch(999)


def test_patch_journal_tracks_restore(dynamic):
    one = dynamic.write(DEMO_PID, HEAP_BASE + 0x124, data="ff000000")
    two = dynamic.write(DEMO_PID, HEAP_BASE + 0x128, data="00000000")
    assert len(dynamic.patches(pid=DEMO_PID)) == 2
    summary = dynamic.restore_all(pid=DEMO_PID)
    assert summary["count"] == 2
    assert all(item["restored"] for item in dynamic.patches())
    assert one["id"] != two["id"]


def test_reparse_module_expression(dynamic):
    va = dynamic.reparse(DEMO_PID, "demo_target.exe+0x1000")
    assert va == MODULE_BASE + 0x1000


def test_aob_scan(dynamic):
    hits = dynamic.scan_aob(DEMO_PID, "48 83 ec 28")
    assert hits
    assert hits[0]["va"] == MODULE_BASE + 0x1000


def test_value_scan_and_narrowing(dynamic):
    scan = dynamic.scan_value(DEMO_PID, 100, "int32", label="health")
    assert scan["count"] >= 1
    assert hex(HEAP_BASE + 0x120) in scan["addresses"]
    dynamic.write(DEMO_PID, HEAP_BASE + 0x120, value=42, value_type="int32")
    narrowed = dynamic.scan_next("health", 100)
    assert hex(HEAP_BASE + 0x120) not in narrowed["addresses"]


def test_scan_changed_detects_writes(dynamic):
    scan = dynamic.scan_value(DEMO_PID, 30, "int32", label="ammo")
    first = dynamic.scan_changed("ammo")
    assert first["changed"] == 0
    dynamic.write(DEMO_PID, HEAP_BASE + 0x124, value=7, value_type="int32")
    second = dynamic.scan_changed("ammo")
    assert second["count"] >= 1


def test_threads_and_callstack(dynamic):
    threads = dynamic.threads(DEMO_PID)
    assert {t["tid"] for t in threads} == {0x1A2B, 0x1A2C}
    frames = dynamic.callstack(DEMO_PID, 0x1A2B)
    assert frames[0]["symbol"].endswith("update_health")
    assert frames[0]["role"] == "rip"


def test_snapshot_and_diff(dynamic, backend):
    snap = dynamic.snapshot(DEMO_PID, HEAP_BASE, 0x200)
    assert snap["size"] == 0x200
    backend.write(DEMO_PID, HEAP_BASE + 0x120, b"\x01\x00\x00\x00")
    changes = dynamic.diff(DEMO_PID, base=HEAP_BASE, size=0x200, snapshot_id=snap["id"])
    assert changes
    assert changes[0]["old"] == "64"


def test_watch_values_reports_change(dynamic, backend):
    def mutate():
        backend.write(DEMO_PID, HEAP_BASE + 0x120, b"\x63\x00\x00\x00")

    import threading

    timer = threading.Timer(0.15, mutate)
    timer.start()
    events = dynamic.watch_values(DEMO_PID, [HEAP_BASE + 0x120], "int32", timeout=1.0)
    timer.cancel()
    assert events
    assert events[0]["new"] == 99


def test_dump_region(dynamic):
    data = dynamic.dump_region(DEMO_PID, HEAP_BASE, 0x200)
    assert len(data) == 0x200
    assert data[0x120:0x124] == (100).to_bytes(4, "little")


def test_pointer_scan_finds_vtable_pointer(dynamic):
    chains = dynamic.pointer_scan(DEMO_PID, MODULE_BASE + 0x1000)
    assert chains
    assert any(item["region"] == "heap" for item in chains[0]["chain"])


def test_unknown_process_raises(dynamic):
    with pytest.raises(NotFound):
        dynamic.list_modules(0xDEAD)


def test_region_listing(backend):
    regions = backend.list_regions(DEMO_PID)
    assert any(region.tag == "heap" for region in regions)
    assert any(region.tag == "stack" for region in regions)
