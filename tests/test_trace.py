"""Change tracing: the substitute for memory breakpoints when nothing can be stopped."""

from __future__ import annotations

import threading
import time

import pytest

from phantomscope.backends.demo import (
    ARENA_BASE,
    ARENA_STRIDE,
    DEMO_PID,
    HEAP_BASE,
    PLAYER_AMMO_OFFSET,
    PLAYER_HEALTH_OFFSET,
)
from phantomscope.errors import InvalidArgument


def _write_later(dynamic, address, value, *, delay=0.03, value_type="int32"):
    """Write from another thread so a sampling call sees a mid-flight change."""
    def run():
        time.sleep(delay)
        dynamic.write(DEMO_PID, address, value=value, value_type=value_type)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def test_trace_changes_catches_a_write_and_names_the_field(dynamic):
    _write_later(dynamic, HEAP_BASE + PLAYER_HEALTH_OFFSET, 42)
    traced = dynamic.trace_changes(DEMO_PID, HEAP_BASE + 0x100, 0x40, samples=6, interval=0.02)

    assert traced["changed_bytes"] == 1
    assert traced["samples"] == 6
    run = traced["runs"][0]
    assert run["va"] == hex(HEAP_BASE + PLAYER_HEALTH_OFFSET)
    assert run["size"] == 1
    assert run["first"] == "64"        # 100
    assert run["last"] == "2a"         # 42
    # A one-byte change still gets a four-byte reading: that is the dword you want.
    int32 = next(i for i in run["interpretations"] if i["type"] == "int32")
    assert (int32["first"], int32["last"]) == (100, 42)
    assert int32["va"] == hex(HEAP_BASE + PLAYER_HEALTH_OFFSET)


def test_trace_changes_reports_nothing_when_nothing_moves(dynamic):
    traced = dynamic.trace_changes(DEMO_PID, HEAP_BASE + 0x200, 0x10, samples=3, interval=0.01)
    assert traced["changed_bytes"] == 0
    assert traced["runs"] == []
    assert traced["written_continuously"] == 0


def test_trace_changes_marks_a_counter_that_only_increases(dynamic):
    def bump():
        time.sleep(0.02)
        for value in (101, 102, 103):
            dynamic.write(DEMO_PID, HEAP_BASE + PLAYER_HEALTH_OFFSET, value=value,
                          value_type="int32")
            time.sleep(0.02)

    threading.Thread(target=bump, daemon=True).start()
    traced = dynamic.trace_changes(DEMO_PID, HEAP_BASE + 0x100, 0x40, samples=8, interval=0.02)
    run = traced["runs"][0]
    assert run["changes"] >= 2
    assert run["monotonic"].startswith("int32: increased")
    assert run["flips"] > 0


def test_trace_changes_merges_adjacent_fields_into_one_run(dynamic):
    # A dword write at +0x120 touches only the low byte of a small value, so use a
    # value with all four bytes set to force one contiguous run.
    _write_later(dynamic, HEAP_BASE + PLAYER_HEALTH_OFFSET, 0x7F7F7F7F)
    traced = dynamic.trace_changes(DEMO_PID, HEAP_BASE + 0x100, 0x40, samples=6, interval=0.02)
    run = traced["runs"][0]
    assert run["size"] == 4
    assert run["va"] == hex(HEAP_BASE + PLAYER_HEALTH_OFFSET)


def test_trace_changes_reports_separate_runs(dynamic):
    def twin_writes():
        time.sleep(0.02)
        dynamic.write(DEMO_PID, HEAP_BASE + PLAYER_HEALTH_OFFSET, value=0x01020304,
                      value_type="int32")
        dynamic.write(DEMO_PID, HEAP_BASE + PLAYER_AMMO_OFFSET, value=0x05060708,
                      value_type="int32")

    threading.Thread(target=twin_writes, daemon=True).start()
    traced = dynamic.trace_changes(DEMO_PID, HEAP_BASE + 0x100, 0x40, samples=8, interval=0.02)
    assert traced["changed_bytes"] == 8
    assert len(traced["runs"]) == 1  # health and ammo are adjacent dwords -> one run


def test_trace_changes_respects_its_range(dynamic):
    _write_later(dynamic, HEAP_BASE + PLAYER_HEALTH_OFFSET, 42)
    # The written field is outside the traced window, so nothing may be reported.
    traced = dynamic.trace_changes(DEMO_PID, HEAP_BASE + 0x200, 0x20, samples=5, interval=0.02)
    assert traced["runs"] == []


def test_trace_changes_rejects_a_bad_range(dynamic):
    with pytest.raises(InvalidArgument):
        dynamic.trace_changes(DEMO_PID, HEAP_BASE, 0, samples=2)
    with pytest.raises(InvalidArgument):
        dynamic.trace_changes(DEMO_PID, HEAP_BASE, 0x10, samples=1)


def test_trace_value_returns_a_series(dynamic):
    _write_later(dynamic, HEAP_BASE + PLAYER_HEALTH_OFFSET, 55, delay=0.03)
    traced = dynamic.trace_value(DEMO_PID, HEAP_BASE + PLAYER_HEALTH_OFFSET, "int32",
                                 samples=6, interval=0.02)
    values = [row["value"] for row in traced["series"]]
    assert values[0] == 100
    assert values[-1] == 55
    assert traced["changed"] is True
    assert traced["constant"] is False
    assert (traced["min"], traced["max"]) == (55, 100)
    # Samples taken before the write deltas are zero; the drop shows up once.
    assert -45 in traced["deltas"]


def test_trace_value_reports_a_constant(dynamic):
    traced = dynamic.trace_value(DEMO_PID, ARENA_BASE + 0x18, "uint64", samples=3, interval=0.01)
    assert traced["constant"] is True
    assert traced["changed"] is False
    assert len(set(row["value"] for row in traced["series"])) == 1


def test_sample_matrix_gives_a_grid(dynamic):
    matrix = dynamic.sample_matrix(DEMO_PID, ARENA_BASE, width=8, rows=ARENA_STRIDE // 8,
                                   stride=8, interval=0.01)
    assert matrix["rows"]
    offsets = [row["offset"] for row in matrix["rows"]]
    assert offsets == [hex(index * 8) for index in range(ARENA_STRIDE // 8)]
    # The vtable pointer at +0x18 reads back as a mapped pointer.
    vtable = next(row for row in matrix["rows"] if row["offset"] == "0x18")
    assert vtable["pointer"] is True
    assert vtable["hex"].startswith("0x7ff6")
    # The id/health qword is not an address.
    first = next(row for row in matrix["rows"] if row["offset"] == "0x0")
    assert first["pointer"] is False
    assert matrix["changed_rows"] == 0
