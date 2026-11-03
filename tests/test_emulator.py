"""Snapshot emulation: stepping, registers, memory and watchpoints."""

from __future__ import annotations

import pytest

from phantomscope.backends.demo import MODULE_BASE
from phantomscope.dynamic.emulator import Emulator, emulator_available, emulator_for

pytestmark = pytest.mark.skipif(not emulator_available(), reason="unicorn is not installed")

ENTRY = MODULE_BASE + 0x1000
UPDATE_HEALTH = MODULE_BASE + 0x1015
HEALTH_GLOBAL = MODULE_BASE + 0x1080


def test_registers_roundtrip(demo_image):
    emu = emulator_for(demo_image)
    emu.write_regs({"rcx": 0x1234, "r8": 0x99})
    assert emu.read_regs(["rcx", "r8"]) == {"rcx": 0x1234, "r8": 0x99}


def test_single_step_advances(demo_image):
    emu = emulator_for(demo_image)
    before = emu.read_regs(["rip"])["rip"]
    emu.step()
    after = emu.read_regs(["rip"])["rip"]
    assert before == ENTRY
    assert after > before


def test_run_until_breakpoint(demo_image):
    emu = emulator_for(demo_image)
    result = emu.run_until(UPDATE_HEALTH, max_steps=64)
    assert result["reason"] == "reached_target"
    assert int(result["to"], 16) == UPDATE_HEALTH


def test_run_until_updates_global(demo_image):
    emu = emulator_for(demo_image)
    emu.run_until(UPDATE_HEALTH, max_steps=64)
    emu.run_until(MODULE_BASE + 0x1009, max_steps=64)
    assert emu.read_u32(HEALTH_GLOBAL) == 105


def test_call_returns_and_sets_state(demo_image):
    emu = emulator_for(demo_image)
    before = emu.read_u32(HEALTH_GLOBAL)
    result = emu.call(UPDATE_HEALTH, max_steps=128)
    assert result["reason"] == "returned"
    assert emu.read_u32(HEALTH_GLOBAL) == before + 5


def test_call_is_repeatable(demo_image):
    emu = emulator_for(demo_image)
    before = emu.read_u32(HEALTH_GLOBAL)
    for _ in range(3):
        assert emu.call(UPDATE_HEALTH, max_steps=128)["reason"] == "returned"
    assert emu.read_u32(HEALTH_GLOBAL) == before + 15


def test_call_then_step_then_run_until(demo_image):
    """A previous call must not break later control-flow primitives."""
    emu = emulator_for(demo_image)
    assert emu.call(UPDATE_HEALTH, max_steps=128)["reason"] == "returned"

    emu.write_regs({"rip": ENTRY, "rsp": 0x7FFF_0000_8000})
    assert int(emu.step(1)["to"], 16) == MODULE_BASE + 0x1004

    assert int(emu.run_until(UPDATE_HEALTH, max_steps=64)["to"], 16) == UPDATE_HEALTH
    assert int(emu.run_until(MODULE_BASE + 0x1009, max_steps=64)["to"], 16) == MODULE_BASE + 0x1009


def test_run_reports_budget_exhaustion(demo_image):
    emu = emulator_for(demo_image)
    emu.write_regs({"rip": UPDATE_HEALTH})
    assert emu.run(max_steps=2)["reason"] == "budget_exhausted"


def test_memory_read_write(demo_image):
    emu = emulator_for(demo_image)
    emu.write(HEALTH_GLOBAL, b"\x01\x00\x00\x00")
    assert emu.read_u32(HEALTH_GLOBAL) == 1
    assert emu.read(HEALTH_GLOBAL, 4) == b"\x01\x00\x00\x00"


def test_watchpoint_records_write(demo_image):
    emu = emulator_for(demo_image)
    emu.watchpoint(HEALTH_GLOBAL, kind="write", size=4, limit=10)
    emu.call(UPDATE_HEALTH, max_steps=128)
    events = emu.watchpoints()
    assert events
    assert any(event["access"] == "write" for event in events)


def test_hook_call_fires(demo_image):
    seen = []
    emu = emulator_for(demo_image)
    emu.hook_call(UPDATE_HEALTH, lambda machine: seen.append(machine.read_regs(["rip"])["rip"]))
    emu.run_until(MODULE_BASE + 0x1009, max_steps=128)
    assert seen == [UPDATE_HEALTH]


def test_cstring_reader(demo_image):
    emu = emulator_for(demo_image)
    emu.write(MODULE_BASE + 0x1200, b"hello\x00")
    assert emu.read_cstring(MODULE_BASE + 0x1200) == "hello"


def test_stack_dump_is_hex(demo_image):
    emu = emulator_for(demo_image)
    words = emu.dump_stack(32)
    assert len(words) == 4
    assert all(len(word) == 16 for word in words)
