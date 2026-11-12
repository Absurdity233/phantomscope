"""Emulator coverage, branch forks and fault capture.

Recording is opt-in because a hook per instruction is expensive; the fault hook is
always installed because it only fires when something is already wrong.

Every emulator is closed by the fixture: unicorn keeps a native engine per
instance, and leaving a dozen of them to the cyclic collector makes the next
``mem_map`` collect them at the worst possible moment.
"""

from __future__ import annotations

import gc

import pytest

from phantomscope.analysis.engine import StaticEngine
from phantomscope.backends.demo import (
    MODULE_BASE,
    build_api_demo_pe,
    build_flow_demo_pe,
    build_struct_demo_pe,
    map_pe_file,
)
from phantomscope.dynamic.emulator import emulator_for


@pytest.fixture(scope="module")
def images():
    engine = StaticEngine()
    engine.load_capture("flow", map_pe_file(build_flow_demo_pe()), MODULE_BASE)
    engine.load_capture("api", map_pe_file(build_api_demo_pe()), MODULE_BASE)
    engine.load_capture("struct", map_pe_file(build_struct_demo_pe()), MODULE_BASE)
    return engine


@pytest.fixture()
def make_emu():
    created = []

    def factory(image, **kwargs):
        emu = emulator_for(image, **kwargs)
        created.append(emu)
        return emu

    yield factory
    for emu in created:
        emu.close()
    created.clear()
    gc.collect()


def test_coverage_records_instructions_and_edges(images, make_emu):
    emu = make_emu(images.get("api"), auto_stubs=True, trace=True)
    result = emu.call(MODULE_BASE + 0x1000, [])
    assert result["reason"] == "returned"

    coverage = emu.coverage()
    assert coverage["tracing"] is True
    assert coverage["steps"] > 5
    assert coverage["unique_instructions"] == len(coverage["executed"])
    assert coverage["edges"] > 0
    assert coverage["hot"][0]["hits"] >= 1


def test_coverage_names_the_taken_branch(images, make_emu):
    # sum(3) loops, so the backward branch has two successors with different counts.
    emu = make_emu(images.get("flow"), auto_stubs=True, trace=True)
    emu.call(MODULE_BASE + 0x1000, [3])

    forks = emu.coverage()["forks"]
    assert forks, emu.coverage()
    fork = forks[0]
    assert fork["successors"]
    assert sum(item["hits"] for item in fork["successors"]) == fork["hits"]


def test_coverage_differs_between_inputs(images, make_emu):
    taken = make_emu(images.get("flow"), auto_stubs=True, trace=True)
    taken.call(MODULE_BASE + 0x1000, [3])
    skipped = make_emu(images.get("flow"), auto_stubs=True, trace=True)
    skipped.call(MODULE_BASE + 0x1000, [0])

    # The loop body only runs for a positive count: fewer instructions, no fork.
    assert taken.coverage()["unique_instructions"] > skipped.coverage()["unique_instructions"]
    assert skipped.coverage()["forks"] == []


def test_coverage_is_off_by_default(images, make_emu):
    emu = make_emu(images.get("flow"), auto_stubs=True)
    emu.call(MODULE_BASE + 0x1000, [3])
    coverage = emu.coverage()
    assert coverage["tracing"] is False
    assert coverage["executed"] == []
    assert coverage["steps"] == 0


def test_trace_can_be_started_and_reset_after_the_fact(images, make_emu):
    emu = make_emu(images.get("flow"), auto_stubs=True)
    emu.call(MODULE_BASE + 0x1000, [2])
    assert emu.coverage()["steps"] == 0

    emu.reset_trace()
    assert emu.start_trace()["tracing"] is True
    emu.call(MODULE_BASE + 0x1000, [2])
    assert emu.coverage()["steps"] > 0

    stopped = emu.stop_trace()
    assert stopped["tracing"] is False
    seen = emu.coverage()["steps"]
    emu.stop_trace()  # stopping twice is harmless
    assert emu.coverage()["steps"] == seen


def test_reached_answers_specific_addresses(images, make_emu):
    emu = make_emu(images.get("flow"), auto_stubs=True, trace=True)
    emu.call(MODULE_BASE + 0x1000, [3])
    answer = emu.reached([MODULE_BASE + 0x1000, MODULE_BASE + 0x1006, MODULE_BASE + 0x1800])
    assert hex(MODULE_BASE + 0x1000) in answer["reached"]
    assert hex(MODULE_BASE + 0x1800) in answer["not_reached"]
    assert answer["count_reached"] == len(answer["reached"])


def test_fault_reports_the_pointer_that_was_bad(images, make_emu):
    # A real function that dereferences its argument: give it an unmapped pointer.
    emu = make_emu(images.get("struct"), auto_stubs=True)
    result = emu.call(MODULE_BASE + 0x1000, [0xDEAD0000])

    assert result["reason"].startswith("fault:")
    fault = result["fault"]
    assert fault["kind"] == "unmapped"
    assert fault["address"].startswith("0xdead")
    assert fault["rip"].startswith("0x7ff6")
    assert emu.faults()[0] == fault


def test_faults_are_listed_with_their_access_kind(images, make_emu):
    emu = make_emu(images.get("struct"), auto_stubs=True)
    emu.call(MODULE_BASE + 0x1000, [0xDEAD0000])
    faults = emu.faults(limit=5)
    assert len(faults) == 1
    assert faults[0]["address"] == "0xdead0010"   # the field offset is added by the code
    assert faults[0]["size"] == 4
    assert faults[0]["access"] == "read_unmapped"


def test_no_fault_is_reported_for_a_clean_run(images, make_emu):
    emu = make_emu(images.get("flow"), auto_stubs=True)
    result = emu.call(MODULE_BASE + 0x1000, [4])
    assert result["reason"] == "returned"
    assert emu.faults() == []
    assert "fault" not in result


def test_close_is_idempotent_and_reports_state(images, make_emu):
    emu = make_emu(images.get("flow"), auto_stubs=True, trace=True)
    emu.call(MODULE_BASE + 0x1000, [1])
    assert emu.closed is False
    assert emu.close()["closed"] is True
    assert emu.closed is True
    assert emu.close()["closed"] is True


def test_emulator_works_as_a_context_manager(images):
    with emulator_for(images.get("flow"), auto_stubs=True) as emu:
        assert emu.call(MODULE_BASE + 0x1000, [2])["reason"] == "returned"
    assert emu.closed is True


def test_registers_can_be_read_and_written(images, make_emu):
    emu = make_emu(images.get("flow"), auto_stubs=True)
    # The default rip is the image entry point, whatever that is.
    assert MODULE_BASE <= emu.read_regs(["rip"])["rip"] < MODULE_BASE + 0x4000
    emu.write_regs({"rcx": 0x1234})
    assert emu.read_regs(["rcx"])["rcx"] == 0x1234
    emu.call(MODULE_BASE + 0x1000, [3])
    # sum(3) returns in rax; the argument register is caller-saved.
    assert emu.read_regs(["rax"])["rax"] == 6


def test_watchpoint_records_the_writing_instruction(images, make_emu):
    # A snapshot can stop, which buys the one thing DMA cannot do: naming the
    # instruction that wrote a value.  ``emu.write`` goes around the engine, so the
    # store has to happen in emulated code for the hook to see it.
    emu = make_emu(images.get("flow"), auto_stubs=True)
    scratch = 0x5000_0000
    code_at = 0x6000_0000
    emu.map(scratch, 0x1000)
    emu.map(code_at, 0x1000)

    store = b"\x48\xc7\x00" + (0xAA).to_bytes(4, "little")   # mov qword ptr [rax], 0xAA
    code = b"\x48\xb8" + scratch.to_bytes(8, "little") + store
    emu.write(code_at, code)

    emu.watchpoint(scratch, kind="write", size=8)
    emu.write_regs({"rip": code_at})
    emu.run_until(code_at + len(code), max_steps=16)

    events = emu.watchpoints()
    assert events
    assert events[0]["va"] == hex(scratch)
    assert events[0]["access"] == "write"
    assert events[0]["value"] == hex(0xAA)
    # The hook names the *store* instruction, not the function or the page.
    assert events[0]["rip"] == hex(code_at + len(b"\x48\xb8" + scratch.to_bytes(8, "little")))
