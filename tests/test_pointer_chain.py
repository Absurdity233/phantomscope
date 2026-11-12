"""Pointer-chain resolution: path form, scanned chains, and honest failures."""

from __future__ import annotations

import pytest

from phantomscope.backends.demo import (
    ARENA_BASE,
    CHAIN_SLOT_OFFSET,
    CHAIN_VALUE,
    DEMO_PID,
    HEAP_BASE,
    MODULE_BASE,
    PLAYER_HEALTH_OFFSET,
)
from phantomscope.dynamic import pointer
from phantomscope.errors import BackendError, InvalidArgument


def test_resolve_reads_the_final_field(dynamic, demo_values):
    result = dynamic.resolve_pointer_chain(
        DEMO_PID, HEAP_BASE + CHAIN_SLOT_OFFSET, [0, 8], value_type="uint32"
    )
    assert result["depth"] == 2
    assert result["value"] == CHAIN_VALUE
    assert result["type"] == "uint32"
    # Both hops are reported with the region they landed in.
    assert [level["level"] for level in result["levels"]] == [0, 1]
    assert result["levels"][0]["pointer"] == hex(HEAP_BASE + 0x1F0)
    assert result["levels"][1]["region_base"] == hex(HEAP_BASE)
    assert result["writable"] is True


def test_resolve_accepts_module_expression(dynamic):
    # Not a real chain, but the base parser has to turn the expression into a VA.
    result = dynamic.resolve_pointer_chain(
        DEMO_PID, "demo_target.exe+0x1000", [], read_size=4
    )
    assert result["base_va"] == hex(MODULE_BASE + 0x1000)
    assert result["base"] == "demo_target.exe+0x1000"
    assert result["depth"] == 0
    assert result["kind"] == "bytes"
    assert result["size"] == 4


def test_resolve_accepts_numeric_expression_with_offset(dynamic):
    result = dynamic.resolve_pointer_chain(
        DEMO_PID, f"{HEAP_BASE:#x}+{CHAIN_SLOT_OFFSET:#x}", [0, 8], value_type="uint32"
    )
    assert result["value"] == CHAIN_VALUE


def test_resolve_null_pointer_names_the_level(dynamic):
    # Wipe the middle hop: the error must say which level broke, not "garbage".
    dynamic.write(DEMO_PID, HEAP_BASE + CHAIN_SLOT_OFFSET, data="00" * 8)
    with pytest.raises(BackendError) as excinfo:
        dynamic.resolve_pointer_chain(DEMO_PID, HEAP_BASE + CHAIN_SLOT_OFFSET, [0, 8])
    assert "level 0" in str(excinfo.value)


def test_resolve_without_a_reader_stops_at_the_address(dynamic):
    # No value_type and no read_size: report the address, do not invent a value.
    result = dynamic.resolve_pointer_chain(DEMO_PID, HEAP_BASE, [0x120])
    assert result["kind"] == "address"
    assert "value" not in result
    assert result["address"] == hex(HEAP_BASE + 0x120)
    assert result["template"]["offsets"] == [0x120]


def test_template_round_trip(dynamic):
    chain = dynamic.resolve_pointer_chain(
        DEMO_PID, HEAP_BASE + CHAIN_SLOT_OFFSET, [0, 8], value_type="uint32"
    )
    template = chain["template"]
    assert template["base"] == hex(HEAP_BASE + CHAIN_SLOT_OFFSET)
    assert template["offsets"] == [0, 8]
    assert template["value_type"] == "uint32"

    # Re-running the template must land on the same field: that is the point.
    again = dynamic.resolve_pointer_chain(
        DEMO_PID, template["base"], template["offsets"], value_type=template["value_type"]
    )
    assert again["value"] == chain["value"]


def test_scan_then_replay_a_module_anchored_chain(dynamic):
    # Plant a pointer in the module image so the chain survives a restart.
    dynamic.write(
        DEMO_PID,
        MODULE_BASE + 0x1100,
        data=(HEAP_BASE + PLAYER_HEALTH_OFFSET).to_bytes(8, "little").hex(),
    )
    chains = dynamic.pointer_scan(DEMO_PID, HEAP_BASE + PLAYER_HEALTH_OFFSET, max_depth=1)
    anchored = [chain for chain in chains if chain["module_anchored"]]
    assert anchored, chains
    assert anchored[0]["static_base"] == "demo_target.exe"
    assert anchored[0]["offsets"] == ["0x1100"]

    replayed = dynamic.replay_pointer_chains(DEMO_PID, anchored, value_type="int32")
    assert replayed[0]["matched"] is True
    assert replayed[0]["value"] == 100
    assert replayed[0]["levels"][0]["module"] == "demo_target.exe"


def test_multi_level_chains_are_found_and_ordered_outermost_first(dynamic):
    # module+0x1300 -> heap health field, and module+0x1200 -> module+0x1300.
    # A two-level chain therefore exists, and it has to be reported starting at
    # the outermost slot: getting this order wrong silently drops every chain
    # longer than one hop, which is most of them.
    dynamic.write(DEMO_PID, MODULE_BASE + 0x1300,
                  data=(HEAP_BASE + PLAYER_HEALTH_OFFSET).to_bytes(8, "little").hex())
    dynamic.write(DEMO_PID, MODULE_BASE + 0x1200,
                  data=(MODULE_BASE + 0x1300).to_bytes(8, "little").hex())

    chains = dynamic.pointer_scan(DEMO_PID, HEAP_BASE + PLAYER_HEALTH_OFFSET, max_depth=2)
    two_level = [chain for chain in chains if chain["depth"] == 2]
    assert two_level, chains
    assert two_level[0]["static_base"] == "demo_target.exe"
    assert two_level[0]["offsets"] == ["0x1200", "0x1300"]
    assert two_level[0]["module_anchored"] is True

    replayed = dynamic.replay_pointer_chains(DEMO_PID, [two_level[0]], value_type="int32")
    assert replayed[0]["matched"] is True
    assert replayed[0]["value"] == 100
    # The hops are in resolution order: module slot first, then what it pointed to.
    assert [level["at"] for level in replayed[0]["levels"]][:2] == [
        hex(MODULE_BASE + 0x1200), hex(MODULE_BASE + 0x1300)
    ]


def test_replay_refuses_chains_that_are_not_module_anchored(dynamic):
    dynamic.write(
        DEMO_PID,
        MODULE_BASE + 0x1100,
        data=(HEAP_BASE + PLAYER_HEALTH_OFFSET).to_bytes(8, "little").hex(),
    )
    chains = dynamic.pointer_scan(DEMO_PID, HEAP_BASE + PLAYER_HEALTH_OFFSET, max_depth=1)
    stack_chains = [chain for chain in chains if not chain["module_anchored"]]
    assert stack_chains

    replayed = dynamic.replay_pointer_chains(DEMO_PID, stack_chains)
    assert replayed[0]["matched"] is None
    assert "not anchored in a module" in replayed[0]["error"]


def test_replay_reports_a_chain_that_no_longer_resolves(dynamic):
    dynamic.write(
        DEMO_PID,
        MODULE_BASE + 0x1100,
        data=(HEAP_BASE + PLAYER_HEALTH_OFFSET).to_bytes(8, "little").hex(),
    )
    chains = dynamic.pointer_scan(DEMO_PID, HEAP_BASE + PLAYER_HEALTH_OFFSET, max_depth=1)
    anchored = [chain for chain in chains if chain["module_anchored"]]
    # The target moved (a reallocation): the old chain now lands somewhere else.
    dynamic.write(DEMO_PID, MODULE_BASE + 0x1100, data=(ARENA_BASE).to_bytes(8, "little").hex())
    replayed = dynamic.replay_pointer_chains(DEMO_PID, anchored)
    assert replayed[0]["matched"] is False
    assert replayed[0]["resolved"] == hex(ARENA_BASE)


def test_parse_base_rejects_a_missing_module(dynamic):
    with pytest.raises(Exception):
        pointer.parse_base(dynamic, DEMO_PID, "nosuch.exe+0x10")
