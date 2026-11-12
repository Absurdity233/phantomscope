"""The synthetic shooter target: a live process whose values actually move.

The demo target is static.  That is enough to test reading, but not enough to test
the two things that only make sense against motion: narrowing a scan while the
value changes under you, and reasoning about a chain that has to survive a
restart.  This fixture is a real ``MockBackend`` with a game loop in a thread.
"""

from __future__ import annotations

import time

import pytest

from phantomscope.backends.gametarget import (
    CONTAINER_BASE,
    ENTITY_BASE,
    ENTITY_COUNT,
    GAME_MODULE,
    GAME_MODULE_BASE,
    GAME_PID,
    LOCAL_PLAYER,
    PLAYER,
    PLAYER_FIELDS,
    PLAYER_SIZE,
    STATIC_SLOT,
    build_game_backend,
    start_tick,
    stop_tick,
)
from phantomscope.dynamic.engine import DynamicEngine


@pytest.fixture()
def game():
    backend, state = build_game_backend()
    yield DynamicEngine(backend), state
    stop_tick(state, getattr(state, "thread", None))
    backend.close()


@pytest.fixture()
def live_game():
    backend, state = build_game_backend(with_tick=True)
    yield DynamicEngine(backend), state
    stop_tick(state, getattr(state, "thread", None))
    backend.close()


def test_the_process_looks_like_a_game_client(game):
    dynamic, _ = game
    processes = dynamic.list_processes()
    assert [row["name"] for row in processes] == [GAME_MODULE]
    assert processes[0]["pid"] == GAME_PID

    modules = dynamic.list_modules(GAME_PID)
    assert modules[0]["name"] == GAME_MODULE
    assert modules[0]["base"] == GAME_MODULE_BASE

    threads = dynamic.threads(GAME_PID)
    assert len(threads) == 1
    frames = dynamic.callstack(GAME_PID, threads[0]["tid"])
    assert frames[0]["symbol"].endswith("CGame::Tick")


def test_the_local_player_reads_back_as_a_struct(game):
    dynamic, _ = game
    obj = dynamic.read_object(GAME_PID, LOCAL_PLAYER, PLAYER_SIZE, fields=PLAYER_FIELDS)
    fields = {field["offset"]: field.get("value") for field in obj["fields"]}

    assert fields["0x0"] == 1                     # id
    assert fields["0x4"] == 100                   # health
    assert fields["0x8"] == 100                   # armor
    assert fields["0xc"] == 2                     # team
    assert fields["0x10"] == pytest.approx(0.0)   # position.x
    assert fields["0x28"] == pytest.approx(90.0)  # yaw
    assert fields["0x30"] == "you"                # name
    assert fields["0x48"] & 0x1                   # FLAG_ALIVE


def test_positions_are_float_triples(game):
    dynamic, _ = game
    second = ENTITY_BASE + PLAYER_SIZE
    x = dynamic.read_typed(GAME_PID, second + PLAYER["position"], "float")["value"]
    y = dynamic.read_typed(GAME_PID, second + PLAYER["position"] + 4, "float")["value"]
    assert x == pytest.approx(14.0)
    assert y == pytest.approx(17.5)


def test_the_entity_list_is_a_pointer_vector(game):
    dynamic, _ = game
    detected = dynamic.detect_container(GAME_PID, CONTAINER_BASE)
    assert detected["primary"]["kind"] == "std::vector<T>"
    # The span is ENTITY_COUNT * 8 bytes.  Every divisor fits the bytes, so the
    # tool cannot know it is a vector of pointers; what it *can* do is find the
    # pointer rhythm inside the elements, which only 8 satisfies here.
    assert detected["primary"]["element_size"] == 8
    assert detected["primary"]["element_size_source"] == "pointer_rhythm"
    assert detected["primary"]["count"] == ENTITY_COUNT

    expanded = dynamic.expand_container(GAME_PID, CONTAINER_BASE, element_size=8)
    assert expanded["element_count"] == ENTITY_COUNT
    # Without follow the elements are the pointer slots in VECTOR_DATA, which is
    # what a vector<Player*> contains; the targets are read by read_array(follow).
    assert [row["va"] for row in expanded["elements"]] == [
        hex(0x000003_A1_0000_0000 + index * 8) for index in range(ENTITY_COUNT)
    ]


def test_the_entity_list_reads_as_followed_pointers(game):
    dynamic, _ = game
    rows = dynamic.read_array(
        GAME_PID, 0x000003_A1_0000_0000, 8, ENTITY_COUNT, follow=True,
        object_size=PLAYER_SIZE, fields="0x0:int32,0x4:int32,0x30:char[16]",
    )
    assert [row["fields"][0]["value"] for row in rows["objects"]] == list(range(100, 108))
    assert rows["objects"][0]["fields"][2]["value"] == "hostile-01"


def test_the_static_slot_is_inside_the_module(game):
    dynamic, _ = game
    # A chain only survives a restart when it is anchored in a module, so the
    # anchor has to live there rather than in a heap region mapped on top of it.
    info = dynamic.module_for(GAME_PID, STATIC_SLOT)
    assert info is not None and info.name == GAME_MODULE
    assert info.base <= STATIC_SLOT < info.base + info.size


def test_pointer_chain_reaches_the_health_field(game):
    dynamic, _ = game
    # pointer_scan finds slots whose content *is* the target, so scan for the
    # player object; the field offset is then applied by resolve_pointer_chain.
    chains = dynamic.pointer_scan(GAME_PID, LOCAL_PLAYER, max_depth=2)
    anchored = [chain for chain in chains if chain["module_anchored"]]
    assert anchored, chains
    assert anchored[0]["static_base"] == GAME_MODULE
    assert anchored[0]["offsets"] == ["0x3008"]

    replayed = dynamic.replay_pointer_chains(GAME_PID, anchored, value_type="int32")
    assert replayed[0]["matched"] is True
    assert replayed[0]["levels"][0]["module"] == GAME_MODULE
    # +0x00 is the player id, which is the field at the resolved address itself.
    assert replayed[0]["value"] == 1


def test_resolve_path_reaches_the_health_field(game):
    dynamic, _ = game
    # One hop plus a field offset: the offset table a real target produces.
    result = dynamic.resolve_pointer_chain(
        GAME_PID, f"{GAME_MODULE}+0x3008", [0x0, PLAYER["health"]], value_type="int32"
    )
    assert result["value"] == 100
    assert result["depth"] == 2
    assert result["address"] == hex(LOCAL_PLAYER + PLAYER["health"])
    assert result["template"]["base"] == f"{GAME_MODULE}+0x3008"
    assert result["template"]["offsets"] == [0x0, PLAYER["health"]]


def test_a_wrong_field_offset_does_not_return_health(game):
    # The offset table has to be *right*, not merely resolvable: +0x08 is armor,
    # also 100 at spawn, so this is the case a sloppy fixture would let through.
    dynamic, _ = game
    wrong = dynamic.resolve_pointer_chain(
        GAME_PID, f"{GAME_MODULE}+0x3008", [0x0, 0x0C], value_type="int32"
    )
    assert wrong["value"] == 2          # team, not health
    assert wrong["address"] != hex(LOCAL_PLAYER + PLAYER["health"])


def test_the_tick_actually_damages_the_player(live_game):
    dynamic, state = live_game
    deadline = time.time() + 3.0
    while time.time() < deadline and state.damage_dealt == 0:
        time.sleep(0.02)

    assert state.damage_dealt > 0, "the background tick never ran"
    health = dynamic.read_typed(GAME_PID, LOCAL_PLAYER + PLAYER["health"], "int32")
    assert health["value"] < 100


def test_trace_value_sees_the_health_dropping(live_game):
    dynamic, _ = live_game
    traced = dynamic.trace_value(GAME_PID, LOCAL_PLAYER + PLAYER["health"], "int32",
                                 samples=8, interval=0.03)
    assert traced["changed"] is True
    # The tick only subtracts, so the series can never go up.
    assert traced["max"] <= 100
    assert all(delta <= 0 for delta in traced["deltas"])


def test_scan_narrowing_works_against_motion(live_game):
    dynamic, _ = live_game
    first = dynamic.scan_value(GAME_PID, 100, "int32", label="hp")
    assert first["count"] >= 1

    # With no baseline, a predicate scan captures the current values and says so;
    # the caller then lets the target change and narrows for real.
    baseline = dynamic.scan_next("hp", decreased=True)
    assert baseline.get("baseline") is True
    assert baseline["count"] == first["count"]

    time.sleep(0.15)
    narrowed = dynamic.scan_next("hp", decreased=True)
    assert narrowed["count"] <= baseline["count"]
    # Health only falls, and the local player is among the candidates.
    assert hex(LOCAL_PLAYER + PLAYER["health"]) in narrowed["addresses"]


def test_scan_next_reports_which_addresses_moved(live_game):
    dynamic, _ = live_game
    dynamic.scan_value(GAME_PID, 100, "int32", label="hp")
    dynamic.scan_next("hp", changed=True)          # capture
    time.sleep(0.15)
    moved = dynamic.scan_next("hp", changed=True)   # narrow
    assert hex(LOCAL_PLAYER + PLAYER["health"]) in moved["addresses"]


def test_entity_positions_drift(live_game):
    dynamic, _ = live_game
    first = dynamic.read_typed(GAME_PID, ENTITY_BASE + PLAYER["position"], "float")["value"]
    time.sleep(0.12)
    second = dynamic.read_typed(GAME_PID, ENTITY_BASE + PLAYER["position"], "float")["value"]
    assert second != first


def test_infer_struct_recovers_the_player_layout(game):
    dynamic, _ = game
    inferred = dynamic.infer_struct(GAME_PID, ENTITY_BASE, PLAYER_SIZE,
                                    stride=PLAYER_SIZE, count=ENTITY_COUNT, align=4)
    by_offset = {field["offset"]: field for field in inferred["fields"]}
    # Position is three floats in a row: a float reading must be offered.
    assert "float" in " ".join(by_offset["0x10"].get("alternatives", []))
    # The name field is a string every sample agrees on the offset of.
    assert any(entry["offset"] == "0x30" for entry in inferred["strings"])
