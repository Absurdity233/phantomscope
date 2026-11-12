"""A synthetic first-person-shooter target, for exercising the cheat workflows.

The point of this module is to give the dynamic engine something with the *shape*
of a real game client so the DMA-side techniques can be driven end to end without
touching anyone's software:

* a local player struct (health, ammo, team, position, view angles),
* an entity list behind a two-level pointer path, exactly like a real
  ``EntityManager -> std::vector<Player*>``,
* a background tick that damages the local player and moves the entities, so
  ``trace_changes`` and a value-forcing loop have something to fight against.

Everything lives in a :class:`MockBackend`, so no hardware and no real process is
involved.  The layouts deliberately mirror the idioms of shipped shooters:
``std::vector<T>`` for the entity list, ``float`` triples for world positions,
an ``int32`` health and a team byte.
"""

from __future__ import annotations

import struct
import threading
import time
from dataclasses import dataclass, field

from ..errors import Unavailable
from ..models import StackFrame
from .mock import MockBackend

GAME_PID = 6100
GAME_MODULE = "firefight.exe"
GAME_MODULE_BASE = 0x7FF7_1000_0000
GAME_MODULE_SIZE = 0x8000

#: Two-level pointer path: this static slot holds the manager, the manager holds
#: the local player and the entity container.  That is the shape ``pointer_scan``
#: is built to find, and the reason every cheat feature resolves through it.
STATIC_SLOT = GAME_MODULE_BASE + 0x3000

#: Every allocation gets its own, non-overlapping page-aligned region.  Sharing
#: one region between the manager and the container truncates the manager, which
#: silently breaks every pointer path through it — exactly the kind of bug that
#: looks like "the scanner is broken".
MANAGER_BASE = 0x000003_A0_0000_0000
MANAGER_SIZE = 0x100
CONTAINER_BASE = 0x000003_A0_0000_1000
VECTOR_DATA = 0x000003_A1_0000_0000
ENTITY_BASE = 0x000003_A2_0000_0000
LOCAL_PLAYER = 0x000003_A3_0000_0000
#: A small pointer table.  Real clients reach the manager through one more hop
#: than you would expect, and ``pointer_scan`` models exactly that: each level it
#: reports is a *slot* whose content is the next slot.  Without this hop the
#: fixture only supports the path form (``base + offsets``) and not a scanned,
#: module-anchored chain — which is the thing the offset workflow has to prove.
POINTER_TABLE = 0x000003_A0_0001_0000
MANAGER_PTR_SLOT = POINTER_TABLE + 0x00
PLAYER_PTR_SLOT = POINTER_TABLE + 0x08
#: A slot holding the *address of* ``PLAYER_PTR_SLOT``, so a scanned chain has a
#: genuine middle hop.  ``pointer_scan`` walks slot -> slot; a chain of length one
#: proves nothing about multi-level resolution.
PLAYER_PTR_SLOT_LINK = POINTER_TABLE + 0x10
#: The module slot holds the *local player*, so a chain resolves as
#: ``firefight.exe+0x3008 -> LOCAL_PLAYER -> +0x04 health``.  Two hops plus a field
#: offset is what a real offset table looks like; parking the health field itself
#: in the slot would make the last offset redundant and, worse, would make a wrong
#: offset table still return the right number by accident.
HEALTH_FIELD_SLOT = GAME_MODULE_BASE + 0x3008

#: ``Player`` layout, shared by the local player and every entity.
PLAYER = {
    "id": 0x00,          # int32
    "health": 0x04,      # int32
    "armor": 0x08,       # int32
    "team": 0x0C,        # int32
    "position": 0x10,    # float[3]
    "velocity": 0x1C,    # float[3]
    "view_angle": 0x28,  # float[2]  yaw/pitch
    "name": 0x30,        # char[16]
    "weapon": 0x40,      # int32
    "ammo": 0x44,        # int32
    "flags": 0x48,       # uint32: bit0 alive, bit1 visible, bit2 scoped
}
PLAYER_SIZE = 0x50

ENTITY_COUNT = 8
LOCAL_TEAM = 2

FLAG_ALIVE = 0x1
FLAG_VISIBLE = 0x2
FLAG_SCOPED = 0x4

#: Field spec that can be handed straight to ``read_object`` / ``read_array``.
PLAYER_FIELDS = (
    "0x0:int32,0x4:int32,0x8:int32,0xc:int32,"
    "0x10:float,0x14:float,0x18:float,"
    "0x1c:float,0x20:float,0x24:float,"
    "0x28:float,0x2c:float,"
    "0x30:char[16],0x40:int32,0x44:int32,0x48:uint32"
)

ENEMY_NAMES = (
    b"hostile-01", b"hostile-02", b"hostile-03", b"hostile-04",
    b"hostile-05", b"hostile-06", b"hostile-07", b"hostile-08",
)


@dataclass
class TickState:
    """What the background tick did, so a test can assert on real motion."""

    ticks: int = 0
    damage_dealt: int = 0
    running: bool = False
    positions_moved: int = 0
    log: list[dict] = field(default_factory=list)


def _pack_player(
    player_id: int,
    health: int,
    team: int,
    position: tuple[float, float, float],
    name: bytes,
    *,
    armor: int = 0,
    ammo: int = 30,
    weapon: int = 1,
    flags: int = FLAG_ALIVE,
    yaw: float = 0.0,
    pitch: float = 0.0,
) -> bytes:
    buffer = bytearray(PLAYER_SIZE)
    struct.pack_into("<i", buffer, PLAYER["id"], player_id)
    struct.pack_into("<i", buffer, PLAYER["health"], health)
    struct.pack_into("<i", buffer, PLAYER["armor"], armor)
    struct.pack_into("<i", buffer, PLAYER["team"], team)
    struct.pack_into("<3f", buffer, PLAYER["position"], *position)
    struct.pack_into("<3f", buffer, PLAYER["velocity"], 0.0, 0.0, 0.0)
    struct.pack_into("<2f", buffer, PLAYER["view_angle"], yaw, pitch)
    buffer[PLAYER["name"] : PLAYER["name"] + 16] = name[:15].ljust(16, b"\x00")
    struct.pack_into("<i", buffer, PLAYER["weapon"], weapon)
    struct.pack_into("<i", buffer, PLAYER["ammo"], ammo)
    struct.pack_into("<I", buffer, PLAYER["flags"], flags)
    return bytes(buffer)


def build_game_backend(*, with_tick: bool = False, name: str = "game") -> tuple[MockBackend, TickState]:
    """Create the synthetic target and return it with its tick state."""
    backend = MockBackend(name=name)
    backend.bits = 64
    backend.add_process(
        GAME_PID,
        GAME_MODULE,
        ppid=8,
        path=rf"C:\Games\Firefight\{GAME_MODULE}",
        cmdline=f"{GAME_MODULE} -dx11 -nosteam",
        wow64=False,
        session=1,
        integrity="high",
        state="running",
    )
    # The static pointer slot lives *inside* the module image, because that is the
    # whole point: a chain anchored at ``firefight.exe+0x3000`` survives a restart,
    # while one anchored at a heap region does not.  Mapping it as a separate region
    # on top of the module would shadow the module and lose that anchor.
    module_image = bytearray(GAME_MODULE_SIZE)
    struct.pack_into("<Q", module_image, STATIC_SLOT - GAME_MODULE_BASE, POINTER_TABLE)
    # The plain offset-table slot: module+0x3008 -> the local player object.
    struct.pack_into("<Q", module_image, HEALTH_FIELD_SLOT - GAME_MODULE_BASE, LOCAL_PLAYER)
    backend.add_module(GAME_PID, GAME_MODULE, GAME_MODULE_BASE, bytes(module_image),
                       entry=GAME_MODULE_BASE + 0x1000, path=rf"C:\Games\Firefight\{GAME_MODULE}")

    # module+0x3008 -> LOCAL_PLAYER -> +0x04 health.  One hop, module anchored:
    # the shape a real "health offset" resolves to, and the one a restart leaves
    # intact.  The field offset stays in the caller's hands, as it does in real life.
    table = bytearray(0x100)
    struct.pack_into("<Q", table, MANAGER_PTR_SLOT - POINTER_TABLE, MANAGER_BASE)
    struct.pack_into("<Q", table, PLAYER_PTR_SLOT - POINTER_TABLE, LOCAL_PLAYER)
    struct.pack_into("<Q", table, PLAYER_PTR_SLOT_LINK - POINTER_TABLE, PLAYER_PTR_SLOT)
    backend.add_region(GAME_PID, POINTER_TABLE, bytes(table), protection="rw-", tag="heap")

    manager = bytearray(MANAGER_SIZE)
    struct.pack_into("<Q", manager, 0x08, LOCAL_PLAYER)
    struct.pack_into("<Q", manager, 0x40, CONTAINER_BASE)  # -> std::vector<Player*>
    struct.pack_into("<i", manager, 0x10, ENTITY_COUNT)
    struct.pack_into("<i", manager, 0x14, LOCAL_TEAM)
    backend.add_region(GAME_PID, MANAGER_BASE, bytes(manager), protection="rw-", tag="heap")

    container = bytearray(0x40)
    struct.pack_into("<Q", container, 0x00, VECTOR_DATA)
    struct.pack_into("<Q", container, 0x08, VECTOR_DATA + ENTITY_COUNT * 8)
    struct.pack_into("<Q", container, 0x10, VECTOR_DATA + ENTITY_COUNT * 8)
    backend.add_region(GAME_PID, CONTAINER_BASE, bytes(container), protection="rw-", tag="heap")

    pointers = bytearray(ENTITY_COUNT * 8)
    entities = bytearray(ENTITY_COUNT * PLAYER_SIZE)
    for index in range(ENTITY_COUNT):
        slot = ENTITY_BASE + index * PLAYER_SIZE
        struct.pack_into("<Q", pointers, index * 8, slot)
        blob = _pack_player(
            player_id=100 + index,
            health=100,
            team=1 if index % 2 == 0 else 3,
            position=(10.0 + index * 4.0, 20.0 - index * 2.5, 1.5),
            name=ENEMY_NAMES[index],
            armor=50 if index % 3 == 0 else 0,
            ammo=24 + index,
            weapon=2 if index % 2 else 1,
            flags=FLAG_ALIVE | (FLAG_VISIBLE if index % 2 == 0 else 0),
        )
        entities[index * PLAYER_SIZE : (index + 1) * PLAYER_SIZE] = blob
    backend.add_region(GAME_PID, VECTOR_DATA, bytes(pointers), protection="rw-", tag="heap")
    backend.add_region(GAME_PID, ENTITY_BASE, bytes(entities), protection="rw-", tag="heap")

    local = _pack_player(
        player_id=1,
        health=100,
        team=LOCAL_TEAM,
        position=(0.0, 0.0, 1.5),
        name=b"you",
        armor=100,
        ammo=30,
        weapon=3,
        flags=FLAG_ALIVE,
        yaw=90.0,
        pitch=-4.5,
    )
    backend.add_region(GAME_PID, LOCAL_PLAYER, local, protection="rw-", tag="heap")

    backend.add_thread(
        GAME_PID,
        0x2C00,
        frames=[
            StackFrame(va=GAME_MODULE_BASE + 0x1200, module=GAME_MODULE, offset=0x1200,
                       symbol=f"{GAME_MODULE}!CGame::Tick", role="rip"),
            StackFrame(va=GAME_MODULE_BASE + 0x1040, module=GAME_MODULE, offset=0x1040,
                       symbol=f"{GAME_MODULE}!WinMain", role="return"),
        ],
        state="running",
        priority=8,
        teb=LOCAL_PLAYER + 0x1000,
        stack_base=LOCAL_PLAYER + 0x2000,
        stack_limit=LOCAL_PLAYER,
    )
    backend.add_symbol(GAME_PID, GAME_MODULE, "CGame::Tick", GAME_MODULE_BASE + 0x1200)
    backend.add_symbol(GAME_PID, GAME_MODULE, "CLocalPlayer::Update", GAME_MODULE_BASE + 0x1300)
    backend.heaps[GAME_PID] = [{"index": 0, "va": MANAGER_BASE, "size": 0x100}]
    backend.open()

    state = TickState()
    if with_tick:
        state.thread = start_tick(backend, state)  # type: ignore[attr-defined]
    return backend, state


def start_tick(backend: MockBackend, state: TickState, *, interval: float = 0.02,
               damage: int = 1) -> threading.Thread:
    """Damage the local player and drift the entities, like a game loop would.

    This is what makes the value-forcing loop meaningful: something is actively
    trying to take the health back down, exactly like a real enemy shooting you.
    """

    def run() -> None:
        state.running = True
        try:
            while state.running:
                time.sleep(interval)
                if not state.running:
                    break
                try:
                    health = struct.unpack(
                        "<i", backend.read(GAME_PID, LOCAL_PLAYER + PLAYER["health"], 4)
                    )[0]
                    if health > 0:
                        backend.write(GAME_PID, LOCAL_PLAYER + PLAYER["health"],
                                      struct.pack("<i", max(0, health - damage)))
                        state.damage_dealt += min(damage, health)
                    # Drift every entity, so position reads are not static.
                    for index in range(ENTITY_COUNT):
                        at = ENTITY_BASE + index * PLAYER_SIZE + PLAYER["position"]
                        x, y, z = struct.unpack("<3f", backend.read(GAME_PID, at, 12))
                        backend.write(GAME_PID, at, struct.pack("<3f", x + 0.25, y - 0.1, z))
                        state.positions_moved += 1
                except Unavailable:
                    # The owner closed the backend; that is a normal shutdown, not
                    # a failure, and it must not surface as a thread exception.
                    break
                state.ticks += 1
                if state.ticks <= 4096:
                    state.log.append({"tick": state.ticks, "health": health})
        finally:
            state.running = False

    thread = threading.Thread(target=run, daemon=True, name="firefight-tick")
    thread.start()
    return thread


def stop_tick(state: TickState, thread: threading.Thread | None = None) -> None:
    """Stop the background tick and wait for it, so no read races a close."""
    state.running = False
    if thread is not None:
        thread.join(timeout=2.0)
