"""A deterministic synthetic target for demos, tests and hardware-less runs.

``populate_demo_backend`` builds a mock process that behaves like a small
Windows game client: a mapped PE module, a heap region with a "player" struct,
a stack region, two threads with plausible callstacks, handles and PDB-style
symbols.

Nothing here touches hardware, so ``session_open(backend="mock")`` always works
and the full static + dynamic pipeline can be exercised end to end.
"""

from __future__ import annotations

import os
import struct

from ..models import ModuleInfo, StackFrame
from .mock import MockBackend

DEMO_PID = 4242
MODULE_BASE = 0x7FF6_0000_0000
MODULE_SIZE = 0x4000
HEAP_BASE = 0x000002_1A_0000_0000
STACK_BASE = 0x000000_5C_0000_0000
ARENA_BASE = 0x000002_1B_0000_0000

PLAYER_HEALTH_OFFSET = 0x120
PLAYER_AMMO_OFFSET = 0x124
PLAYER_SCORE_OFFSET = 0x128
PLAYER_NAME_OFFSET = 0x130

#: A ``std::vector<Npc>``-shaped header in the heap: {begin, end, capacity}.
VECTOR_HEADER_OFFSET = 0x180
#: An ``Npc**`` array: qwords that point at the arena records.
POINTER_ARRAY_OFFSET = 0x1C0
#: A one-hop pointer, so pointer-chain resolution has something to walk.
CHAIN_SLOT_OFFSET = 0x1E0
CHAIN_TARGET_OFFSET = 0x1F0
CHAIN_VALUE = 0xDEAD_BEEF

#: Arena record layout: int32 id, int32 health, char name[12], qword vtable.
ARENA_STRIDE = 0x20
ARENA_COUNT = 4
NPC_NAMES = (b"alpha", b"bravo", b"charlie", b"delta")
NPC_HEALTH = (100, 80, 60, 0)


def build_minimal_pe() -> bytes:
    """Build a small but valid PE32+ image (one section, a handful of insns)."""
    image = bytearray(MODULE_SIZE)

    # DOS header
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)

    # PE signature + COFF header
    image[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH", image, 0x44,
        0x8664,   # Machine: AMD64
        1,        # NumberOfSections
        0,        # TimeDateStamp
        0, 0,     # symbol table
        0xF0,     # SizeOfOptionalHeader
        0x0022,   # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    # Optional header (PE32+)
    opt = 0x58
    struct.pack_into("<H", image, opt + 0, 0x20B)   # Magic
    struct.pack_into("<B", image, opt + 2, 1)       # MajorLinkerVersion
    struct.pack_into("<I", image, opt + 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<I", image, opt + 20, 0x1000)  # BaseOfCode
    struct.pack_into("<Q", image, opt + 24, MODULE_BASE)  # ImageBase
    struct.pack_into("<I", image, opt + 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", image, opt + 36, 0x200)   # FileAlignment
    struct.pack_into("<H", image, opt + 40, 6)       # MajorOperatingSystemVersion
    struct.pack_into("<H", image, opt + 48, 6)       # MajorSubsystemVersion
    struct.pack_into("<I", image, opt + 56, MODULE_SIZE)  # SizeOfImage
    struct.pack_into("<I", image, opt + 60, 0x200)   # SizeOfHeaders
    struct.pack_into("<H", image, opt + 68, 3)       # Subsystem: CUI
    struct.pack_into("<H", image, opt + 70, 0x8160)  # DllCharacteristics
    struct.pack_into("<Q", image, opt + 72, 0x100000)  # SizeOfStackReserve
    struct.pack_into("<Q", image, opt + 80, 0x1000)  # SizeOfStackCommit
    struct.pack_into("<Q", image, opt + 88, 0x100000)  # SizeOfHeapReserve
    struct.pack_into("<Q", image, opt + 96, 0x1000)  # SizeOfHeapCommit
    struct.pack_into("<I", image, opt + 108, 16)     # NumberOfRvaAndSizes

    # Section header (40 bytes) right after the optional header
    section = opt + 0xF0
    image[section : section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", image, section + 8, 0x1000, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)  # code | execute | read

    # Function bodies.  RVA 0x1000 is the entry point and also `main`.
    main = bytes.fromhex(
        "4883ec28"          # 0x1000 sub rsp, 0x28
        "e80c000000"        # 0x1004 call 0x1015 (update_health)
        "4883c428"          # 0x1009 add rsp, 0x28
        "c3"                # 0x100d ret
        "cccccccccccccc"    # 0x100e..0x1014 padding
    )
    # NOTE: this function builds a *file* image, so RVA 0x1000 lives at the
    # section's raw offset (0x200) rather than at the RVA itself.
    raw = 0x200
    image[raw : raw + len(main)] = main
    update_health = bytes.fromhex(
        "8b0d65000000"      # 0x1015 mov ecx, [rip+0x65]  -> 0x1080
        "83c105"            # 0x101b add ecx, 5
        "890d5c000000"      # 0x101e mov [rip+0x5c], ecx  -> 0x1080
        "c3"                # 0x1024 ret
    )
    image[raw + 0x15 : raw + 0x15 + len(update_health)] = update_health
    struct.pack_into("<i", image, raw + 0x80, 100)  # health global at 0x1080

    return bytes(image)


STRUCT_UPDATE_RVA = 0x1030


def build_struct_demo_pe() -> bytes:
    """A second synthetic module whose callee touches a struct through ``rcx``.

    ``struct_update(rcx)`` reads and writes a handful of fields at fixed
    offsets, which is exactly the pattern :mod:`phantomscope.analysis.structs`
    turns into a candidate layout.  Keeping it in its own image means the
    layout tests do not depend on the demo target's exact instruction stream.
    """
    image = bytearray(build_minimal_pe())
    raw = 0x200  # raw offset of RVA 0x1000 in the single .text section

    main = bytes.fromhex(
        "4883ec28"      # 0x1000 sub rsp, 0x28
        "e827000000"    # 0x1004 call 0x1030 (struct_update)
        "4883c428"      # 0x1009 add rsp, 0x28
        "c3"            # 0x100d ret
    )
    struct_update = bytes.fromhex(
        "8b4110"        # 0x1030 mov eax, [rcx+0x10]
        "894114"        # 0x1033 mov [rcx+0x14], eax
        "488b5108"      # 0x1036 mov rdx, [rcx+0x8]
        "83790c00"      # 0x103a cmp dword [rcx+0xc], 0
        "7402"          # 0x103e je 0x1042
        "c3"            # 0x1040 ret
        "c3"            # 0x1041 ret (padding)
        "8b4118"        # 0x1042 mov eax, [rcx+0x18]
        "c3"            # 0x1045 ret
    )

    image[raw : raw + len(main)] = main
    image[raw + 0x30 : raw + 0x30 + len(struct_update)] = struct_update
    return bytes(image)


def _put(image: bytearray, rva: int, data: bytes) -> None:
    """Write bytes at an RVA of the single-section demo PE.

    ``build_minimal_pe`` maps RVA 0x1000 at file offset 0x200, so this is the
    only conversion needed; it keeps the builders free of magic offsets.
    """
    offset = 0x200 + (rva - 0x1000)
    image[offset : offset + len(data)] = data


def build_flow_demo_pe() -> bytes:
    """A module with real control flow: a loop and an if/else with two returns.

    ``sum(n)`` is the classic accumulator loop and ``pick(a)`` is the classic
    "compare then return one of two constants", which is what the pseudo-C
    structurer is tested against.
    """
    image = bytearray(build_minimal_pe())
    # Entry point stays at `_main`, which now calls both new functions.
    struct.pack_into("<I", image, 0x58 + 16, 0x1040)

    # 0x1000 sum(int n in ecx)
    _put(image, 0x1000, bytes.fromhex(
        "31c0"            # xor eax, eax
        "85c9"            # test ecx, ecx
        "7e06"            # jle 0x100c
        "01c8"            # add eax, ecx
        "ffc9"            # dec ecx
        "75fa"            # jnz 0x1006
        "c3"              # ret
    ))

    # 0x1020 pick(int a in ecx)
    _put(image, 0x1020, bytes.fromhex(
        "83f905"          # cmp ecx, 5
        "7e06"            # jle 0x102b
        "b864000000"      # mov eax, 100
        "c3"              # ret
        "b807000000"      # mov eax, 7
        "c3"              # ret
    ))

    # 0x1040 _main
    _put(image, 0x1040, bytes.fromhex(
        "4883ec28"        # sub rsp, 0x28
        "b905000000"      # mov ecx, 5
        "e8b2ffffff"      # call 0x1000
        "e8cdffffff"      # call 0x1020
        "4883c428"        # add rsp, 0x28
        "c3"              # ret
    ))
    return bytes(image)


def build_api_demo_pe() -> bytes:
    """A module with a real import table (``KERNEL32!Sleep``, ``GetTickCount``).

    The entry point calls both imports through their IAT slots and loads a string
    literal, which is what the API-resolution, string-xref and import-stub tests
    need.  The imported names never resolve: nothing here is executed for real.
    """
    image = bytearray(build_minimal_pe())

    # 0x1000 _main: Sleep(10); then GetTickCount() with a string argument.
    _put(image, 0x1000, bytes.fromhex(
        "4883ec28"        # 0x1000 sub rsp, 0x28
        "b90a000000"      # 0x1004 mov ecx, 10
        "ff1521000000"    # 0x1009 call qword [rip+0x21] -> 0x1030 (Sleep)
        "488d0d8a000000"  # 0x100f lea rcx, [rip+0x8a]  -> 0x10a0 (string)
        "ff151c000000"    # 0x1016 call qword [rip+0x1c] -> 0x1038 (GetTickCount)
        "4883c428"        # 0x101c add rsp, 0x28
        "c3"              # 0x1020 ret
    ))

    # IAT (0x1030) and import lookup table (0x1048) share the hint/name pointers.
    for slot, target in ((0x1030, 0x1070), (0x1038, 0x1078),
                         (0x1048, 0x1070), (0x1050, 0x1078)):
        struct.pack_into("<Q", image, 0x200 + (slot - 0x1000), target)
    struct.pack_into("<Q", image, 0x200 + (0x1040 - 0x1000), 0)
    struct.pack_into("<Q", image, 0x200 + (0x1058 - 0x1000), 0)

    _put(image, 0x1070, b"\x00\x00Sleep\x00")             # 0x1070..0x1077
    _put(image, 0x1078, b"\x00\x00GetTickCount\x00")      # 0x1078..0x1086
    _put(image, 0x1088, b"KERNEL32.dll\x00")              # 0x1088..0x1094
    _put(image, 0x10A0, b"demo-secret-key\x00")           # string literal

    # IMAGE_IMPORT_DESCRIPTOR at 0x10b0, one entry plus the null terminator.
    struct.pack_into("<IIIII", image, 0x200 + (0x10B0 - 0x1000),
                     0x1048, 0, 0, 0x1088, 0x1030)
    struct.pack_into("<IIIII", image, 0x200 + (0x10B0 - 0x1000) + 20, 0, 0, 0, 0, 0)
    # DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = (rva, size)
    struct.pack_into("<II", image, 0x58 + 112 + 8, 0x10B0, 0x28)
    return bytes(image)


def map_pe_file(data: bytes) -> bytes:
    """Convert a raw PE file image into an RVA-indexed memory image.

    A live module captured over DMA is RVA-indexed; the mock backend stores
    modules the same way so ``capture_module`` behaves identically on both.
    """
    import pefile

    pe = pefile.PE(data=bytes(data), fast_load=True)
    size = int(pe.OPTIONAL_HEADER.SizeOfImage or len(data))
    mapped = bytearray(size)
    header_size = min(int(pe.OPTIONAL_HEADER.SizeOfHeaders or 0x400), len(data))
    mapped[:header_size] = data[:header_size]
    for section in pe.sections:
        start = int(section.VirtualAddress)
        chunk = bytes(data[int(section.PointerToRawData) : int(section.PointerToRawData) + int(section.SizeOfRawData)])
        if start < size and chunk:
            mapped[start : start + min(len(chunk), size - start)] = chunk[: size - start]
    return bytes(mapped)


def populate_demo_backend(backend: MockBackend, *, module_bytes: bytes | None = None,
                          name: str = "demo_target.exe") -> MockBackend:
    """Create the demo process inside ``backend``.

    ``module_bytes`` is a file-layout PE; the backend stores the RVA-indexed
    image, exactly like a module captured from live memory.
    """
    data = module_bytes or build_minimal_pe()
    module_image = map_pe_file(data)
    backend.bits = 64
    backend.add_process(
        DEMO_PID,
        name,
        ppid=4,
        path=rf"C:\Games\Demo\{name}",
        cmdline=f"{name} --headless",
        wow64=False,
        session=1,
        integrity="medium",
        state="running",
    )
    backend.add_module(
        DEMO_PID,
        name,
        MODULE_BASE,
        module_image,
        entry=MODULE_BASE + 0x1000,
        path=rf"C:\Games\Demo\{name}",
    )

    heap = bytearray(0x400)
    struct.pack_into("<i", heap, PLAYER_HEALTH_OFFSET, 100)
    struct.pack_into("<i", heap, PLAYER_AMMO_OFFSET, 30)
    struct.pack_into("<i", heap, PLAYER_SCORE_OFFSET, 1337)
    heap[PLAYER_NAME_OFFSET : PLAYER_NAME_OFFSET + 8] = b"PLAYER01"
    struct.pack_into("<Q", heap, 0x100, MODULE_BASE + 0x1000)  # a vtable-ish pointer

    # An arena of small records plus the container shapes that point into it, so
    # container detection, array reads and layout inference have real data.
    arena = bytearray(ARENA_STRIDE * ARENA_COUNT)
    for index in range(ARENA_COUNT):
        base = index * ARENA_STRIDE
        struct.pack_into("<i", arena, base + 0x00, index + 1)
        struct.pack_into("<i", arena, base + 0x04, NPC_HEALTH[index])
        arena[base + 0x08 : base + 0x08 + 8] = NPC_NAMES[index].ljust(8, b"\x00")
        struct.pack_into("<Q", arena, base + 0x18, MODULE_BASE + 0x1000)
    backend.add_region(DEMO_PID, ARENA_BASE, bytes(arena), protection="rw-", tag="arena")

    struct.pack_into("<Q", heap, VECTOR_HEADER_OFFSET, ARENA_BASE)
    struct.pack_into("<Q", heap, VECTOR_HEADER_OFFSET + 8, ARENA_BASE + len(arena))
    struct.pack_into("<Q", heap, VECTOR_HEADER_OFFSET + 16, ARENA_BASE + len(arena))
    for index in range(ARENA_COUNT):
        struct.pack_into("<Q", heap, POINTER_ARRAY_OFFSET + index * 8,
                         ARENA_BASE + index * ARENA_STRIDE)
    struct.pack_into("<Q", heap, CHAIN_SLOT_OFFSET, HEAP_BASE + CHAIN_TARGET_OFFSET)
    struct.pack_into("<I", heap, CHAIN_TARGET_OFFSET + 8, CHAIN_VALUE)

    backend.add_region(DEMO_PID, HEAP_BASE, bytes(heap), protection="rw-", tag="heap")

    stack = bytearray(0x2000)
    struct.pack_into("<Q", stack, 0, MODULE_BASE + 0x1004)
    struct.pack_into("<Q", stack, 8, HEAP_BASE + PLAYER_HEALTH_OFFSET)
    backend.add_region(DEMO_PID, STACK_BASE, bytes(stack), protection="rw-", tag="stack")

    backend.add_thread(
        DEMO_PID,
        0x1A2B,
        frames=[
            StackFrame(va=MODULE_BASE + 0x1015, module=name, offset=0x1015,
                       symbol=f"{name}!update_health", role="rip"),
            StackFrame(va=MODULE_BASE + 0x1004, module=name, offset=0x1004,
                       symbol=f"{name}!main", role="return"),
            StackFrame(va=0x7FFB_1234_5678, module="ntdll.dll", offset=0x15678,
                       symbol="ntdll.dll!RtlUserThreadStart", role="return"),
        ],
        state="running",
        priority=8,
        teb=STACK_BASE + 0x1000,
        stack_base=STACK_BASE + 0x2000,
        stack_limit=STACK_BASE,
    )
    backend.add_thread(DEMO_PID, 0x1A2C, state="waiting", priority=9)

    backend.add_symbol(DEMO_PID, name, "main", MODULE_BASE + 0x1000)
    backend.add_symbol(DEMO_PID, name, "update_health", MODULE_BASE + 0x1015)

    backend.heaps[DEMO_PID] = [{"index": 0, "va": HEAP_BASE, "size": 0x400}]
    backend.handles[DEMO_PID] = [
        {"handle": 0x4, "type": "Event", "name": "demo-event"},
        {"handle": 0x8, "type": "File", "name": r"\Device\HarddiskVolume3\Games\Demo\data.pak"},
    ]
    # A minimal kernel view so the kernel tools have something to return.
    backend._kernel_modules = [
        ModuleInfo(name="ntoskrnl.exe", base=0xFFFF_F800_0000_0000, size=0xB00000,
                   path=r"\SystemRoot\System32\ntoskrnl.exe"),
        ModuleInfo(name="demo_driver.sys", base=0xFFFF_F800_00B0_0000, size=0x20000,
                   path=r"\SystemRoot\System32\drivers\demo_driver.sys"),
    ]
    backend._kernel_processes = [backend.processes[DEMO_PID]]
    backend.add_physical(0x1000, module_image[:0x2000])
    return backend


def load_sample_module(path: str | None) -> bytes | None:
    """Read a PE file to use as the demo module, tolerating its absence."""
    if not path or not os.path.isfile(path):
        return None
    with open(path, "rb") as handle:
        return handle.read()
