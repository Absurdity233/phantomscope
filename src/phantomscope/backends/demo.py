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

from ..models import StackFrame
from .mock import MockBackend

DEMO_PID = 4242
MODULE_BASE = 0x7FF6_0000_0000
MODULE_SIZE = 0x4000
HEAP_BASE = 0x000002_1A_0000_0000
STACK_BASE = 0x000000_5C_0000_0000

PLAYER_HEALTH_OFFSET = 0x120
PLAYER_AMMO_OFFSET = 0x124
PLAYER_SCORE_OFFSET = 0x128
PLAYER_NAME_OFFSET = 0x130


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
    backend.add_physical(0x1000, module_image[:0x2000])
    return backend


def load_sample_module(path: str | None) -> bytes | None:
    """Read a PE file to use as the demo module, tolerating its absence."""
    if not path or not os.path.isfile(path):
        return None
    with open(path, "rb") as handle:
        return handle.read()
