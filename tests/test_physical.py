"""Physical-memory layer: image, page tables, PE scanning, backend."""

from __future__ import annotations

import struct

import pytest

from phantomscope.analysis.engine import StaticEngine
from phantomscope.backends.demo import build_minimal_pe, map_pe_file
from phantomscope.backends.factory import create_backend
from phantomscope.errors import BackendError, InvalidArgument, Unavailable
from phantomscope.physical import (
    PhysicalBackend,
    PhysicalImage,
    X64Pager,
    parse_memmap,
    scan_pe_images,
)
from phantomscope.physical.pescan import read_image_bytes

PAGE = 0x1000
CR3 = 0x20_0000

# Layout of the synthetic physical dump.
PE_PA = 0x10_0000
PML4_PA = CR3
PDPT_PA = CR3 + PAGE
PD_PA = CR3 + 2 * PAGE
PT_PA = CR3 + 3 * PAGE
PT2_PA = CR3 + 4 * PAGE
IMAGE_VA = 0x7FF6_0000_0000
DUMP_SIZE = 0x40_0000


def _entry(pa: int, flags: int = 0x7) -> bytes:
    return struct.pack("<Q", (pa & 0x000F_FFFF_FFFF_F000) | flags)


def _build_dump(path, image: bytes) -> str:
    """Write a raw dump with page tables mapping IMAGE_VA -> PE_PA."""
    data = bytearray(DUMP_SIZE)

    def put(pa: int, blob: bytes) -> None:
        data[pa : pa + len(blob)] = blob

    put(PE_PA, image)

    # 4 KiB pages across two PTs (2 x 512 pages = 4 MiB of VA).
    for page_index in range(0x200):
        put(PT_PA + page_index * 8, _entry(PE_PA + page_index * PAGE))
    for page_index in range(0x200):
        put(PT2_PA + page_index * 8, _entry(PE_PA + PAGE + page_index * PAGE))

    pml4e = (IMAGE_VA >> 39) & 0x1FF
    pdpte = (IMAGE_VA >> 30) & 0x1FF
    pde = (IMAGE_VA >> 21) & 0x1FF
    pte = (IMAGE_VA >> 12) & 0x1FF
    assert pte == 0, "fixture assumes an aligned mapping"

    put(PML4_PA + pml4e * 8, _entry(PDPT_PA))
    put(PDPT_PA + pdpte * 8, _entry(PD_PA))
    put(PD_PA + pde * 8, _entry(PT_PA))
    put(PD_PA + (pde + 1) * 8, _entry(PT2_PA))

    # A 2 MiB large page mapping, to exercise the big-page path.
    large_pde = pde + 2
    put(PML4_PA + pml4e * 8, _entry(PDPT_PA))
    put(PD_PA + large_pde * 8, _entry(PE_PA, flags=0x87))

    with open(path, "wb") as handle:
        handle.write(bytes(data))
    return str(path)


@pytest.fixture()
def dump_path(tmp_path, demo_pe_bytes):
    return _build_dump(tmp_path / "mem.raw", map_pe_file(demo_pe_bytes))


@pytest.fixture()
def image(dump_path):
    instance = PhysicalImage(dump_path)
    yield instance
    instance.close()


@pytest.fixture()
def pager(image):
    return X64Pager(image, CR3)


# -- memmap -------------------------------------------------------------------
def test_parse_memmap_single_and_multi():
    one = parse_memmap("0x1000,0x2000")
    assert [(s.pa, s.size, s.file_offset) for s in one] == [(0x1000, 0x2000, 0)]

    many = parse_memmap("0x1000,0x1000;0x8000,0x2000")
    assert [(s.pa, s.size, s.file_offset) for s in many] == [
        (0x1000, 0x1000, 0),
        (0x8000, 0x2000, 0x1000),
    ]


def test_parse_memmap_rejects_bad_entries():
    for spec in ("0x1000", "abc,def", "0x1000,0", "-1,0x1000"):
        with pytest.raises(InvalidArgument):
            parse_memmap(spec)


# -- physical image -----------------------------------------------------------
def test_image_geometry(image):
    assert image.file_size == DUMP_SIZE
    assert image.mapped_bytes == DUMP_SIZE
    assert image.max_address == DUMP_SIZE
    assert image.contains(0) and image.contains(PE_PA)
    assert not image.contains(DUMP_SIZE)


def test_image_reads_pe_header(image, demo_pe_bytes):
    assert image.read(PE_PA, 2) == b"MZ"
    assert image.read(PE_PA, 4) == map_pe_file(demo_pe_bytes)[:4]


def test_image_gap_reads_zero_and_is_counted(tmp_path):
    raw = tmp_path / "sparse.raw"
    raw.write_bytes(bytes(0x3000))
    sparse = PhysicalImage(str(raw), parse_memmap("0x1000,0x1000;0x20000,0x1000"))
    try:
        assert sparse.read(0x1000, 4) == b"\x00" * 4
        assert sparse.read(0x5000, 8) == b"\x00" * 8  # in the gap
        assert sparse.read_misses >= 1
        assert [pa for pa, _size in sparse.map()] == [0x1000, 0x20000]
    finally:
        sparse.close()


def test_image_write_roundtrip(dump_path):
    image = PhysicalImage(dump_path)
    try:
        image.write(PE_PA + 0x100, b"\xAA\xBB")
        assert image.read(PE_PA + 0x100, 2) == b"\xAA\xBB"
        assert image.write_count == 1
        with pytest.raises(BackendError):
            image.write(DUMP_SIZE - 1, b"\x00\x00")  # runs past the dump
    finally:
        image.close()


def test_image_rejects_segment_larger_than_file(tmp_path):
    raw = tmp_path / "small.raw"
    raw.write_bytes(bytes(0x1000))
    with pytest.raises(InvalidArgument):
        PhysicalImage(str(raw), parse_memmap("0x0,0x2000"))


def test_image_rejects_overlapping_segments(tmp_path):
    raw = tmp_path / "overlap.raw"
    raw.write_bytes(bytes(0x2000))
    with pytest.raises(InvalidArgument):
        PhysicalImage(str(raw), parse_memmap("0x1000,0x1000;0x1800,0x1000"))


# -- paging -------------------------------------------------------------------
def test_translate_small_pages(pager):
    assert pager.translate(IMAGE_VA) == PE_PA
    assert pager.translate(IMAGE_VA + 0x123) == PE_PA + 0x123


def test_translate_second_page(pager):
    assert pager.translate(IMAGE_VA + PAGE) == PE_PA + PAGE


def test_translate_unmapped_returns_none(pager):
    # No PD entry exists this far into the address range.
    assert pager.translate(IMAGE_VA + 0x2000_0000) is None


def test_read_virtual_crosses_a_page(pager, demo_pe_bytes):
    data = pager.read(IMAGE_VA + PAGE - 4, 8)
    assert data == map_pe_file(demo_pe_bytes)[PAGE - 4 : PAGE + 4]


def test_read_virtual_strict_raises_on_hole(pager):
    hole = IMAGE_VA + 0x2000_0000
    with pytest.raises(InvalidArgument):
        pager.read(hole, 8)
    assert pager.read(hole, 8, strict=False) == b"\x00" * 8


def test_large_page_translation(pager):
    large_va = IMAGE_VA + 0x400_000  # pde + 2, mapped as a 2 MiB page
    assert pager.translate(large_va) == (PE_PA & ~0x1F_FFFF) | (large_va & 0x1F_FFFF)


def test_walk_range_reports_present_pages(pager):
    hits = pager.walk_range(IMAGE_VA, 0x3000)
    assert [h["va"] for h in hits] == [hex(IMAGE_VA), hex(IMAGE_VA + PAGE), hex(IMAGE_VA + 2 * PAGE)]


def test_read_cstring(pager):
    assert pager.read_cstring(IMAGE_VA) == "MZ"


# -- PE scanning --------------------------------------------------------------
def test_scan_finds_the_image(image):
    hits = scan_pe_images(image)
    assert [h.pa for h in hits] == [PE_PA]
    hit = hits[0]
    assert hit.arch == "x64"
    assert hit.size == 0x4000
    assert hit.entry_rva == 0x1000
    assert hit.end == PE_PA + 0x4000


def test_scanned_image_flows_into_static_engine(image):
    hit = scan_pe_images(image)[0]
    payload = read_image_bytes(image, hit)
    engine = StaticEngine()
    engine.load_capture("phys", payload, PE_PA)
    summary = engine.summary("phys")
    assert summary["arch"] == "x64"
    assert summary["entry"] == hex(PE_PA + 0x1000)
    instructions = engine.disassemble("phys", None, count=3)
    assert instructions[0]["mnemonic"] == "sub"


# -- backend ------------------------------------------------------------------
@pytest.fixture()
def backend(dump_path):
    instance = PhysicalBackend(device=dump_path, name="phys")
    instance.open()
    yield instance
    instance.close()


def test_backend_geometry_and_map(backend):
    info = backend.info()
    assert info["kind"] == "physical"
    assert info["mapped_bytes"] == DUMP_SIZE
    regions = backend.physical_map()
    assert regions[0].base == 0 and regions[0].size == DUMP_SIZE


def test_backend_physical_read_write(backend):
    assert backend.read_physical(PE_PA, 2) == b"MZ"
    backend.write_physical(PE_PA + 0x200, b"\x41\x42")
    assert backend.read_physical(PE_PA + 0x200, 2) == b"\x41\x42"


def test_backend_virtual_read_through_cr3(backend):
    backend.set_cr3(CR3)
    assert backend.translate(IMAGE_VA) == PE_PA
    assert backend.read_virtual(IMAGE_VA, 2) == b"MZ"


def test_backend_read_contract_pid_zero_is_physical(backend):
    assert backend.read(0, PE_PA, 2) == b"MZ"


def test_backend_read_contract_pid_is_cr3(backend):
    assert backend.read(CR3, IMAGE_VA, 2) == b"MZ"


def test_backend_virtual_write_roundtrip(backend):
    backend.set_cr3(CR3)
    backend.write_virtual(IMAGE_VA + 0x3000, b"\x11\x22")
    assert backend.read_virtual(IMAGE_VA + 0x3000, 2) == b"\x11\x22"


def test_backend_has_no_process_list(backend):
    with pytest.raises(Unavailable):
        backend.list_processes()


def test_backend_modules_are_scan_results(backend):
    modules = backend.list_modules(0)
    assert modules[0].base == PE_PA
    assert modules[0].name == f"image_{PE_PA:x}"


def test_backend_capture_image(backend):
    payload, base_va, hit = backend.capture_image(PE_PA)
    assert hit.pa == PE_PA
    assert len(payload) == 0x4000
    assert hit.arch == "x64"
    # The base is the PE ImageBase, not the physical address.
    assert base_va == hit.image_base_va


def test_backend_capture_image_accepts_load_base(backend):
    payload, base_va, hit = backend.capture_image(PE_PA, base_va=IMAGE_VA)
    assert base_va == IMAGE_VA
    assert payload[:2] == b"MZ"


def test_backend_capture_rejects_non_pe(backend):
    with pytest.raises(InvalidArgument):
        backend.capture_image(0x3000)


def test_backend_image_cache_refresh(backend):
    first = [hit.pa for hit in backend.images()]
    assert [hit.pa for hit in backend.images()] == first  # cached
    assert [hit.pa for hit in backend.images(refresh=True)] == first


def test_backend_requires_cr3_for_virtual_reads(backend):
    with pytest.raises(InvalidArgument):
        backend.read_virtual(IMAGE_VA, 4)


def test_backend_rejects_missing_path():
    instance = PhysicalBackend(device="")
    with pytest.raises(InvalidArgument):
        instance.open()


def test_factory_creates_physical_backend(dump_path):
    backend = create_backend("physical", device=dump_path)
    backend.open()
    try:
        assert backend.kind == "physical"
        assert backend.read_physical(PE_PA, 2) == b"MZ"
    finally:
        backend.close()


def test_backend_memmap_option(tmp_path, demo_pe_bytes):
    raw = tmp_path / "seg.raw"
    raw.write_bytes(map_pe_file(demo_pe_bytes))
    backend = PhysicalBackend(device=str(raw), options=["memmap=0x800000,0x4000"])
    backend.open()
    try:
        assert backend.physical_map()[0].base == 0x800000
        assert backend.read_physical(0x800000, 2) == b"MZ"
    finally:
        backend.close()
