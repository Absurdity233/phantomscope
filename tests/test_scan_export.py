"""Live string scanning and module export — the two gaps in the old surface."""

from __future__ import annotations

import struct

import pytest

from phantomscope.analysis.engine import StaticEngine
from phantomscope.analysis.pe import load_pe_from_bytes
from phantomscope.backends.demo import (
    ARENA_BASE,
    DEMO_PID,
    HEAP_BASE,
    MODULE_BASE,
    build_minimal_pe,
    map_pe_file,
    populate_demo_backend,
)
from phantomscope.backends.mock import MockBackend
from phantomscope.dynamic.engine import DynamicEngine, _iter_strings
from phantomscope.errors import InvalidArgument

# -- the run extractor -------------------------------------------------------


def test_ascii_runs_are_found_anywhere_in_the_buffer():
    data = b"\x01\x02\x03secret-token\x00\xff\xfehttp://c2.example/gate\x00"
    texts = [hit["text"] for hit in _iter_strings(data, 1, 6)]
    assert texts == ["secret-token", "http://c2.example/gate"]


def test_short_runs_are_dropped():
    data = b"ab\x00abcdefgh\x00"
    assert [hit["text"] for hit in _iter_strings(data, 1, 6)] == ["abcdefgh"]


def test_wide_runs_need_a_zero_high_byte():
    good = "wide secret".encode("utf-16-le") + b"\x00\x00"
    # The same bytes read as ASCII would look like garbage, not a string.
    assert [hit["text"] for hit in _iter_strings(good, 2, 6)] == ["wide secret"]

    # A run of UTF-16 Cyrillic has non-zero high bytes and must not match.
    cyrillic = "привет".encode("utf-16-le") + b"\x00\x00"
    assert list(_iter_strings(cyrillic, 2, 6)) == []


@pytest.mark.parametrize("pad", [0, 1])
def test_wide_runs_are_found_at_both_alignments(pad):
    # A string is only 2-aligned relative to its allocation, not to the region we
    # read, so an even-only walk would miss about half of all wide strings.
    data = b"\x11" * pad + "paid".encode("utf-16-le") + b"\x00\x00"
    assert [hit["text"] for hit in _iter_strings(data, 2, 4)] == ["paid"]


def test_a_run_touching_the_end_of_the_buffer_still_counts():
    data = b"\x00" + b"trailing"
    assert [hit["text"] for hit in _iter_strings(data, 1, 6)] == ["trailing"]


# -- live scan ---------------------------------------------------------------


def _write_string(dynamic, va, text, *, wide=False):
    payload = text.encode("utf-16-le") if wide else text.encode()
    dynamic.write(DEMO_PID, va, data=payload.hex())


def test_scan_strings_finds_a_heap_string(dynamic):
    _write_string(dynamic, HEAP_BASE + 0x220, "wss://relay.invalid/session")
    found = dynamic.scan_strings(DEMO_PID, "relay.invalid", encoding="ascii")
    assert found["count"] == 1
    assert found["matches"][0]["text"] == "wss://relay.invalid/session"
    assert found["matches"][0]["va"] == hex(HEAP_BASE + 0x220)
    assert found["matches"][0]["encoding"] == "ascii"


def test_scan_strings_finds_a_wide_string(dynamic):
    _write_string(dynamic, HEAP_BASE + 0x240, "Licence expired for user", wide=True)
    found = dynamic.scan_strings(DEMO_PID, "licence expired", encoding="utf16")
    assert found["count"] == 1
    assert found["matches"][0]["text"] == "Licence expired for user"
    assert found["matches"][0]["encoding"] == "utf16"


def test_scan_strings_both_covers_both_encodings(dynamic):
    _write_string(dynamic, HEAP_BASE + 0x220, "alpha-marker")
    _write_string(dynamic, HEAP_BASE + 0x260, "beta-marker", wide=True)
    found = dynamic.scan_strings(DEMO_PID, "marker", encoding="both")
    assert [row["encoding"] for row in found["matches"]] == ["ascii", "utf16"]


def test_scan_strings_without_a_needle_returns_everything(dynamic):
    found = dynamic.scan_strings(DEMO_PID, min_length=6, encoding="ascii", limit=50)
    texts = {row["text"] for row in found["matches"]}
    # The demo heap holds PLAYER01 and the arena holds the npc names.
    assert "PLAYER01" in texts
    assert "charlie" in texts


def test_scan_strings_reports_the_module_it_lives_in(dynamic):
    # Plant a marker inside the module image so the result has to say where it is.
    _write_string(dynamic, MODULE_BASE + 0x1800, "module-side-marker")
    found = dynamic.scan_strings(DEMO_PID, "module-side-marker", encoding="ascii")
    assert found["count"] == 1
    assert found["matches"][0]["module"] == "demo_target.exe"


def test_scan_strings_can_be_limited_to_a_module(dynamic):
    _write_string(dynamic, HEAP_BASE + 0x220, "heap-only-marker")
    assert dynamic.scan_strings(DEMO_PID, "heap-only-marker",
                                region_filter="demo_target.exe")["count"] == 0
    assert dynamic.scan_strings(DEMO_PID, "heap-only-marker",
                                region_filter="heap")["count"] == 1


def test_scan_strings_respects_the_limit(dynamic):
    for index in range(8):
        _write_string(dynamic, HEAP_BASE + 0x220 + index * 0x10, f"marker-{index:02d}")
    found = dynamic.scan_strings(DEMO_PID, "marker", limit=3, encoding="ascii")
    assert found["count"] == 3


def test_scan_strings_rejects_a_bad_encoding(dynamic):
    with pytest.raises(InvalidArgument):
        dynamic.scan_strings(DEMO_PID, encoding="utf8")


# -- module export -----------------------------------------------------------


def test_save_writes_a_loadable_pe(tmp_path):
    image = load_pe_from_bytes(build_minimal_pe(), base=MODULE_BASE,
                              path="demo_target.exe", mapped=False)
    target = tmp_path / "out" / "dumped.exe"
    result = image.save(str(target))

    assert result["layout"] == "file"
    assert target.exists()
    assert result["size"] == target.stat().st_size
    # The real test: another parser accepts it and finds the same sections.
    reloaded = load_pe_from_bytes(target.read_bytes(), base=MODULE_BASE,
                                 path=str(target), mapped=False)
    assert [s.name for s in reloaded.sections] == [s.name for s in image.sections]
    assert reloaded.entry_rva == image.entry_rva


def test_save_creates_missing_directories(tmp_path):
    image = load_pe_from_bytes(build_minimal_pe(), base=MODULE_BASE, mapped=False)
    target = tmp_path / "a" / "b" / "c" / "x.exe"
    image.save(str(target))
    assert target.exists()


def test_raw_save_keeps_the_mapped_layout(tmp_path):
    image = load_pe_from_bytes(build_minimal_pe(), base=MODULE_BASE, mapped=False)
    raw_target = tmp_path / "raw.bin"
    result = image.save(str(raw_target), raw=True)
    assert result["layout"] == "rva"
    assert raw_target.read_bytes() == bytes(image.image)


def test_file_image_preserves_section_bytes():
    image = load_pe_from_bytes(build_minimal_pe(), base=MODULE_BASE, mapped=False)
    demapped = image.file_image()
    # A mapped image has RVA>=0x1000 for the first section; the file layout puts
    # those bytes at the raw offset instead, and that is exactly what makes the
    # difference between "opens in IDA" and "not a valid PE".
    assert demapped[:2] == b"MZ"
    assert demapped != bytes(image.image)


def test_static_engine_save_image_round_trip(tmp_path):
    engine = StaticEngine()
    engine.load_capture("live", map_pe_file(build_minimal_pe()), MODULE_BASE,
                        path="demo_target.exe")
    target = tmp_path / "captured.exe"
    result = engine.save_image("live", str(target))
    assert result["base"] == hex(MODULE_BASE)
    reloaded = engine.load_file(str(target), key="reloaded")
    assert reloaded.base == MODULE_BASE
    # Same code discovery on the round-tripped copy.
    assert [f["va"] for f in engine.functions("reloaded")] == \
           [f["va"] for f in engine.functions("live")]


def test_save_image_requires_a_loaded_key(tmp_path):
    engine = StaticEngine()
    with pytest.raises(Exception):
        engine.save_image("nope", str(tmp_path / "x.exe"))
