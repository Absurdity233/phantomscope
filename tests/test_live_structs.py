"""Live structure recovery: objects, arrays, layout inference, containers."""

from __future__ import annotations

import pytest

from phantomscope.backends.demo import (
    ARENA_BASE,
    ARENA_COUNT,
    ARENA_STRIDE,
    DEMO_PID,
    HEAP_BASE,
    MODULE_BASE,
    NPC_NAMES,
    PLAYER_HEALTH_OFFSET,
    PLAYER_SCORE_OFFSET,
    POINTER_ARRAY_OFFSET,
    VECTOR_HEADER_OFFSET,
)
from phantomscope.errors import InvalidArgument


def test_read_object_reports_pointers_and_ascii(dynamic):
    obj = dynamic.read_object(DEMO_PID, HEAP_BASE, 0x140)
    assert obj["va"] == hex(HEAP_BASE)
    assert obj["size"] == 0x140
    assert "0000" in obj["hexdump"]
    # The name field sits three dwords in, so the leading `ascii` banner cannot
    # show it; the string runs can.
    assert "PLAYER01" in [entry["text"] for entry in obj["strings"]]
    qword = next(q for q in obj["qwords"] if q["offset"] == "0x100")
    assert qword["pointer_ok"] is True
    assert qword["points_to"] == hex(MODULE_BASE + 0x1000)
    assert qword["target_module"] == "demo_target.exe"


def test_read_object_decodes_explicit_fields(dynamic):
    obj = dynamic.read_object(
        DEMO_PID, HEAP_BASE + PLAYER_HEALTH_OFFSET, 0x20,
        fields="0x0:int32,0x4:int32,0x10:char[8]",
    )
    values = {field["offset"]: field["value"] for field in obj["fields"]}
    assert values["0x0"] == 100
    assert values["0x4"] == 30
    assert values["0x10"] == "PLAYER01"


def test_read_object_marks_a_field_beyond_the_object(dynamic):
    obj = dynamic.read_object(DEMO_PID, HEAP_BASE, 0x10, fields="0x1000:int32")
    assert obj["fields"][0]["error"] == "beyond the object"


def test_read_object_rejects_an_unknown_field_type(dynamic):
    # A typo in the layout must be loud: silently reading the wrong width is worse.
    with pytest.raises(InvalidArgument):
        dynamic.read_object(DEMO_PID, HEAP_BASE, 0x10, fields="0x0:nonsense")


def test_read_array_walks_a_stride(dynamic):
    rows = dynamic.read_array(
        DEMO_PID, ARENA_BASE, ARENA_STRIDE, ARENA_COUNT,
        fields="0x0:int32,0x4:int32,0x8:char[8]",
    )
    assert rows["count"] == ARENA_COUNT
    assert rows["returned"] == ARENA_COUNT
    firsts = [(row["fields"][0]["value"], row["fields"][2]["value"]) for row in rows["objects"]]
    assert firsts == [(index + 1, NPC_NAMES[index].decode()) for index in range(ARENA_COUNT)]


def test_read_array_follows_pointers(dynamic):
    rows = dynamic.read_array(
        DEMO_PID, HEAP_BASE + POINTER_ARRAY_OFFSET, 8, ARENA_COUNT, follow=True,
        object_size=ARENA_STRIDE, fields="0x0:int32",
    )
    assert [row["target"] for row in rows["objects"]] == [
        hex(ARENA_BASE + index * ARENA_STRIDE) for index in range(ARENA_COUNT)
    ]
    assert [row["fields"][0]["value"] for row in rows["objects"]] == [1, 2, 3, 4]


def test_read_array_reports_a_bad_pointer_instead_of_raising(dynamic):
    dynamic.write(DEMO_PID, HEAP_BASE + POINTER_ARRAY_OFFSET, data="00" * 8)
    rows = dynamic.read_array(DEMO_PID, HEAP_BASE + POINTER_ARRAY_OFFSET, 8, 1, follow=True)
    assert rows["objects"][0]["error"] == "pointer is null or not mapped"


def test_read_array_respects_the_limit(dynamic):
    rows = dynamic.read_array(DEMO_PID, ARENA_BASE, ARENA_STRIDE, ARENA_COUNT, limit=2)
    assert rows["returned"] == 2
    assert rows["requested"] == ARENA_COUNT
    assert rows["truncated"] is True


def test_read_array_rejects_a_zero_stride(dynamic):
    with pytest.raises(InvalidArgument):
        dynamic.read_array(DEMO_PID, ARENA_BASE, 0, 4)


def test_infer_struct_finds_the_pointer_and_the_zeros(dynamic):
    inferred = dynamic.infer_struct(DEMO_PID, ARENA_BASE, ARENA_STRIDE,
                                   stride=ARENA_STRIDE, count=ARENA_COUNT)
    by_offset = {field["offset"]: field for field in inferred["fields"]}
    # +0x18 is a pointer in every sample and does not vary.
    assert by_offset["0x18"]["type"] == "pointer"
    assert by_offset["0x18"]["varies"] is False
    # +0x10 is the tail of the name field: zero in every record.
    assert by_offset["0x10"]["varies"] is False
    # The id/health qword differs between records.
    assert by_offset["0x0"]["varies"] is True
    assert inferred["samples"] == ARENA_COUNT


def test_infer_struct_aligns_to_four_when_asked(dynamic):
    inferred = dynamic.infer_struct(DEMO_PID, ARENA_BASE, ARENA_STRIDE, stride=ARENA_STRIDE,
                                    count=ARENA_COUNT, align=4)
    offsets = [field["offset"] for field in inferred["fields"]]
    assert "0x4" in offsets
    assert "0x8" in offsets
    assert "int32_t field_4" in inferred["c_struct"]


def test_infer_struct_reports_strings(dynamic):
    inferred = dynamic.infer_struct(DEMO_PID, ARENA_BASE, ARENA_STRIDE, stride=ARENA_STRIDE,
                                    count=ARENA_COUNT, align=4)
    text = {entry["offset"]: entry["text"] for entry in inferred["strings"]}
    assert text["0x8"] == "alpha"
    assert set(inferred["strings"][0]["values"]) == {"alpha", "bravo", "charlie", "delta"}
    # The declaration sizes the field to the longest value plus its terminator.
    assert "char text_8[8];" in inferred["c_struct"]


def test_detect_container_identifies_a_vector(dynamic):
    detected = dynamic.detect_container(DEMO_PID, HEAP_BASE + VECTOR_HEADER_OFFSET)
    kinds = [candidate["kind"] for candidate in detected["candidates"]]
    assert kinds[0] == "std::vector<T>"
    primary = detected["primary"]
    assert primary["data_va"] == hex(ARENA_BASE)
    # The pointer rhythm in the arena gives the true element size, not a guess.
    assert primary["element_size"] == ARENA_STRIDE
    assert primary["element_size_source"] == "pointer_rhythm"
    assert primary["element_size_guessed"] is False
    assert primary["count"] == ARENA_COUNT
    # A pointer in the count slot must not be mistaken for an Unreal TArray.
    assert not any("TArray" in kind for kind in kinds)


def test_detect_container_honours_an_explicit_element_size(dynamic):
    detected = dynamic.detect_container(
        DEMO_PID, HEAP_BASE + VECTOR_HEADER_OFFSET, element_size=8
    )
    primary = detected["primary"]
    assert primary["element_size"] == 8
    assert primary["count"] == ARENA_COUNT * 4


def test_detect_container_rejects_a_size_that_cannot_fit(dynamic):
    with pytest.raises(InvalidArgument):
        dynamic.detect_container(DEMO_PID, HEAP_BASE + VECTOR_HEADER_OFFSET, element_size=7)


def test_detect_container_on_a_plain_object_says_so(dynamic):
    detected = dynamic.detect_container(DEMO_PID, HEAP_BASE + PLAYER_HEALTH_OFFSET)
    assert detected["candidates"] == [] or "note" in detected


def test_expand_container_returns_the_elements(dynamic):
    expanded = dynamic.expand_container(DEMO_PID, HEAP_BASE + VECTOR_HEADER_OFFSET,
                                        fields="0x0:int32,0x8:char[8]")
    assert expanded["element_count"] == ARENA_COUNT
    assert [row["fields"][0]["value"] for row in expanded["elements"]] == [1, 2, 3, 4]
    assert expanded["element_size"] == ARENA_STRIDE


def test_expand_container_reports_an_empty_container(dynamic):
    # A vector whose begin == end == capacity is empty, not broken.
    empty_at = HEAP_BASE + 0x300
    dynamic.write(DEMO_PID, empty_at,
                  data=(ARENA_BASE).to_bytes(8, "little").hex()
                  + (ARENA_BASE).to_bytes(8, "little").hex()
                  + (ARENA_BASE).to_bytes(8, "little").hex())
    expanded = dynamic.expand_container(DEMO_PID, empty_at)
    assert expanded["elements"] == []
    assert "empty" in expanded["note"]


def test_detect_container_identifies_a_std_string(dynamic):
    # MSVC std::string: 16-byte inline buffer, then size, then capacity.
    at = HEAP_BASE + 0x280
    dynamic.write(DEMO_PID, at,
                  data=b"hello-vector-sso".hex() + (0x10).to_bytes(8, "little").hex()
                  + (0x10).to_bytes(8, "little").hex())
    detected = dynamic.detect_container(DEMO_PID, at)
    kinds = [candidate["kind"] for candidate in detected["candidates"]]
    assert any("std::string" in kind for kind in kinds), detected
    string = next(c for c in detected["candidates"] if "std::string" in c["kind"])
    assert string["value"] == "hello-vector-sso"


def test_detect_container_falls_back_to_a_named_bare_container(dynamic):
    # {ptr, count, capacity} with no ordering evidence is still worth naming.
    at = HEAP_BASE + 0x2C0
    dynamic.write(DEMO_PID, at,
                  data=(ARENA_BASE).to_bytes(8, "little").hex()
                  + (0x400).to_bytes(8, "little").hex()
                  + (0x800).to_bytes(8, "little").hex())
    detected = dynamic.detect_container(DEMO_PID, at)
    assert detected["candidates"], detected
    assert detected["candidates"][0]["confidence"] in ("weak", "plausible", "strong")


def test_module_snapshot_and_diff(dynamic, demo_values):
    baseline = dynamic.snapshot_module(DEMO_PID, "demo_target.exe", label="before")
    assert baseline["regions"]
    assert baseline["base"] == hex(MODULE_BASE)

    dynamic.write(DEMO_PID, MODULE_BASE + 0x1010, data="90909090")
    diff = dynamic.diff_module(DEMO_PID, "demo_target.exe")
    assert diff["snapshot_id"] == baseline["id"]
    assert diff["changed_bytes"] == 4
    assert diff["changes"][0]["va"] == hex(MODULE_BASE + 0x1010)
    assert diff["changes"][0]["new"] == "90909090"


def test_diff_module_requires_a_baseline(dynamic):
    with pytest.raises(Exception):
        dynamic.diff_module(DEMO_PID, "demo_target.exe")


def test_score_field_is_where_the_demo_put_it(dynamic):
    # Sanity anchor: the numbers the demo wrote are the numbers read back.
    assert dynamic.read_typed(DEMO_PID, HEAP_BASE + PLAYER_SCORE_OFFSET, "int32")["value"] == 1337
