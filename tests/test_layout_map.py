"""Merging a static access pattern with live field inference."""

from __future__ import annotations

import pytest

from phantomscope.analysis.layout_map import merge, vector_groups


def _static(*fields: tuple[int, int, int, int], role: str = "arg0") -> list[dict]:
    """Static layouts: (offset, size, reads, writes)."""
    return [{
        "role": role,
        "register": "rcx",
        "function": "0x1000",
        "overlaps": [],
        "fields": [
            {"offset": hex(offset), "size": size, "reads": reads, "writes": writes,
             "accesses": [{"offset": hex(offset), "size": size,
                           "access": "write" if writes else "read",
                           "va": "0x1004", "mnemonic": "mov", "text": "mov", "scale": 0}]}
            for offset, size, reads, writes in fields
        ],
    }]


def _live(*fields: dict, samples: int = 4, strings: list[dict] | None = None) -> dict:
    return {"samples": samples, "fields": list(fields),
            "strings": strings or [], "va": "0x2000", "c_struct": ""}


def _f(offset: int, kind: str, *, size: int = 4, varies: bool = True,
       alternatives: list[str] | None = None, confidence: str = "likely") -> dict:
    entry = {"offset": hex(offset), "size": size, "type": kind,
             "confidence": confidence, "varies": varies}
    if alternatives:
        entry["alternatives"] = alternatives
    return entry


def test_code_and_data_both_appear_with_full_confidence():
    merged = merge(_static((0x0, 4, 1, 0), (0x4, 4, 0, 1)),
                   _live(_f(0x0, "int32"), _f(0x4, "int32")))[0]

    assert merged["summary"]["fields"] == 2
    assert merged["summary"]["confirmed_both"] == 2
    assert all(field["confirmed_by_code"] for field in merged["fields"])
    assert all(field["confirmed_by_data"] for field in merged["fields"])


def test_padding_is_dropped_not_declared():
    # 0x8 is zero in every sample and the code never touches it: real padding.
    merged = merge(_static((0x0, 4, 1, 0), (0x10, 4, 1, 0)),
                   _live(_f(0x0, "int32"), _f(0x8, "zero", varies=False), _f(0x10, "int32")))[0]
    offsets = [field["offset"] for field in merged["fields"]]
    assert "0x8" not in offsets
    assert offsets == ["0x0", "0x10"]


def test_data_only_fields_are_kept_but_marked():
    # The data shows a pointer at 0x18 that this function never touches.
    merged = merge(_static((0x0, 4, 1, 0)),
                   _live(_f(0x0, "int32"), _f(0x18, "pointer", size=8)))[0]

    pointer = next(field for field in merged["fields"] if field["offset"] == "0x18")
    assert pointer["confirmed_by_code"] is False
    assert pointer["confirmed_by_data"] is True
    assert merged["data_only_offsets"] == ["0x18"]


def test_code_only_offsets_are_reported_not_hidden():
    # The code writes 0x20 but the sampled object shows nothing readable there:
    # either it is written later, or a different object was sampled.
    merged = merge(_static((0x0, 4, 1, 0), (0x20, 4, 0, 1)),
                   _live(_f(0x0, "int32")))[0]

    assert merged["code_only_offsets"] == ["0x20"]
    field = next(item for item in merged["fields"] if item["offset"] == "0x20")
    assert field["confirmed_by_data"] is False
    assert field["confirmed_by_code"] is True
    assert any("nothing readable" in note for note in merged["notes"])


def test_a_confirmed_float_wins_over_the_access_width():
    # `mov eax, [rcx+0x10]` looks like a dword move, but 10.0f is not 1092616192.
    merged = merge(_static((0x10, 4, 1, 0)),
                   _live(_f(0x10, "int32", alternatives=["float 10.0"])))[0]

    field = merged["fields"][0]
    assert field["c_type"] == "float"
    assert field["live_type"] == "float"
    assert field["type_source"].startswith("float alternative")
    assert "float f_10;" in merged["c_struct"]


def test_an_unconfirmed_int32_stays_int32():
    merged = merge(_static((0x10, 4, 1, 0)), _live(_f(0x10, "int32")))[0]
    assert merged["fields"][0]["c_type"] == "int32_t"


def test_inline_strings_become_char_arrays():
    merged = merge(
        _static((0x30, 8, 1, 0)),
        _live(_f(0x30, "int64", size=8),
              strings=[{"offset": "0x30", "length": 7, "text": "hostile",
                        "values": ["hostile", "friendly"]}]),
    )[0]
    field = merged["fields"][0]
    assert field["c_type"] == "char"
    assert field["size"] == 8          # longest value + terminator
    assert field["name"] == "text_30"
    assert "char text_30[8];" in merged["c_struct"]
    assert field["string_values"] == ["hostile", "friendly"]


def test_names_encode_evidence_not_guesses():
    merged = merge(
        _static((0x0, 4, 1, 0), (0x4, 4, 0, 1), (0x8, 4, 1, 1), (0x10, 8, 1, 0)),
        _live(_f(0x0, "int32", varies=False), _f(0x4, "int32", varies=False),
              _f(0x8, "int32", varies=True), _f(0x10, "pointer", size=8)),
    )[0]
    names = {field["offset"]: field["name"] for field in merged["fields"]}
    assert names["0x0"] == "field_0"      # read only, constant, plain int
    assert names["0x4"] == "const_4"      # written, never varies
    assert names["0x8"] == "state_8"      # written and per-instance
    assert names["0x10"] == "ptr_10"


def test_multiple_objects_merge_independently():
    layouts = _static((0x0, 4, 1, 0), role="arg0") + _static((0x8, 8, 1, 0), role="arg1")
    merged = merge(layouts, _live(_f(0x0, "int32"), _f(0x8, "pointer", size=8)))
    assert [item["role"] for item in merged] == ["arg0", "arg1"]
    assert "struct arg0_t" in merged[0]["c_struct"]
    assert "struct arg1_t" in merged[1]["c_struct"]


def test_a_single_sample_is_flagged():
    merged = merge(_static((0x0, 4, 1, 0)), _live(_f(0x0, "int32"), samples=1))[0]
    assert any("one sample" in note for note in merged["notes"])


def test_the_declaration_has_one_member_per_field():
    merged = merge(_static((0x0, 4, 1, 0), (0x10, 8, 1, 0)),
                   _live(_f(0x0, "int32"), _f(0x10, "pointer", size=8)))[0]
    body = [line for line in merged["c_struct"].splitlines() if line.strip().startswith("/*")]
    assert len(body) == 2


# -- vector grouping ---------------------------------------------------------


def test_three_adjacent_floats_become_a_position():
    fields = [
        {"offset": hex(0x10), "c_type": "float"},
        {"offset": hex(0x14), "c_type": "float"},
        {"offset": hex(0x18), "c_type": "float"},
    ]
    groups = vector_groups(fields)
    assert len(groups) == 1
    assert groups[0]["kind"] == "float3"
    assert groups[0]["suggestion"] == "float pos_10[3];"


def test_two_adjacent_floats_group_but_are_not_called_a_position():
    fields = [{"offset": hex(0x28), "c_type": "float"},
              {"offset": hex(0x2c), "c_type": "float"}]
    groups = vector_groups(fields)
    assert groups[0]["kind"] == "float[2]"
    assert groups[0]["suggestion"] == "float vec_28[2];"


def test_a_gap_breaks_the_group():
    fields = [{"offset": hex(0x10), "c_type": "float"},
              {"offset": hex(0x14), "c_type": "float"},
              {"offset": hex(0x20), "c_type": "float"}]
    groups = vector_groups(fields)
    assert len(groups) == 1 and groups[0]["count"] == 2


def test_a_lone_float_is_not_a_vector():
    assert vector_groups([{"offset": hex(0x10), "c_type": "float"}]) == []


def test_non_floats_never_group():
    fields = [{"offset": hex(0x10), "c_type": "int32_t"},
              {"offset": hex(0x14), "c_type": "int32_t"}]
    assert vector_groups(fields) == []
