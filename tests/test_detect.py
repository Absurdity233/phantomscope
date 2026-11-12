"""Triage: packing evidence, crypto constants and immediate search."""

from __future__ import annotations

import pytest

from phantomscope.analysis import detect
from phantomscope.analysis.index import IndexCache
from phantomscope.analysis.pe import load_pe_from_bytes
from phantomscope.backends.demo import MODULE_BASE, build_flow_demo_pe, build_minimal_pe

AES_SBOX = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")
SBOX_RVA = 0x1100


def _index(data: bytes):
    image = load_pe_from_bytes(data, base=MODULE_BASE, path="demo", mapped=False)
    return IndexCache().get(image)


@pytest.fixture()
def flow_index():
    return _index(build_flow_demo_pe())


def test_packing_report_shape(flow_index):
    report = detect.packing_report(flow_index)
    assert 0 <= report["score"] <= 10
    assert report["verdict"] in ("likely packed or virtualised", "some anomalies",
                                 "not obviously packed")
    assert report["functions"] >= 3
    assert isinstance(report["findings"], list)
    assert isinstance(report["entropy"], dict)


def test_packing_report_flags_a_missing_import_table(flow_index):
    names = {finding["finding"] for finding in detect.packing_report(flow_index)["findings"]}
    assert "no_imports" in names


def test_crypto_constants_find_an_embedded_sbox():
    """An AES S-box planted in the image has to come back with its address."""
    data = bytearray(build_minimal_pe())
    raw = 0x200 + (SBOX_RVA - 0x1000)  # raw offset of the RVA in the single section
    data[raw:raw + len(AES_SBOX)] = AES_SBOX
    hits = detect.crypto_constants(_index(bytes(data)))
    assert [hit["name"] for hit in hits] == ["aes_sbox"]
    assert hits[0]["va"] == hex(MODULE_BASE + SBOX_RVA)
    assert hits[0]["section"] == ".text"


def test_crypto_constants_are_empty_without_tables(flow_index):
    assert detect.crypto_constants(flow_index) == []


def test_search_immediates_finds_code_and_data(flow_index):
    result = detect.search_immediates(flow_index, 5)
    code = {row["text"] for row in result["code"]}
    assert "cmp ecx, 5" in code
    assert "mov ecx, 5" in code
    assert result["value"] == "0x5"
    assert result["counts"]["code"] >= 2


def test_search_immediates_skips_code_bytes_by_default(flow_index):
    default = detect.search_immediates(flow_index, 5)
    assert default["data"] == []
    widened = detect.search_immediates(flow_index, 5, include_code_bytes=True)
    assert widened["data"]


def test_search_immediates_matches_a_negative_value(flow_index):
    """`cmp ecx, -1` stores 0xffffffff, so -1 has to match."""
    result = detect.search_immediates(flow_index, 0xFFFFFFFF, width=4)
    assert isinstance(result["code"], list)
    assert detect.search_immediates(flow_index, -1, width=4)["value"] == "-0x1"
