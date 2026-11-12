"""Fingerprints, similarity matching and build diffing."""

from __future__ import annotations

import pytest

from phantomscope.analysis import fingerprint as fp
from phantomscope.analysis.index import IndexCache
from phantomscope.analysis.pe import load_pe_from_bytes
from phantomscope.backends.demo import MODULE_BASE, build_flow_demo_pe


def _index():
    image = load_pe_from_bytes(build_flow_demo_pe(), base=MODULE_BASE, path="flow", mapped=False)
    return IndexCache().get(image)


@pytest.fixture()
def flow_index():
    return _index()


def test_fingerprint_shape(flow_index):
    row = fp.fingerprint(flow_index, MODULE_BASE + 0x1000)
    assert row.function == MODULE_BASE + 0x1000
    assert row.instructions > 0
    assert row.blocks == 3
    assert row.hash and row.mnemonic_hash
    data = row.to_dict()
    assert data["function"] == hex(MODULE_BASE + 0x1000)
    assert all(value.startswith("0x") for value in data["constants"])


def test_same_function_hashes_the_same_at_a_new_base(flow_index):
    """Normalisation has to survive a different load address."""
    rebased = load_pe_from_bytes(build_flow_demo_pe(), base=0x140000000, path="flow2",
                                 mapped=False)
    other = IndexCache().get(rebased)
    left = fp.fingerprint(flow_index, MODULE_BASE + 0x1000)
    right = fp.fingerprint(other, 0x140000000 + 0x1000)
    assert left.hash == right.hash


def test_different_functions_differ(flow_index):
    loop = fp.fingerprint(flow_index, MODULE_BASE + 0x1000)
    branch = fp.fingerprint(flow_index, MODULE_BASE + 0x1020)
    assert loop.hash != branch.hash
    assert loop.mnemonic_hash != branch.mnemonic_hash


def test_similarity_is_one_for_identical_and_low_for_strangers(flow_index):
    loop = fp.fingerprint(flow_index, MODULE_BASE + 0x1000)
    same = fp.fingerprint(flow_index, MODULE_BASE + 0x1000)
    branch = fp.fingerprint(flow_index, MODULE_BASE + 0x1020)
    loop_tokens = fp._tokens(flow_index, loop.function)[0]
    branch_tokens = fp._tokens(flow_index, branch.function)[0]
    assert fp.similarity(loop, same, loop_tokens, loop_tokens) == 1.0
    assert fp.similarity(loop, branch, loop_tokens, branch_tokens) < 0.5


def test_diff_of_an_image_against_itself_is_all_identical(flow_index):
    result = fp.diff_images(flow_index, _index())
    counts = result["counts"]
    assert counts["identical"] >= 3
    assert counts["removed"] == 0
    assert counts["added"] == 0
    assert counts["similar"] == 0


def test_match_images_reports_identical_functions(flow_index):
    rows = fp.match_images(flow_index, _index())
    assert rows
    assert all(row["kind"] == "identical" for row in rows)
    assert all(row["similarity"] == 1.0 for row in rows)


def test_find_similar_excludes_itself(flow_index):
    rows = fp.find_similar(flow_index, MODULE_BASE + 0x1000, min_similarity=0.0, limit=10)
    assert all(row["function"] != hex(MODULE_BASE + 0x1000) for row in rows)
