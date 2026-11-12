"""Import resolution: which APIs a stripped function actually calls.

Over DMA the import table is often the only naming anchor left, so these tests
pin the two things that were easy to get wrong: the IAT slot address a call goes
through (``pefile`` reports imports as VAs, exports as RVAs) and the
``mov reg,[iat]; call reg`` thunk form.
"""

from __future__ import annotations

import pytest

from phantomscope.analysis import apis
from phantomscope.analysis.index import IndexCache
from phantomscope.analysis.pe import load_pe_from_bytes
from phantomscope.backends.demo import MODULE_BASE, build_api_demo_pe


@pytest.fixture()
def api_index():
    image = load_pe_from_bytes(build_api_demo_pe(), base=MODULE_BASE, path="api", mapped=False)
    return IndexCache().get(image)


def test_import_slots_are_resolved(api_index):
    image = api_index.image
    slots = {imp.name: imp.iat_va for imp in image.imports}
    assert slots["Sleep"] == MODULE_BASE + 0x1030
    assert slots["GetTickCount"] == MODULE_BASE + 0x1038
    assert image.resolve_import_name(MODULE_BASE + 0x1030) == "KERNEL32.dll!Sleep"


def test_api_sites_carry_address_function_and_kind(api_index):
    sites = [site.to_dict() for site in apis.api_sites(api_index)]
    assert [site["name"] for site in sites] == ["Sleep", "GetTickCount"]
    assert sites[0]["kind"] == "call"
    assert sites[0]["function"] == hex(MODULE_BASE + 0x1000)
    assert sites[0]["slot"] == hex(MODULE_BASE + 0x1030)


def test_api_calls_filter_by_function(api_index):
    all_calls = apis.api_calls(api_index)
    assert {call.name for call in all_calls} == {"Sleep", "GetTickCount"}
    # Filtering by any address inside the function gives the same answer.
    inside = apis.api_calls(api_index, MODULE_BASE + 0x1010)
    assert {call.name for call in inside} == {"Sleep", "GetTickCount"}


def test_api_summary_groups_by_api(api_index):
    summary = apis.api_summary(api_index)
    assert len(summary) == 2
    entry = next(row for row in summary if row["name"] == "Sleep")
    assert entry["count"] == 1
    assert entry["functions"] == [hex(MODULE_BASE + 0x1000)]


def test_find_api_is_case_insensitive(api_index):
    found = apis.find_api(api_index, "sleep")
    assert len(found) == 1
    assert found[0]["apis"] == ["KERNEL32.dll!Sleep"]
    assert apis.find_api(api_index, "CreateFile") == []


def test_unresolved_indirect_counts_calls_through_registers(api_index):
    assert apis.unresolved_indirect(api_index) == 0
