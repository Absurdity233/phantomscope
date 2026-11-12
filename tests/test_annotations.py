"""Annotations: names/comments that stick and persist in a sidecar."""

from __future__ import annotations

import json

import pytest

from phantomscope.analysis.annotations import AnnotationStore, SIDECAR_SUFFIX
from phantomscope.analysis.pe import load_pe_from_file, load_pe_from_bytes
from phantomscope.backends.demo import MODULE_BASE, build_flow_demo_pe


@pytest.fixture()
def pe_file(tmp_path):
    target = tmp_path / "flow.dll"
    target.write_bytes(build_flow_demo_pe())
    return target


def test_rename_and_comment_round_trip(pe_file):
    image = load_pe_from_file(str(pe_file))
    store = AnnotationStore.for_image(image)
    store.rename(MODULE_BASE + 0x1000, "sum_loop")
    store.comment(MODULE_BASE + 0x1000, "counts down ecx")
    store.note("entry calls sum_loop twice", MODULE_BASE + 0x1040)
    store.apply_to(image)

    assert image.user_name(MODULE_BASE + 0x1000) == "sum_loop"
    assert image.label(MODULE_BASE + 0x1000) == "sum_loop"
    assert image.user_comments[MODULE_BASE + 0x1000] == "counts down ecx"

    assert store.save() is True
    sidecar = pe_file.with_name(pe_file.name + SIDECAR_SUFFIX)
    assert sidecar.is_file()
    payload = json.loads(sidecar.read_text(encoding="utf-8"))
    assert payload["functions"][hex(MODULE_BASE + 0x1000)] == "sum_loop"


def test_a_second_load_reads_the_sidecar_back(pe_file):
    image = load_pe_from_file(str(pe_file))
    store = AnnotationStore.for_image(image)
    store.rename(MODULE_BASE + 0x1020, "pick")
    store.save()

    reloaded = load_pe_from_file(str(pe_file))
    again = AnnotationStore.for_image(reloaded)
    assert again.name_for(MODULE_BASE + 0x1020) == "pick"


def test_invalid_names_are_rejected(pe_file):
    image = load_pe_from_file(str(pe_file))
    store = AnnotationStore.for_image(image)
    for bad in ("", "has space", "0leading-digit", "x" * 300):
        with pytest.raises(ValueError):
            store.rename(MODULE_BASE + 0x1000, bad)


def test_clear_removes_one_address_or_everything(pe_file):
    image = load_pe_from_file(str(pe_file))
    store = AnnotationStore.for_image(image)
    store.rename(MODULE_BASE + 0x1000, "a")
    store.rename(MODULE_BASE + 0x1020, "b")
    store.comment(MODULE_BASE + 0x1000, "note")
    assert store.clear(MODULE_BASE + 0x1000) == 2
    assert store.name_for(MODULE_BASE + 0x1020) == "b"
    assert store.clear() == 1
    assert store.to_dict()["counts"] == {"functions": 0, "comments": 0, "notes": 0}


def test_a_mapped_image_gets_no_sidecar():
    image = load_pe_from_bytes(build_flow_demo_pe(), base=MODULE_BASE, path="game.exe",
                               mapped=True)
    store = AnnotationStore.for_image(image)
    assert store.sidecar is None
    store.rename(MODULE_BASE + 0x1000, "in_memory_only")
    assert store.save() is False


def test_a_corrupt_sidecar_does_not_break_loading(pe_file):
    sidecar = pe_file.with_name(pe_file.name + SIDECAR_SUFFIX)
    sidecar.write_text("{ this is not json", encoding="utf-8")
    store = AnnotationStore.for_image(load_pe_from_file(str(pe_file)))
    assert store.functions == {}


def test_serialization_hexes_addresses(pe_file):
    image = load_pe_from_file(str(pe_file))
    store = AnnotationStore.for_image(image)
    store.rename(MODULE_BASE + 0x1000, "sum_loop")
    payload = store.to_dict()
    assert payload["functions"] == {hex(MODULE_BASE + 0x1000): "sum_loop"}
    assert payload["counts"]["functions"] == 1
