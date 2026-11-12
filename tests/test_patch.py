"""Static byte patching: apply, list, roll back, and survive a save/reload."""

from __future__ import annotations

import pytest

from phantomscope.analysis.engine import StaticEngine
from phantomscope.analysis.pe import load_pe_from_bytes
from phantomscope.backends.demo import MODULE_BASE, build_minimal_pe
from phantomscope.errors import InvalidArgument, NotFound


@pytest.fixture()
def engine(demo_pe_bytes):
    instance = StaticEngine()
    image = load_pe_from_bytes(demo_pe_bytes, base=MODULE_BASE,
                               path="demo_target.exe", mapped=False)
    instance.load_file  # the fixture builds the entry directly to keep it small
    from phantomscope.analysis.engine import ImageEntry

    instance.images["demo"] = ImageEntry(key="demo", image=image, source="file")
    return instance


def test_patch_replaces_bytes_and_keeps_the_original(engine):
    target = MODULE_BASE + 0x1010
    before = engine.read("demo", target, 4)["hex"]
    record = engine.apply_patch("demo", target, bytes.fromhex("90909090"), note="nop out")

    assert record["va"] == hex(target)
    assert record["old"] == before
    assert record["new"] == "90909090"
    assert record["note"] == "nop out"
    assert engine.read("demo", target, 4)["hex"] == "90909090"


def test_patch_invalidates_the_cached_index(engine):
    # Disassemble first so the index is warm; the patch must not be invisible.
    original = engine.disassemble("demo", MODULE_BASE + 0x1015, count=2)
    engine.apply_patch("demo", MODULE_BASE + 0x1015, b"\x90\x90")
    patched = engine.disassemble("demo", MODULE_BASE + 0x1015, count=2)

    assert original[0]["text"] != patched[0]["text"]
    assert patched[0]["text"].startswith("nop")


def test_patch_outside_the_image_is_rejected(engine):
    with pytest.raises(InvalidArgument):
        engine.apply_patch("demo", MODULE_BASE + 0x100000, b"\x90")
    with pytest.raises(InvalidArgument):
        engine.apply_patch("demo", MODULE_BASE - 4, b"\x90")


def test_patch_list_accumulates(engine):
    engine.apply_patch("demo", MODULE_BASE + 0x1010, b"\x90")
    engine.apply_patch("demo", MODULE_BASE + 0x1020, b"\x90")
    records = engine.patch_list()
    assert [row["va"] for row in records] == [hex(MODULE_BASE + 0x1010),
                                              hex(MODULE_BASE + 0x1020)]


def test_restore_one_patch(engine):
    record = engine.apply_patch("demo", MODULE_BASE + 0x1010, bytes.fromhex("90909090"))
    result = engine.patch_restore(0)
    assert result == {"restored": 1, "remaining": 0}
    assert engine.read("demo", MODULE_BASE + 0x1010, 4)["hex"] == record["old"]


def test_restore_all_patches(engine):
    a = engine.apply_patch("demo", MODULE_BASE + 0x1010, bytes.fromhex("90909090"))
    b = engine.apply_patch("demo", MODULE_BASE + 0x1020, bytes.fromhex("cccc"))
    result = engine.patch_restore(all=True)

    assert result == {"restored": 2, "remaining": 0}
    assert engine.read("demo", MODULE_BASE + 0x1010, 4)["hex"] == a["old"]
    assert engine.read("demo", MODULE_BASE + 0x1020, 2)["hex"] == b["old"]


def test_restore_without_a_target_is_rejected(engine):
    with pytest.raises(InvalidArgument):
        engine.patch_restore()
    with pytest.raises(NotFound):
        engine.patch_restore(7)


def test_a_patch_survives_save_and_reload(engine, tmp_path):
    target = MODULE_BASE + 0x1010
    engine.apply_patch("demo", target, bytes.fromhex("90909090"))
    saved = engine.save_image("demo", str(tmp_path / "patched.exe"))

    reloaded = engine.load_file(saved["path"], key="reloaded")
    assert reloaded.read(target, 4) == bytes.fromhex("90909090")


def test_restore_after_save_only_affects_memory(engine, tmp_path):
    # The file written earlier is a snapshot; restoring the image does not and
    # should not rewrite it.  Saying so out loud in a test keeps it a decision.
    target = MODULE_BASE + 0x1010
    record = engine.apply_patch("demo", target, bytes.fromhex("90909090"))
    saved = engine.save_image("demo", str(tmp_path / "patched.exe"))
    engine.patch_restore(all=True)

    assert engine.read("demo", target, 4)["hex"] == record["old"]
    written = (tmp_path / "patched.exe").read_bytes()
    assert bytes.fromhex("90909090") in written
