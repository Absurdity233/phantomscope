"""Emulator import stubs: run code that calls the OS without faulting.

A snapshot holds the image, not ``kernel32``.  Stubbing the IAT is what makes
``emu_call`` usable on real code, so the behaviour worth pinning is: the call
returns, the return value is the one requested, and the arguments are logged.
"""

from __future__ import annotations

import pytest

from phantomscope.analysis.pe import load_pe_from_bytes
from phantomscope.backends.demo import MODULE_BASE, build_api_demo_pe

pytest.importorskip("unicorn", reason="snapshot emulation needs unicorn")

from phantomscope.dynamic.emulator import emulator_for  # noqa: E402


@pytest.fixture()
def image():
    return load_pe_from_bytes(build_api_demo_pe(), base=MODULE_BASE, path="api", mapped=False)


def test_stubs_cover_every_import_slot(image):
    emu = emulator_for(image)
    installed = emu.install_import_stubs()
    assert installed["installed"] == 2
    apis = [stub["api"] for stub in emu.stubs()]
    assert apis == ["KERNEL32.dll!Sleep", "KERNEL32.dll!GetTickCount"]


def test_call_through_imports_returns_instead_of_faulting(image):
    emu = emulator_for(image, auto_stubs=True)
    result = emu.call(MODULE_BASE + 0x1000, [], max_steps=5000)
    assert result["reason"] == "returned"
    assert result["retval"] == "0x0"


def test_import_calls_are_logged_with_arguments(image):
    emu = emulator_for(image, auto_stubs=True)
    emu.call(MODULE_BASE + 0x1000, [], max_steps=5000)
    calls = emu.import_calls()
    assert [call["api"] for call in calls] == ["KERNEL32.dll!Sleep", "KERNEL32.dll!GetTickCount"]
    assert calls[0]["args"][0] == "0xa"  # Sleep(10)
    assert calls[1]["args"][0] == hex(MODULE_BASE + 0x10A0)  # the string literal


def test_return_values_are_steerable(image):
    """Driving a return value is how a check gets taken down the success path."""
    emu = emulator_for(image)
    emu.install_import_stubs(returns={"Sleep": 0x1, "KERNEL32.dll!GetTickCount": 0x99})
    result = emu.call(MODULE_BASE + 0x1000, [], max_steps=5000)
    assert result["retval"] == "0x99"
    values = {stub["api"]: stub["returns"] for stub in emu.stubs()}
    assert values["KERNEL32.dll!Sleep"] == "0x1"


def test_default_return_applies_to_unlisted_imports(image):
    emu = emulator_for(image)
    emu.install_import_stubs(default=7)
    emu.call(MODULE_BASE + 0x1000, [], max_steps=5000)
    assert {stub["returns"] for stub in emu.stubs()} == {"0x7"}


def test_an_image_without_imports_reports_it():
    from phantomscope.backends.demo import build_minimal_pe

    plain = load_pe_from_bytes(build_minimal_pe(), base=MODULE_BASE, path="plain", mapped=False)
    result = emulator_for(plain).install_import_stubs()
    assert result["installed"] == 0
    assert "no import table" in result["reason"]
