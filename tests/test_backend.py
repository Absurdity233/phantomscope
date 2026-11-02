"""Backend contract tests, run against the mock backend."""

from __future__ import annotations

import pytest

from phantomscope.backends.demo import DEMO_PID, HEAP_BASE, MODULE_BASE
from phantomscope.backends.factory import create_backend
from phantomscope.errors import BackendError, InvalidArgument, NotFound


def test_factory_mock_is_populated():
    backend = create_backend("mock", name="x")
    backend.open()
    assert backend.kind == "mock"
    assert backend.find_process("demo_target").pid == DEMO_PID


def test_factory_rejects_unknown_kind():
    with pytest.raises(InvalidArgument):
        create_backend("quantum")


def test_find_process_by_pid_and_name(backend):
    assert backend.find_process(DEMO_PID).name == "demo_target.exe"
    assert backend.find_process("DEMO_TARGET.EXE").pid == DEMO_PID
    assert backend.find_process("does-not-exist") is None


def test_short_read_is_zero_padded(backend):
    data = backend.read(DEMO_PID, 0x10, 8)
    assert data == b"\x00" * 8


def test_cross_region_read(backend):
    data = backend.read(DEMO_PID, HEAP_BASE - 4, 0x200)
    assert len(data) == 0x200


def test_write_outside_mapping_raises(backend):
    with pytest.raises(BackendError):
        backend.write(DEMO_PID, 0x1, b"\x90")


def test_module_for_va(backend):
    module = backend.module_for_va(DEMO_PID, MODULE_BASE + 0x100)
    assert module is not None
    assert module.name == "demo_target.exe"
    assert backend.module_for_va(DEMO_PID, 0x10) is None


def test_symbol_resolution(backend):
    address = backend.resolve_symbol(DEMO_PID, "demo_target.exe", "update_health")
    assert address == MODULE_BASE + 0x1015


def test_physical_read(backend):
    data = backend.read_physical(0x1000, 4)
    assert data[:2] == b"MZ"


def test_capabilities_advertised(backend):
    caps = backend.caps.to_dict()
    assert caps["processes"] and caps["write"] and caps["symbols"]


def test_closed_backend_rejects_operations():
    backend = create_backend("mock")
    with pytest.raises(Exception):
        backend.list_modules(DEMO_PID)
