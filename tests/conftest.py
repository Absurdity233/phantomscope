"""Shared fixtures: the synthetic demo image, a demo backend and a static engine."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from phantomscope.analysis.engine import ImageEntry, StaticEngine  # noqa: E402
from phantomscope.analysis.pe import load_pe_from_bytes  # noqa: E402
from phantomscope.backends.demo import (  # noqa: E402
    DEMO_PID,
    HEAP_BASE,
    MODULE_BASE,
    build_minimal_pe,
    map_pe_file,
    populate_demo_backend,
)
from phantomscope.backends.mock import MockBackend  # noqa: E402
from phantomscope.dynamic.engine import DynamicEngine  # noqa: E402


@pytest.fixture(scope="session")
def demo_pe_bytes() -> bytes:
    return build_minimal_pe()


@pytest.fixture()
def demo_image(demo_pe_bytes):
    return load_pe_from_bytes(
        demo_pe_bytes, base=MODULE_BASE, path="demo_target.exe", mapped=False
    )


@pytest.fixture()
def static_engine(demo_pe_bytes) -> StaticEngine:
    engine = StaticEngine()
    image = load_pe_from_bytes(
        demo_pe_bytes, base=MODULE_BASE, path="demo_target.exe", mapped=False
    )
    engine.images["demo"] = ImageEntry(key="demo", image=image, source="file")
    return engine


@pytest.fixture()
def backend() -> MockBackend:
    instance = MockBackend(name="test")
    populate_demo_backend(instance)
    instance.open()
    return instance


@pytest.fixture()
def dynamic(backend) -> DynamicEngine:
    return DynamicEngine(backend)


@pytest.fixture()
def demo_values():
    return {
        "pid": DEMO_PID,
        "module_base": MODULE_BASE,
        "heap_base": HEAP_BASE,
        "health": HEAP_BASE + 0x120,
        "ammo": HEAP_BASE + 0x124,
        "score": HEAP_BASE + 0x128,
        "mapped_module": map_pe_file(build_minimal_pe()),
    }
