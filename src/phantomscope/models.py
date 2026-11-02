"""Typed results returned by backends, the static analyser and the dynamic engine.

Every model serialises with :meth:`Model.to_dict`, which drops ``None`` values
so MCP responses stay compact.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any


class Model:
    """Mixin providing recursive ``to_dict`` for dataclasses."""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for f in fields(self):  # type: ignore[arg-type]
            value = getattr(self, f.name)
            if value is None:
                continue
            if isinstance(value, Model):
                value = value.to_dict()
            elif isinstance(value, (list, tuple)):
                value = [v.to_dict() if isinstance(v, Model) else v for v in value]
                if not value:
                    continue
            elif isinstance(value, dict) and not value:
                continue
            out[f.name] = value
        return out


@dataclass
class ProcessInfo(Model):
    pid: int
    name: str
    ppid: int | None = None
    path: str | None = None
    cmdline: str | None = None
    eprocess: int | None = None
    wow64: bool = False
    session: int | None = None
    integrity: str | None = None
    state: str | None = None
    dtb: int | None = None


@dataclass
class ModuleInfo(Model):
    name: str
    base: int
    size: int = 0
    entry: int | None = None
    path: str | None = None
    file_size: int | None = None
    wow64: bool = False
    pid: int | None = None

    @property
    def end(self) -> int:
        return self.base + self.size

    def contains(self, va: int) -> bool:
        return self.base <= va < self.end


@dataclass
class Region(Model):
    base: int
    size: int
    protection: str = "---"
    tag: str | None = None
    module: str | None = None
    kind: str | None = None

    @property
    def end(self) -> int:
        return self.base + self.size

    def contains(self, va: int) -> bool:
        return self.base <= va < self.end


@dataclass
class ThreadInfo(Model):
    tid: int
    pid: int
    state: str | None = None
    priority: int | None = None
    teb: int | None = None
    start: int | None = None
    stack_base: int | None = None
    stack_limit: int | None = None
    ethread: int | None = None


@dataclass
class StackFrame(Model):
    va: int
    module: str | None = None
    function: str | None = None
    offset: int | None = None
    symbol: str | None = None
    role: str | None = None


@dataclass
class ScanHit(Model):
    va: int
    module: str | None = None
    region_base: int | None = None
    region_size: int | None = None
    preview: str | None = None


@dataclass
class PatchRecord(Model):
    id: int
    pid: int
    va: int
    size: int
    original: str
    current: str
    note: str | None = None
    created: float | None = None
    restored: bool = False


@dataclass
class SnapshotRecord(Model):
    id: int
    pid: int
    base: int
    size: int
    created: float | None = None


@dataclass
class SectionInfo(Model):
    name: str
    va: int
    vsize: int
    raw_offset: int | None = None
    raw_size: int | None = None
    executable: bool = False
    writable: bool = False
    readable: bool = True
    entropy: float | None = None


@dataclass
class ImportInfo(Model):
    module: str
    name: str | None = None
    ordinal: int | None = None
    iat_va: int | None = None


@dataclass
class ExportInfo(Model):
    name: str | None = None
    ordinal: int | None = None
    va: int | None = None
    forwarder: str | None = None


@dataclass
class SessionInfo(Model):
    name: str
    kind: str
    device: str | None = None
    processes: int | None = None
    bits: int | None = None
    capabilities: dict[str, bool] = field(default_factory=dict)


@dataclass
class Instruction(Model):
    va: int
    bytes: str
    mnemonic: str
    operands: str
    text: str
    size: int
    kind: str | None = None  # call / jump / cond_jump / ret / plain
    target: int | None = None
    ref: int | None = None
    comment: str | None = None


@dataclass
class FunctionInfo(Model):
    va: int
    end: int | None = None
    size: int | None = None
    name: str | None = None
    source: str | None = None  # entry / export / call_target / prologue
    blocks: int | None = None
    callers: int | None = None


@dataclass
class Xref(Model):
    from_va: int
    to_va: int
    kind: str
    text: str | None = None
    function: int | None = None


@dataclass
class BasicBlock(Model):
    start: int
    end: int
    instructions: int
    successors: list[int] = field(default_factory=list)
