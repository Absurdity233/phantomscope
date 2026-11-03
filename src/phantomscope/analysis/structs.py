"""Structure layout inference from memory operands.

Reverse engineering a target usually starts with "what does this pointer point
to?"  Over DMA you cannot attach a debugger and click a field, so the practical
route is to read what the code *does* with the pointer: every ``[rcx+0x10]`` is
a field access, and the width of the access is the field's type size.

This module collects those accesses per base register and turns them into a
candidate layout.  It is deliberately honest about its limits:

* it reports what the code touches, not what the struct contains — untouched
  fields are invisible;
* offsets are relative and the base is a *role* (``arg0``, ``arg1``, ...) or a
  register name, because nothing here proves which object the register holds;
* overlapping accesses are reported rather than merged, so a union or a
  misidentified base stays visible.

The output is a hypothesis to confirm with ``read_typed`` against live memory,
which is why every field carries the instruction addresses that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from capstone.x86 import X86_OP_MEM, X86_OP_REG

from ..models import Instruction, Model
from .index import CodeIndex

try:  # capstone 5 exposes the register enum as X86_REG_*
    from capstone.x86 import (
        X86_REG_R8, X86_REG_R9, X86_REG_RCX, X86_REG_RDX, X86_REG_RSP,
    )
except Exception:  # pragma: no cover - older capstone
    X86_REG_RCX = X86_REG_RDX = X86_REG_R8 = X86_REG_R9 = X86_REG_RSP = -1

#: x64 register used for the n-th integer argument (Microsoft calling convention).
ARG_ROLES = {
    "rcx": "arg0", "ecx": "arg0", "cx": "arg0", "cl": "arg0",
    "rdx": "arg1", "edx": "arg1", "dx": "arg1", "dl": "arg1",
    "r8": "arg2", "r8d": "arg2", "r8w": "arg2", "r8b": "arg2",
    "r9": "arg3", "r9d": "arg3", "r9w": "arg3", "r9b": "arg3",
}

STACK_ROLES = {"rsp", "esp", "sp", "rbp", "ebp", "bp"}

#: Instructions whose destination operand is *not* written.
READ_ONLY_MNEMONICS = {
    "cmp", "test", "push", "call", "jmp", "je", "jne", "jz", "jnz", "ja", "jb",
    "jg", "jl", "jge", "jle", "jae", "jbe", "js", "jns", "jo", "jno", "jp", "jnp",
}


@dataclass
class FieldAccess(Model):
    """One observed access to a field."""

    offset: int
    size: int
    access: str            # "read" / "write"
    va: int                # instruction that performed it
    mnemonic: str
    text: str
    scale: int = 0         # non-zero for ``[base + index*scale + disp]``

    def to_dict(self) -> dict:
        out = super().to_dict()
        out["offset"] = hex(self.offset)
        out["va"] = hex(self.va)
        return out


@dataclass
class CandidateField(Model):
    """A field hypothesis: one offset, merged over every access to it."""

    offset: int
    size: int
    reads: int = 0
    writes: int = 0
    array_stride: int = 0
    accesses: list[FieldAccess] = field(default_factory=list)

    def to_dict(self) -> dict:
        out = super().to_dict()
        out["offset"] = hex(self.offset)
        out["accesses"] = [a.to_dict() for a in self.accesses]
        return out


@dataclass
class StructLayout(Model):
    """Candidate layout for one base register (and therefore one object)."""

    role: str
    register: str
    function: int
    fields: list[CandidateField] = field(default_factory=list)
    overlaps: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def span(self) -> int:
        """Total extent covered by the observed fields."""
        if not self.fields:
            return 0
        lowest = min(f.offset for f in self.fields)
        highest = max(f.offset + max(f.size, 1) for f in self.fields)
        return highest - lowest

    @property
    def min_offset(self) -> int:
        return min((f.offset for f in self.fields), default=0)

    def to_dict(self) -> dict:
        out = {k: v for k, v in super().to_dict().items() if k != "fields"}
        out["function"] = hex(self.function)
        out["span"] = hex(self.span)
        out["min_offset"] = hex(self.min_offset)
        out["fields"] = [f.to_dict() for f in self.fields]
        return out


@dataclass
class GlobalRef(Model):
    """A RIP-relative or absolute memory reference outside the struct bases."""

    va: int
    target: int
    size: int
    access: str
    mnemonic: str
    text: str

    def to_dict(self) -> dict:
        out = super().to_dict()
        out["va"] = hex(self.va)
        out["target"] = hex(self.target)
        return out


def _decode(index: CodeIndex, va: int):
    """Disassemble one instruction with full operand detail."""
    image = index.image
    data = image.read(va, 16)
    if not data:
        return None
    return index.disassembler.one(data, va)


def _reg_name(insn, reg_id: int) -> str:
    try:
        return (insn.reg_name(reg_id) or "").lower()
    except Exception:
        return ""


def _mem_operand(insn):
    """Return the first x86 memory operand of a capstone instruction."""
    try:
        for position, operand in enumerate(insn.operands):
            if operand.type == X86_OP_MEM:
                return position, operand
    except Exception:
        return None, None
    return None, None


def _is_write(insn, position: int) -> bool:
    """Is the memory operand at ``position`` written by this instruction?"""
    mnemonic = insn.mnemonic.lower()
    if mnemonic in READ_ONLY_MNEMONICS:
        return False
    return position == 0


def infer_layout(index: CodeIndex, function_va: int, *, limit: int = 8000) -> list[StructLayout]:
    """Infer candidate struct layouts touched by one function."""
    instructions = index.disassemble_function(function_va, limit=limit)
    layouts: dict[str, StructLayout] = {}
    by_field: dict[tuple[str, int], CandidateField] = {}

    for instruction in instructions:
        try:
            decoded = _decode(index, instruction.va)
        except Exception:
            continue
        if decoded is None:
            continue
        position, operand = _mem_operand(decoded)
        if operand is None:
            continue
        mem = operand.mem
        if mem.base == 0:
            continue  # absolute reference, not a struct access
        base_name = _reg_name(decoded, mem.base)
        if not base_name or base_name in ("rip", "eip"):
            continue  # module global: see globals_touched()
        if base_name in STACK_ROLES:
            continue  # stack frame, not a heap/object layout

        role = ARG_ROLES.get(base_name.lower(), f"reg:{base_name.lower()}")
        scale = int(mem.scale or 0) if mem.index else 0

        layout = layouts.get(role)
        if layout is None:
            layout = StructLayout(role=role, register=base_name.lower(), function=function_va)
            layouts[role] = layout

        size = int(operand.size or 0) or 1
        access = "write" if _is_write(decoded, position) else "read"
        entry = FieldAccess(
            offset=int(mem.disp),
            size=size,
            access=access,
            va=instruction.va,
            mnemonic=decoded.mnemonic,
            text=instruction.text,
            scale=scale,
        )

        key = (role, int(mem.disp))
        candidate = by_field.get(key)
        if candidate is None:
            candidate = CandidateField(offset=int(mem.disp), size=size)
            by_field[key] = candidate
            layout.fields.append(candidate)
        if access == "write":
            candidate.writes += 1
        else:
            candidate.reads += 1
        if scale and not candidate.array_stride:
            candidate.array_stride = scale * max(size, 1)
        candidate.size = max(candidate.size, size)
        candidate.accesses.append(entry)

    for layout in layouts.values():
        layout.fields.sort(key=lambda f: f.offset)
        layout.overlaps = _detect_overlaps(layout)
        if layout.role.startswith("reg:"):
            layout.notes.append(
                f"{layout.register} is not an argument register; confirm what it holds "
                "before trusting these offsets"
            )
        if layout.min_offset < 0:
            layout.notes.append(
                f"fields start at {layout.min_offset:#x} (below the base); the register may "
                "point into the middle of an object, or be a save-area pointer rather than "
                "an object base"
            )
        if layout.span > 0x400:
            layout.notes.append(
                f"span {layout.span:#x} is large for one object; the base may be an "
                "array pointer"
            )
    return [layouts[role] for role in sorted(layouts)]


def _detect_overlaps(layout: StructLayout) -> list[str]:
    """Report fields that overlap without being identical.

    A wide access covering narrower ones is normal (a 8-byte read whose halves
    are also read individually); two *equal-width* fields sharing bytes is not,
    and usually means a union or that two different objects were merged into
    one role.
    """
    spans = sorted(
        ((f.offset, f.offset + max(f.size, 1), f) for f in layout.fields),
        key=lambda item: item[0],
    )
    out: list[str] = []
    for (start_a, end_a, field_a), (start_b, end_b, field_b) in zip(spans, spans[1:]):
        if end_a <= start_b:
            continue
        if field_a.offset == field_b.offset:
            continue  # same offset, merged into one candidate already
        if end_a >= end_b and field_a.size > field_b.size:
            # The wide field fully contains the narrow one: likely one access
            # read a whole chunk. Worth mentioning, not alarming.
            out.append(
                f"{field_a.size}B access at {start_a:#x} also covers {start_b:#x} "
                "(the wide field may be a copy of several smaller ones)"
            )
        else:
            out.append(
                f"{start_a:#x}({field_a.size}B) overlaps {start_b:#x}({field_b.size}B) "
                "(union, or two different bases collapsed into one role)"
            )
    return out


def globals_touched(index: CodeIndex, function_va: int, *, limit: int = 2000) -> list[GlobalRef]:
    """List RIP-relative / absolute memory references made by a function.

    These are the module's own globals, which is where per-process state
    (health, flags, RNG seeds) usually lives.
    """
    refs: list[GlobalRef] = []
    seen: set[tuple[int, int]] = set()
    for instruction in index.disassemble_function(function_va, limit=limit):
        try:
            decoded = _decode(index, instruction.va)
        except Exception:
            continue
        if decoded is None:
            continue
        position, operand = _mem_operand(decoded)
        if operand is None:
            continue
        mem = operand.mem
        base = _reg_name(decoded, mem.base) if mem.base else ""
        if base in ("rip", "eip"):
            target = int(decoded.address) + int(decoded.size) + int(mem.disp)
        elif not base and not mem.index:
            target = int(mem.disp)  # absolute (x86) reference
        else:
            continue  # register-relative: handled by infer_layout
        if target <= 0:
            continue
        key = (instruction.va, target)
        if key in seen:
            continue
        seen.add(key)
        refs.append(
            GlobalRef(
                va=instruction.va,
                target=target,
                size=int(operand.size or 0) or 1,
                access="write" if _is_write(decoded, position) else "read",
                mnemonic=decoded.mnemonic,
                text=instruction.text,
            )
        )
    return refs
