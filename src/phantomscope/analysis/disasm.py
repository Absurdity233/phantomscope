"""Capstone wrapper with a normalised instruction model.

x86/x64 is the primary target (DMA against Windows).  ARM support is limited to
decoding; the higher-level analysis in :mod:`phantomscope.analysis.index` is
x86/x64 only and reports :class:`~phantomscope.errors.Unavailable` otherwise.
"""

from __future__ import annotations

from capstone import (
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
    CS_OPT_SYNTAX_INTEL,
    Cs,
)
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from ..errors import Unavailable
from ..models import BasicBlock, Instruction, Xref
from .pe import PEImage

CALL_MNEMONICS = {"call", "bl", "blx", "blr"}
RET_MNEMONICS = {"ret", "retn", "bx", "pop"}
JMP_MNEMONICS = {"jmp", "b", "br"}
COND_JUMP_PREFIXES = ("j", "loop", "b.", "cbz", "cbnz", "tbz", "tbnz")


class Disassembler:
    """Cached Capstone wrapper for one architecture."""

    def __init__(self, bits: int = 64, arch: str = "x64", syntax: str = "intel") -> None:
        self.bits = bits
        self.arch = arch
        self.x86 = arch in ("x86", "x64")
        if self.x86:
            cs = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
            if syntax == "intel":
                cs.syntax = CS_OPT_SYNTAX_INTEL
        elif arch.startswith("arm64"):
            cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        elif arch.startswith("arm"):
            cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        else:
            raise Unavailable(f"unsupported architecture for disassembly: {arch}")
        cs.detail = True
        self.cs = cs

    @classmethod
    def for_image(cls, image: PEImage, syntax: str = "intel") -> "Disassembler":
        return cls(bits=image.bits, arch=image.arch, syntax=syntax)

    # -- primitives --------------------------------------------------------
    def decode(self, code: bytes, va: int, count: int = 1) -> list:
        return list(self.cs.disasm(bytes(code), va, count=count))

    def iter(self, code: bytes, va: int):
        yield from self.cs.disasm(bytes(code), va)

    def one(self, code: bytes, va: int):
        return next(iter(self.cs.disasm(bytes(code), va, count=1)), None)

    # -- classification ----------------------------------------------------
    def classify(self, insn) -> tuple[str, int | None]:
        mnemonic = insn.mnemonic.lower()
        target = self._direct_target(insn)
        if mnemonic in CALL_MNEMONICS or mnemonic.startswith("call"):
            return "call", target
        if mnemonic in RET_MNEMONICS:
            return "ret", None
        if mnemonic in JMP_MNEMONICS:
            return "jump", target
        if any(mnemonic.startswith(prefix) for prefix in COND_JUMP_PREFIXES):
            return "cond_jump", target
        return "plain", target

    @staticmethod
    def _direct_target(insn) -> int | None:
        try:
            operands = insn.operands
        except Exception:
            return None
        for operand in operands:
            try:
                if operand.type == X86_OP_IMM and operand.imm:
                    return int(operand.imm)
            except Exception:
                continue
        return None

    def mem_ref(self, insn) -> int | None:
        """Absolute address of a memory operand (RIP-relative or x86 absolute)."""
        if not self.x86:
            return None
        try:
            operands = insn.operands
        except Exception:
            return None
        for operand in operands:
            try:
                if operand.type != X86_OP_MEM:
                    continue
                mem = operand.mem
                if mem.base == X86_REG_RIP:
                    return int(insn.address) + int(insn.size) + int(mem.disp)
                if mem.base == 0 and mem.index == 0 and mem.disp:
                    return int(mem.disp)
            except Exception:
                continue
        return None

    # -- rendering ---------------------------------------------------------
    def render(self, insn, image: PEImage | None = None) -> Instruction:
        mnemonic = insn.mnemonic.lower()
        operands = insn.op_str or ""
        kind, target = self.classify(insn)
        ref = self.mem_ref(insn)
        comment = None
        if image is not None:
            if ref is not None:
                label = self._label(ref, image)
                if label:
                    comment = label
            if target is not None and target != 0:
                label = self._label(target, image)
                if label and (not comment or comment != label):
                    comment = f"{comment}; {label}" if comment else label
        return Instruction(
            va=int(insn.address),
            bytes=bytes(insn.bytes).hex(" "),
            mnemonic=mnemonic,
            operands=operands,
            text=f"{mnemonic} {operands}".strip(),
            size=int(insn.size),
            kind=kind,
            target=target,
            ref=ref,
            comment=comment,
        )

    @staticmethod
    def _label(value: int, image: PEImage) -> str | None:
        import_name = image.resolve_import_name(value)
        if import_name:
            return import_name
        for export in image.exports:
            if export.va == value and export.name:
                return export.name
        if image.contains(value):
            section = image.section_for_va(value)
            if section is not None:
                return f"{section.name}+{value - section.va:#x}"
        return None

    # -- ranges ------------------------------------------------------------
    def disassemble(self, code: bytes, va: int, image: PEImage | None = None,
                    *, limit: int = 20000) -> list[Instruction]:
        out: list[Instruction] = []
        for insn in self.iter(code, va):
            out.append(self.render(insn, image))
            if len(out) >= limit:
                break
        return out

    def disassemble_range(self, image: PEImage, start: int, size: int, *, limit: int = 20000) -> list[Instruction]:
        if not image.contains(start) or size <= 0:
            return []
        return self.disassemble(image.read(start, size), start, image, limit=limit)

    def disassemble_function(self, image: PEImage, start: int, *, max_bytes: int = 0x10000,
                             limit: int = 8000) -> list[Instruction]:
        """Recursive-descent disassembly following direct branches."""
        available = max(0, image.base + image.size - start)
        code = image.read(start, min(max_bytes, available))
        if not code:
            return []
        end_limit = start + len(code)
        visited: dict[int, Instruction] = {}
        queue = [start]
        while queue and len(visited) < limit:
            va = queue.pop()
            while start <= va < end_limit and va not in visited and len(visited) < limit:
                insn = self.one(image.read(va, 16), va)
                if insn is None:
                    break
                rendered = self.render(insn, image)
                visited[va] = rendered
                next_va = va + rendered.size
                if rendered.kind == "ret":
                    break
                if rendered.kind == "jump":
                    if rendered.target is not None and start <= rendered.target < end_limit:
                        queue.append(rendered.target)
                    break
                if rendered.kind == "cond_jump":
                    if rendered.target is not None and start <= rendered.target < end_limit:
                        queue.append(rendered.target)
                    va = next_va
                    continue
                va = next_va
        return [visited[key] for key in sorted(visited)]

    # -- control flow ------------------------------------------------------
    def basic_blocks(self, instructions: list[Instruction]) -> list[BasicBlock]:
        if not instructions:
            return []
        by_va = {insn.va: insn for insn in instructions}
        leaders = {instructions[0].va}
        for insn in instructions:
            next_va = insn.va + insn.size
            if insn.kind in ("jump", "cond_jump", "ret"):
                if next_va in by_va:
                    leaders.add(next_va)
            if insn.kind in ("jump", "cond_jump") and insn.target in by_va:
                leaders.add(insn.target)
        starts = sorted(leaders)
        blocks: list[BasicBlock] = []
        for index, start in enumerate(starts):
            boundary = starts[index + 1] if index + 1 < len(starts) else None
            body = [va for va in sorted(by_va) if va >= start and (boundary is None or va < boundary)]
            if not body:
                continue
            last = by_va[body[-1]]
            successors: list[int] = []
            if last.kind == "cond_jump":
                successors.append(last.va + last.size)
                if last.target is not None:
                    successors.append(last.target)
            elif last.kind == "jump":
                if last.target is not None:
                    successors.append(last.target)
            elif last.kind != "ret":
                successors.append(last.va + last.size)
            blocks.append(
                BasicBlock(
                    start=start,
                    end=last.va + last.size,
                    instructions=len(body),
                    successors=[s for s in successors if s in by_va],
                )
            )
        return blocks

    def xrefs(self, instructions: list[Instruction]) -> list[Xref]:
        out: list[Xref] = []
        for insn in instructions:
            if insn.target is not None and insn.kind in ("call", "jump", "cond_jump"):
                out.append(Xref(from_va=insn.va, to_va=insn.target, kind=insn.kind, text=insn.text))
            if insn.ref is not None:
                out.append(Xref(from_va=insn.va, to_va=insn.ref, kind="data", text=insn.text))
        return out
