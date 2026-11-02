"""Control-flow indexing: functions, basic blocks, xrefs.

The index is built once per image and cached.  Construction is bounded by
``max_instructions`` so it stays responsive on large modules.

Pipeline
--------
1. seeds: entry point, exports, TLS callbacks, x64 ``.pdata`` function table;
2. recursive descent from every seed, following direct calls and branches;
3. a linear sweep recovers code the descent could not reach (jump tables,
   virtualised dispatchers);
4. prologue heuristics add function starts that are only called indirectly;
5. xrefs are collected from direct branches and memory operands;
6. pointer-sized values in data sections that point into the image become
   data xrefs, which is how you find vtables and dispatch tables.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET

from ..models import BasicBlock, FunctionInfo, Instruction, Xref
from .disasm import Disassembler
from .pe import PEImage

DEFAULT_MAX_INSTRUCTIONS = 1_500_000

PROLOGUES_X64 = (
    b"\x48\x89\x5c\x24", b"\x48\x89\x6c\x24", b"\x48\x89\x74\x24",
    b"\x48\x89\x7c\x24", b"\x4c\x89\x44\x24", b"\x4c\x89\x4c\x24",
    b"\x48\x83\xec", b"\x48\x81\xec", b"\x40\x53", b"\x40\x55",
    b"\x40\x56", b"\x40\x57", b"\x48\x8d\x64\x24",
)
PROLOGUES_X86 = (
    b"\x55\x8b\xec", b"\x55\x89\xe5", b"\x53\x56", b"\x56\x57",
    b"\x83\xec", b"\x81\xec", b"\x8b\xff\x55\x8b\xec",
)


@dataclass
class CodeIndex:
    image: PEImage
    disassembler: Disassembler
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS

    insns: dict[int, Instruction] = field(default_factory=dict)
    function_starts: set[int] = field(default_factory=set)
    function_sources: dict[int, str] = field(default_factory=dict)
    function_ranges: dict[int, tuple[int, int]] = field(default_factory=dict)
    refs_to: dict[int, list[Xref]] = field(default_factory=lambda: {})
    refs_from: dict[int, list[Xref]] = field(default_factory=lambda: {})
    ptr_refs_to: dict[int, list[int]] = field(default_factory=lambda: {})
    blocks: dict[int, list[BasicBlock]] = field(default_factory=dict)
    strings_ref_cache: dict[int, list[int]] = field(default_factory=lambda: {})
    truncated: bool = False
    built: bool = False

    # -- construction ------------------------------------------------------
    def build(self) -> "CodeIndex":
        if self.built:
            return self
        self.built = True
        seeds: dict[int, str] = {}

        if self.image.contains(self.image.entry):
            seeds[self.image.entry] = "entry"
        for export in self.image.exports:
            if export.va and self.image.is_executable_va(export.va):
                seeds[export.va] = "export"
        for callback in self.image.tls_callbacks():
            if self.image.is_executable_va(callback):
                seeds[callback] = "tls"
        for begin, end in self._pdata_ranges():
            seeds.setdefault(begin, "pdata")
            self.function_ranges[begin] = (begin, end)

        queue = sorted(seeds)
        while queue and len(self.insns) < self.max_instructions:
            seed = queue.pop(0)
            if seed in self.insns or not self.image.is_executable_va(seed):
                continue
            self.function_starts.add(seed)
            self.function_sources.setdefault(seed, seeds.get(seed, "call"))
            new_calls = self._walk(seed)
            queue.extend(target for target in new_calls if target not in self.insns)

        self._linear_sweep()
        self._add_prologue_candidates()
        self._collect_xrefs()
        self._collect_pointer_refs()
        self._finalise_ranges()
        return self

    def _pdata_ranges(self) -> list[tuple[int, int]]:
        if not self.image.is_64:
            return []
        directory = self.image.pe.OPTIONAL_HEADER.DATA_DIRECTORY
        try:
            entry = directory[3]  # IMAGE_DIRECTORY_ENTRY_EXCEPTION
        except (IndexError, AttributeError):
            return []
        rva, size = int(entry.VirtualAddress), int(entry.Size)
        if not rva or not size:
            return []
        data = self.image.read_rva(rva, size)
        out: list[tuple[int, int]] = []
        for offset in range(0, len(data) - 11, 12):
            begin, end, _unwind = struct.unpack_from("<III", data, offset)
            if begin and end and end > begin:
                out.append((self.image.base + begin, self.image.base + end))
        return out

    def _walk(self, seed: int) -> list[int]:
        """Recursive descent from one seed.

        Returns the *call* targets discovered on the way; branch targets are
        followed internally so an intra-function ``jmp`` never becomes a new
        function start.
        """
        calls: list[int] = []
        pending = [seed]
        section = self.image.section_for_va(seed)
        section_end = section.va + max(section.vsize, 0x1000) if section else None
        budget = 500_000
        while pending and budget > 0:
            va = pending.pop()
            while budget > 0:
                budget -= 1
                if va in self.insns or not self.image.is_executable_va(va):
                    break
                if section_end is not None and va >= section_end:
                    break
                insn = self.disassembler.one(self.image.read(va, 16), va)
                if insn is None:
                    break
                rendered = self.disassembler.render(insn, self.image)
                self.insns[va] = rendered
                next_va = va + rendered.size
                if rendered.kind == "call":
                    if rendered.target and self.image.is_executable_va(rendered.target):
                        calls.append(rendered.target)
                elif rendered.kind == "ret":
                    break
                elif rendered.kind == "jump":
                    if rendered.target and self.image.is_executable_va(rendered.target):
                        pending.append(rendered.target)
                    break
                elif rendered.kind == "cond_jump":
                    if rendered.target and self.image.is_executable_va(rendered.target):
                        pending.append(rendered.target)
                elif rendered.mnemonic == "int3":
                    break
                va = next_va
        return calls

    def _linear_sweep(self) -> None:
        for start, end in self.image.executable_ranges():
            data = self.image.read(start, end - start)
            if not data:
                continue
            for insn in self.disassembler.iter(data, start):
                if len(self.insns) >= self.max_instructions:
                    self.truncated = True
                    return
                address = int(insn.address)
                if address in self.insns:
                    continue
                self.insns[address] = self.disassembler.render(insn, self.image)

    def _add_prologue_candidates(self) -> None:
        prologues = PROLOGUES_X64 if self.image.is_64 else PROLOGUES_X86
        boundaries = set(self.insns)
        for start, end in self.image.executable_ranges():
            data = self.image.read(start, end - start)
            for prologue in prologues:
                offset = data.find(prologue)
                while offset != -1:
                    candidate = start + offset
                    if candidate in boundaries and candidate not in self.function_starts:
                        # Only trust a prologue preceded by padding or a terminator.
                        prev = candidate - 1
                        if prev < start or data[prev - start] in (0xCC, 0xC3, 0x90):
                            self.function_starts.add(candidate)
                            self.function_sources.setdefault(candidate, "prologue")
                    offset = data.find(prologue, offset + 1)

    def _collect_xrefs(self) -> None:
        for address, insn in self.insns.items():
            if insn.target is not None and insn.kind in ("call", "jump", "cond_jump"):
                self._add_ref(address, insn.target, insn.kind, insn.text)
            if insn.ref is not None and self.image.contains(insn.ref):
                self._add_ref(address, insn.ref, "mem", insn.text)
            if insn.kind == "call" and insn.target is not None and self.image.is_executable_va(insn.target):
                self.function_starts.add(insn.target)
        for start in list(self.function_starts):
            self.function_sources.setdefault(start, "call")

    def _add_ref(self, from_va: int, to_va: int, kind: str, text: str | None = None) -> None:
        xref = Xref(from_va=from_va, to_va=to_va, kind=kind, text=text)
        self.refs_to.setdefault(to_va, []).append(xref)
        self.refs_from.setdefault(from_va, []).append(xref)

    def _collect_pointer_refs(self) -> None:
        width = 8 if self.image.is_64 else 4
        lo, hi = self.image.base, self.image.base + self.image.size
        budget = 400_000
        for section in self.image.sections:
            if section.executable or not section.vsize:
                continue
            data = self.image.read(section.va, section.vsize)
            for offset in range(0, len(data) - width + 1, width):
                value = int.from_bytes(data[offset : offset + width], "little")
                if lo <= value < hi:
                    self.ptr_refs_to.setdefault(value, []).append(section.va + offset)
                    budget -= 1
                    if budget <= 0:
                        return

    def _finalise_ranges(self) -> None:
        starts = sorted(self.function_starts)
        for index, start in enumerate(starts):
            if start in self.function_ranges:
                continue
            section = self.image.section_for_va(start)
            section_end = (
                min(section.va + max(section.vsize, 0x1000), self.image.base + self.image.size)
                if section
                else self.image.base + self.image.size
            )
            end = starts[index + 1] if index + 1 < len(starts) else section_end
            end = max(end, start + 1)
            self.function_ranges[start] = (start, min(end, section_end))

    # -- queries -----------------------------------------------------------
    def function_start(self, va: int) -> int | None:
        if va in self.function_starts:
            return va
        best: int | None = None
        for start, (begin, end) in self.function_ranges.items():
            if begin <= va < end:
                if best is None or begin > best:
                    best = begin
        return best

    def function(self, va: int) -> FunctionInfo | None:
        start = self.function_start(va)
        if start is None:
            return None
        begin, end = self.function_ranges.get(start, (start, start))
        return FunctionInfo(
            va=start,
            end=end,
            size=end - begin,
            name=self._name_for(start),
            source=self.function_sources.get(start),
            callers=len(self.refs_to.get(start, [])),
        )

    def _name_for(self, va: int) -> str | None:
        for export in self.image.exports:
            if export.va == va and export.name:
                return export.name
        return None

    def functions(self, *, limit: int = 20000, offset: int = 0, name_filter: str | None = None) -> list[FunctionInfo]:
        out: list[FunctionInfo] = []
        needle = name_filter.lower() if name_filter else None
        for start in sorted(self.function_starts):
            name = self._name_for(start)
            if needle and (not name or needle not in name.lower()):
                continue
            begin, end = self.function_ranges.get(start, (start, start))
            out.append(
                FunctionInfo(
                    va=start,
                    end=end,
                    size=end - begin,
                    name=name,
                    source=self.function_sources.get(start),
                    blocks=len(self.blocks_for(start)),
                    callers=len(self.refs_to.get(start, [])),
                )
            )
        return out[offset : offset + limit]

    def disassemble_function(self, va: int, *, limit: int = 8000) -> list[Instruction]:
        start = self.function_start(va)
        if start is None:
            return []
        begin, end = self.function_ranges.get(start, (start, start + 0x1000))
        return self.disassembler.disassemble_function(
            self.image, begin, max_bytes=max(0x40, min(end - begin + 16, 0x20000)), limit=limit
        )

    def blocks_for(self, va: int) -> list[BasicBlock]:
        start = self.function_start(va)
        if start is None:
            return []
        if start not in self.blocks:
            self.blocks[start] = self.disassembler.basic_blocks(self.disassemble_function(start))
        return self.blocks[start]

    def xrefs_to(self, va: int, *, limit: int = 200, include_pointers: bool = True,
                 include_data: bool = True) -> list[Xref]:
        hits = []
        for xref in self.refs_to.get(va, []):
            if not include_data and xref.kind == "mem":
                continue
            hits.append(xref)
        if include_pointers:
            for from_va in self.ptr_refs_to.get(va, []):
                hits.append(Xref(from_va=from_va, to_va=va, kind="pointer"))
        for xref in hits:
            xref.function = self.function_start(xref.from_va)
        return hits[:limit]

    def xrefs_from(self, va: int, *, limit: int = 400) -> list[Xref]:
        start = self.function_start(va) or va
        begin, end = self.function_ranges.get(start, (start, start))
        out: list[Xref] = []
        for address in sorted(self.refs_from):
            if begin <= address < max(end, begin + 1):
                out.extend(self.refs_from[address])
                if len(out) >= limit:
                    break
        return out[:limit]

    def callers(self, va: int) -> list[int]:
        start = self.function_start(va) or va
        return sorted({
            self.function_start(xref.from_va) or xref.from_va
            for xref in self.refs_to.get(start, [])
            if xref.kind == "call"
        })

    def callees(self, va: int) -> list[int]:
        start = self.function_start(va) or va
        begin, end = self.function_ranges.get(start, (start, start))
        out: set[int] = set()
        for address in range(begin, max(end, begin + 1)):
            for xref in self.refs_from.get(address, []):
                if xref.kind == "call":
                    out.add(xref.to_va)
        return sorted(out)

    def call_graph(self, *, limit: int = 4000) -> dict[int, list[int]]:
        graph: dict[int, list[int]] = {}
        for address, insn in self.insns.items():
            if insn.kind != "call" or insn.target is None:
                continue
            caller = self.function_start(address)
            if caller is None:
                continue
            graph.setdefault(caller, []).append(insn.target)
            if len(graph) >= limit:
                break
        return graph

    def string_xrefs(self, va: int) -> list[int]:
        if va in self.string_ref_cache:
            return self.string_ref_cache[va]
        out: list[int] = []
        for xref in self.refs_to.get(va, []):
            out.append(xref.from_va)
        out.extend(self.ptr_refs_to.get(va, []))
        out = sorted(set(out))
        self.string_ref_cache[va] = out
        return out


class IndexCache:
    """Lazily built :class:`CodeIndex` per image."""

    def __init__(self, disassembler_factory=Disassembler.for_image,
                 max_instructions: int = DEFAULT_MAX_INSTRUCTIONS) -> None:
        self._disassembler_factory = disassembler_factory
        self._max = max_instructions
        self._cache: dict[int, CodeIndex] = {}

    def get(self, image: PEImage) -> CodeIndex:
        key = (id(image), image.base)
        index = self._cache.get(key)
        if index is None:
            index = CodeIndex(
                image=image,
                disassembler=self._disassembler_factory(image),
                max_instructions=self._max,
            )
            self._cache[key] = index
        return index.build()

    def clear(self) -> None:
        self._cache.clear()
