"""Heuristic pseudo-C recovery for x86/x64 functions.

DMA hands you bytes, not a debugger.  A raw instruction listing is honest but
expensive to read: semantics live in the operand encoding, imports are indirect,
and control flow is a soup of ``jcc``.  This module lifts one function to a
compact pseudo-C form that says the same thing in far fewer tokens:

* **expressions** — ``mov``/``add``/``lea``/... become assignments; RIP-relative
  references become the import they point at, the string literal stored there, or
  ``g_<rva>`` for a module global; struct-like operand forms become
  ``arg0->0x10``;
* **conditions** — a ``cmp``/``test`` plus the following ``jcc`` becomes
  ``if (a < b)`` with the right signedness and the sense inverted when the branch
  skips the body;
* **structure** — dominators, post-dominators and natural loops recover
  ``if``/``else``, ``while`` and single-block loops; whatever cannot be
  structured honestly becomes a label plus ``goto``, never a silent drop;
* **traceability** — every emitted line carries the instruction it came from as
  a trailing comment, and unmodelled instructions are kept verbatim as
  ``__asm__("...")`` so nothing disappears.

It is deliberately *heuristic*: no type inference, no variable coalescing, no
inlining, no symbolic arithmetic.  ``confidence`` and ``notes`` in the result say
what was guessed or truncated, and ``blocks`` explains when a function was too
large to structure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from ..errors import Unavailable
from ..models import Instruction
from .index import CodeIndex
from .structs import ARG_ROLES

#: A 741-block / 6000-instruction function renders in well under a second, so the
#: block cap is only there to refuse the pathological case (a jump-table blob
#: disassembled as one "function") instead of rendering 100k lines of noise.
MAX_BLOCKS = 1200
MAX_INSNS = 6000
MAX_LINES = 8000
#: Nesting deeper than this is a symptom of a linear if/else chain, not structure.
MAX_INDENT = 12
MAX_DEPTH = 40
MAX_STRING = 96

#: Condition suffixes of ``jcc``/``setcc``/``cmovcc`` mapped to comparison ops.
_CONDITIONS = {
    "e": "==", "z": "==", "ne": "!=", "nz": "!=",
    "l": "<", "nge": "<", "le": "<=", "ng": "<=",
    "g": ">", "nle": ">", "ge": ">=", "nl": ">=",
    "b": "<", "c": "<", "nae": "<", "be": "<=", "na": "<=",
    "a": ">", "nbe": ">", "ae": ">=", "nb": ">=", "nc": ">=",
    "s": "<", "ns": ">=", "o": "overflow", "no": "!overflow",
    "p": "parity", "np": "!parity",
}
_INVERSE = {"==": "!=", "!=": "==", "<": ">=", "<=": ">", ">": "<=", ">=": "<",
            "overflow": "!overflow", "!overflow": "overflow",
            "parity": "!parity", "!parity": "parity"}

_ALIASES = {
    "rax": ("rax", "eax", "ax", "al"),
    "rcx": ("rcx", "ecx", "cx", "cl"),
    "rdx": ("rdx", "edx", "dx", "dl"),
    "rbx": ("rbx", "ebx", "bx", "bl"),
    "rsp": ("rsp", "esp", "sp", "spl"),
    "rbp": ("rbp", "ebp", "bp", "bpl"),
    "rsi": ("rsi", "esi", "si", "sil"),
    "rdi": ("rdi", "edi", "di", "dil"),
}
for _index in range(8, 16):
    _ALIASES[f"r{_index}"] = (f"r{_index}", f"r{_index}d", f"r{_index}w", f"r{_index}b")
_CANON = {alias: base for base, aliases in _ALIASES.items() for alias in aliases}
_RAX = {"rax", "eax", "ax", "al"}

_BINARY = {
    "add": "+=", "sub": "-=", "and": "&=", "or": "|=", "xor": "^=",
    "shl": "<<=", "sal": "<<=", "shr": ">>=", "sar": ">>=",
}
_SKIP = {
    "nop", "int3", "hlt", "ud2", "endbr64", "endbr32", "pause", "cld", "std",
    "clc", "stc", "cmc", "push", "pop", "leave", "enter", "fnop", "wait",
}
#: Instructions that only move the stack pointer; they are frame bookkeeping.
_FRAME_REGS = {"rsp", "esp", "sp", "rbp", "ebp", "bp"}
#: `[frame+0x8] = rbx` — a callee-saved register pushed into the frame.
_CALLEE_SAVED_STORE = re.compile(
    r"^\[[^\]]+\]=(rbx|ebx|bl|rbp|ebp|rsi|esi|rdi|edi|r1[2-5]|r1[2-5]d|r1[2-5]w|r1[2-5]b)$"
)


@dataclass
class _Cond:
    """A comparison: ``lhs op rhs`` (``rhs`` may be empty for flag tests)."""

    lhs: str
    op: str = ""
    rhs: str = ""

    def __str__(self) -> str:
        if not self.op:
            return self.lhs
        return f"{self.lhs} {self.op} {self.rhs}" if self.rhs else f"{self.lhs} {self.op}"

    def inverted(self) -> "_Cond":
        if not self.op:
            if self.lhs.startswith("!"):
                return _Cond(self.lhs[1:])
            return _Cond(f"!{self.lhs}")
        op = _INVERSE.get(self.op)
        if op is None:
            return _Cond(f"!({self})")
        return _Cond(self.lhs, op, self.rhs)


@dataclass
class _Block:
    start: int
    end: int
    insns: list[Instruction]
    successors: list[int] = field(default_factory=list)

    @property
    def terminator(self) -> Instruction:
        return self.insns[-1]


class _Function:
    """Disassembly, blocks and capstone decoding for one function."""

    def __init__(self, index: CodeIndex, start: int) -> None:
        self.index = index
        self.image = index.image
        self.start = start
        self.insns: list[Instruction] = index.disassemble_function(start, limit=MAX_INSNS)
        self.by_va: dict[int, Instruction] = {insn.va: insn for insn in self.insns}
        self.blocks: dict[int, _Block] = {}
        self._decoded: dict[int, object] = {}
        for raw in index.blocks_for(start):
            body = [self.by_va[va] for va in sorted(self.by_va) if raw.start <= va < raw.end]
            if not body:
                continue
            successors = [
                target if target in self.by_va else self._containing(target)
                for target in raw.successors
            ]
            self.blocks[raw.start] = _Block(
                start=raw.start, end=raw.end, insns=body,
                successors=[s for s in successors if s is not None],
            )

    def _containing(self, va: int) -> int | None:
        for start, block in self.blocks.items():
            if block.start <= va < block.end:
                return start
        return None

    def decode(self, va: int):
        if va not in self._decoded:
            self._decoded[va] = self.index.disassembler.one(self.image.read(va, 16), va)
        return self._decoded[va]

    def block_after(self, start: int) -> int | None:
        ordered = sorted(self.blocks)
        try:
            position = ordered.index(start)
        except ValueError:
            return None
        return ordered[position + 1] if position + 1 < len(ordered) else None


def _dominators(nodes: list[int], succ: dict[int, list[int]], entry: int) -> dict[int, set[int]]:
    universe = set(nodes)
    dom = {node: set(universe) for node in nodes}
    dom.setdefault(entry, {entry})
    dom[entry] = {entry}
    preds: dict[int, list[int]] = {node: [] for node in nodes}
    for node, targets in succ.items():
        for target in targets:
            preds.setdefault(target, []).append(node)
    for _ in range(len(nodes) + 2):
        changed = False
        for node in nodes:
            if node == entry:
                continue
            incoming = preds.get(node) or []
            if not incoming:
                new = {node}
            else:
                new = set.intersection(*(dom.get(p, {p}) for p in incoming)) | {node}
            if new != dom[node]:
                dom[node] = new
                changed = True
        if not changed:
            break
    return dom


def _postdominators(nodes: list[int], succ: dict[int, list[int]]) -> tuple[dict[int, set[int]], int]:
    exit_node = -1
    universe = set(nodes) | {exit_node}
    pdom = {node: set(universe) for node in nodes}
    pdom[exit_node] = {exit_node}
    for _ in range(len(nodes) + 2):
        changed = False
        for node in reversed(nodes):
            targets = succ.get(node) or [exit_node]
            new = set.intersection(*(pdom.get(t, {t}) for t in targets)) | {node}
            if new != pdom[node]:
                pdom[node] = new
                changed = True
        if not changed:
            break
    return pdom, exit_node


def _nearest(pdom: dict[int, set[int]], node: int) -> int | None:
    """The closest strict post-dominator (``None`` for the virtual exit)."""
    candidates = pdom.get(node, set()) - {node}
    if not candidates:
        return None
    for candidate in candidates:
        if all(other == candidate or other in pdom.get(candidate, set()) for other in candidates):
            return None if candidate == -1 else candidate
    return None


def _natural_loop(header: int, latch: int, preds: dict[int, list[int]]) -> set[int]:
    body = {header}
    stack = [latch]
    while stack:
        node = stack.pop()
        if node in body:
            continue
        body.add(node)
        if node == header:
            continue
        stack.extend(preds.get(node, []))
    return body


class _CFG:
    def __init__(self, fn: _Function) -> None:
        self.starts = sorted(fn.blocks)
        if not self.starts:
            raise Unavailable("no basic blocks recovered for this function")
        self.entry = fn.start if fn.start in fn.blocks else self.starts[0]
        self.succ = {
            start: [t for t in fn.blocks[start].successors if t in fn.blocks]
            for start in self.starts
        }
        self.dom = _dominators(self.starts, self.succ, self.entry)
        self.pdom, self.exit = _postdominators(self.starts, self.succ)
        self.ipdom = {node: _nearest(self.pdom, node) for node in self.starts}
        self.preds: dict[int, list[int]] = {node: [] for node in self.starts}
        for node, targets in self.succ.items():
            for target in targets:
                self.preds[target].append(node)

        self.back_edges: list[tuple[int, int]] = []
        self.loops: dict[int, set[int]] = {}
        for node, targets in self.succ.items():
            for target in targets:
                if target == node or target in self.dom[node]:
                    self.back_edges.append((node, target))
                    self.loops.setdefault(target, set()).update(
                        _natural_loop(target, node, self.preds)
                    )
        self.loop_of: dict[int, int] = {}
        for header, body in self.loops.items():
            for node in body:
                current = self.loop_of.get(node)
                if current is None or len(self.loops[current]) > len(body):
                    self.loop_of[node] = header
        #: Edges that jump backwards without dominating their target: irreducible.
        self.irreducible_edges = [
            (node, target)
            for node, targets in self.succ.items()
            for target in targets
            if target < node and target not in self.dom[node]
        ]

    def exits_of(self, header: int) -> list[int]:
        body = self.loops.get(header, set())
        return sorted({t for node in body for t in self.succ.get(node, []) if t not in body})

    def summary(self) -> dict:
        return {
            "blocks": len(self.starts),
            "edges": sum(len(v) for v in self.succ.values()),
            "loops": [
                {
                    "header": hex(header),
                    "blocks": len(body),
                    "exits": [hex(exit_) for exit_ in self.exits_of(header)],
                }
                for header, body in sorted(self.loops.items())
            ],
            "irreducible": len(self.irreducible_edges),
        }


class _Emitter:
    """Turns the CFG into pseudo-C lines."""

    def __init__(self, fn: _Function, cfg: _CFG, *, include_comments: bool = True) -> None:
        self.fn = fn
        self.cfg = cfg
        self.image = fn.image
        self.include_comments = include_comments
        self.lines: list[str] = []
        self.emitted: set[int] = set()
        self.loops_done: set[int] = set()
        self.goto_targets: set[int] = set()
        self.known_targets: set[int] = set()
        self._cmp: tuple[str, str, str] | None = None
        self._flags: str | None = None
        self._args: dict[str, str] = {}
        self.used_args: set[str] = set()
        self.tail_returns = False
        self._clobbered: set[str] = set()
        self._ret_reg: str | None = None
        self.wrote_rax = False
        self.writes_memory = False
        self.calls: list[str] = []
        self.imports: list[str] = []
        self.strings: list[str] = []
        self.dropped = 0
        self.note: list[str] = []

    # -- entry -------------------------------------------------------------
    def render(self) -> list[str]:
        """Two passes: the first discovers the labels, the second emits them."""
        self._pass(set())
        targets = set(self.goto_targets)
        self.lines = []
        self.emitted = set()
        self.loops_done = set()
        self.goto_targets = set()
        self._pass(targets)
        return self.lines

    def _pass(self, targets: set[int]) -> None:
        self.known_targets = targets
        self._clobbered = set()
        self._ret_reg = None
        self.wrote_rax = False
        self._emit_region(self.cfg.entry, frozenset(), 1, 0)
        remainder = [start for start in self.cfg.starts if start not in self.emitted]
        if remainder:
            self.note.append(
                f"{len(remainder)} block(s) are not reachable from the entry and were "
                "emitted separately"
            )
            self.lines.append("    // --- unreachable from the entry ---")
            for start in remainder:
                if start in self.emitted:
                    continue
                self.lines.append(f"L_{start - self.image.base:04X}:")
                block = self.fn.blocks[start]
                self.emitted.add(start)
                self._body(block, 1)
                self._terminator_only(block, 1)

    # -- regions -----------------------------------------------------------
    def _emit_region(self, start: int | None, stop: frozenset[int], depth: int, nest: int) -> None:
        cur = start
        guard = 0
        while cur is not None and cur not in stop:
            guard += 1
            if guard > MAX_LINES or len(self.lines) > MAX_LINES or depth > MAX_DEPTH:
                self.note.append("output budget exhausted; the rest of the function is omitted")
                return
            if cur in self.emitted:
                self._goto(cur, depth)
                return
            block = self.fn.blocks.get(cur)
            if block is None:
                return
            header = self.cfg.loop_of.get(cur)
            if header == cur and cur not in self.loops_done:
                cur = self._loop(block, stop, depth, nest)
                continue
            self.emitted.add(cur)
            self._label(cur, depth)
            self._body(block, depth)
            term = block.terminator
            if term.kind == "ret":
                self.lines.append(self._indent(depth) + self._return_line())
                return
            if term.kind == "jump":
                target = term.target
                if target is None:
                    self._tail_indirect(term, depth)
                    return
                if target in self.fn.blocks:
                    if target in stop:
                        return
                    if target in self.emitted:
                        self._goto(target, depth)
                        return
                    cur = target
                    continue
                # A jump out of the function: an import thunk or a tail call.
                self._tail(term, depth)
                return
            if term.kind == "cond_jump":
                if term.target is not None and term.target not in self.fn.blocks:
                    self._external_branch(block, depth)
                    cur = self.fn.block_after(cur)
                    continue
                cur = self._branch(block, stop, depth, nest)
                continue
            cur = self.fn.block_after(cur)

    def _loop(self, block: _Block, stop: frozenset[int], depth: int, nest: int) -> int | None:
        header = block.start
        body = self.cfg.loops[header]
        exits = self.cfg.exits_of(header)
        self.loops_done.add(header)
        self.emitted.add(header)
        self._label(header, depth)
        term = block.terminator
        inner_stop = frozenset(set(stop) | {header} | set(exits))

        if term.kind == "cond_jump" and term.target in body:
            # Latch and header are the same block: the block *is* the body, and
            # its own flags decide whether the loop repeats.
            self.lines.append(self._indent(depth) + "while (1) {")
            self._body(block, depth + 1)
            cond = self._condition(term)
            if cond is not None:
                self.lines.append(self._indent(depth + 1) + f"if ({cond.inverted()}) break;")
            else:
                self.note.append(
                    f"the latch of the loop at {header - self.image.base:#x} has no "
                    "recoverable condition"
                )
            self.lines.append(self._indent(depth) + "}")
        elif term.kind == "cond_jump":
            # Classic `while (cond) { body }`: the header evaluates and jumps out.
            self._body(block, depth)
            cond = self._condition(term)
            if cond is not None:
                self.lines.append(self._indent(depth) + f"while ({cond.inverted()}) {{")
            else:
                self.lines.append(self._indent(depth) + "while (1) {")
            self._emit_region(term.va + term.size, inner_stop, depth + 1, nest + 1)
            self.lines.append(self._indent(depth) + "}")
        else:
            # An unconditional entry into the body: render `while (1)` and let the
            # latch's branch out become a break.
            self._body(block, depth)
            entry = term.target if term.kind == "jump" and term.target else self.fn.block_after(header)
            self.lines.append(self._indent(depth) + "while (1) {")
            self._emit_region(entry, inner_stop, depth + 1, nest + 1)
            self.lines.append(self._indent(depth) + "}")

        for exit_ in exits:
            if exit_ in self.fn.blocks and exit_ not in self.emitted:
                return exit_
        return None

    def _branch(self, block: _Block, stop: frozenset[int], depth: int, nest: int) -> int | None:
        term = block.terminator
        target = term.target
        fallthrough = term.va + term.size
        fall = fallthrough if fallthrough in self.fn.blocks else self.fn.block_after(block.start)
        cond = self._condition(term)
        if target is None or target not in self.fn.blocks:
            return fall
        if cond is None:
            self._goto(target, depth)
            return fall
        if target in stop:
            header = self.cfg.loop_of.get(block.start)
            if header == target:
                self.lines.append(self._indent(depth) + f"if ({cond.inverted()}) break;")
                return None
            self.lines.append(self._indent(depth) + f"if ({cond}) goto {self._label_name(target)};")
            return fall if fall not in stop else None
        if fall is None:
            self.lines.append(self._indent(depth) + f"if ({cond}) {{")
            self._emit_region(target, frozenset(set(stop) | {target}), depth + 1, nest + 1)
            self.lines.append(self._indent(depth) + "}")
            return None

        join = self.cfg.ipdom.get(block.start)
        if join == block.start:
            self._goto(target, depth)
            return fall
        if join is None:
            # Both arms leave the function (typically two returns): if/else.
            taken = cond if target < fall else cond.inverted()
            first, second = (target, fall) if target < fall else (fall, target)
            self.lines.append(self._indent(depth) + f"if ({taken}) {{")
            self._emit_region(first, stop, depth + 1, nest + 1)
            self.lines.append(self._indent(depth) + "} else {")
            self._emit_region(second, stop, depth + 1, nest + 1)
            self.lines.append(self._indent(depth) + "}")
            return None
        if fall == join:
            self.lines.append(self._indent(depth) + f"if ({cond}) {{")
            self._emit_region(target, frozenset(set(stop) | {join}), depth + 1, nest + 1)
            self.lines.append(self._indent(depth) + "}")
            return join
        if target == join:
            self.lines.append(self._indent(depth) + f"if ({cond.inverted()}) {{")
            self._emit_region(fall, frozenset(set(stop) | {join}), depth + 1, nest + 1)
            self.lines.append(self._indent(depth) + "}")
            return join

        # Two real arms.  Emit in address order so the listing reads downwards.
        if target > fall:
            inner_stop = frozenset(set(stop) | {join})
            self.lines.append(self._indent(depth) + f"if ({cond.inverted()}) {{")
            self._emit_region(fall, inner_stop, depth + 1, nest + 1)
            self.lines.append(self._indent(depth) + "} else {")
            self._emit_region(target, inner_stop, depth + 1, nest + 1)
            self.lines.append(self._indent(depth) + "}")
        else:
            inner_stop = frozenset(set(stop) | {join})
            self.lines.append(self._indent(depth) + f"if ({cond}) {{")
            self._emit_region(target, inner_stop, depth + 1, nest + 1)
            self.lines.append(self._indent(depth) + "} else {")
            self._emit_region(fall, inner_stop, depth + 1, nest + 1)
            self.lines.append(self._indent(depth) + "}")
        return join

    def _tail_indirect(self, term: Instruction, depth: int) -> None:
        """``jmp qword ptr [rip+X]`` / ``jmp rax``: an import thunk or vtable slot."""
        if term.ref is not None:
            import_name = self.image.resolve_import_name(term.ref)
            if import_name:
                self.imports.append(import_name)
                self.tail_returns = True
                self.lines.append(self._indent(depth) + f"return {import_name}();")
                return
            label = self.image.label(term.ref) or f"0x{term.ref:x}"
            self.lines.append(self._indent(depth) + f"goto *({label});")
            return
        decoded = self.fn.decode(term.va)
        if decoded is not None:
            for operand in decoded.operands:
                if operand.type in (X86_OP_REG, X86_OP_MEM):
                    rendered = self._operand(decoded, operand)
                    self.lines.append(self._indent(depth) + f"return (*{rendered})();")
                    return
        self.lines.append(self._indent(depth) + "goto <indirect>;")

    def _tail(self, term: Instruction, depth: int) -> None:
        """Render a jump out of the function: thunk, tail call or plain address."""
        label, callable_ = self._resolve_external(term.target or 0)
        self._record(label, callable_)
        self.lines.append(
            self._indent(depth) + (f"return {label}();" if callable_ else f"goto {label};")
        )

    def _external_branch(self, block: _Block, depth: int) -> None:
        """A conditional branch that leaves the function (typically a tail call)."""
        term = block.terminator
        cond = self._condition(term)
        label, callable_ = self._resolve_external(term.target or 0)
        self._record(label, callable_)
        body = f"return {label}();" if callable_ else f"goto {label};"
        if cond is None:
            self.lines.append(self._indent(depth) + body)
        else:
            self.lines.append(self._indent(depth) + f"if ({cond}) {{ {body} }}")

    def _resolve_external(self, target: int) -> tuple[str, bool]:
        import_name = self.image.resolve_import_name(target)
        if import_name:
            return import_name, True
        if self.image.contains(target) and self.image.is_executable_va(target):
            return self._function_name(target), True
        if self.image.contains(target):
            return f"g_{target - self.image.base:04X}", False
        return f"0x{target:x}", False

    def _record(self, label: str, callable_: bool) -> None:
        if not callable_:
            return
        self.tail_returns = True
        if "!" in label:
            self.imports.append(label)
        elif label not in self.calls:
            self.calls.append(label)

    def _terminator_only(self, block: _Block, depth: int) -> None:
        term = block.terminator
        if term.kind == "ret":
            self.lines.append(self._indent(depth) + self._return_line())
        elif term.kind == "cond_jump":
            if term.target is not None and term.target not in self.fn.blocks:
                self._external_branch(block, depth)
                return
            cond = self._condition(term)
            self.lines.append(
                self._indent(depth)
                + (f"if ({cond}) goto {self._label_name(term.target)};" if cond else
                   f"goto {self._label_name(term.target)};")
            )
        elif term.kind == "jump":
            if term.target is None:
                return
            if term.target in self.fn.blocks:
                self.lines.append(self._indent(depth) + f"goto {self._label_name(term.target)};")
            else:
                self._tail(term, depth)

    # -- statements --------------------------------------------------------
    def _body(self, block: _Block, depth: int) -> None:
        self._cmp = None
        self._flags = None
        self._args = {}
        body = block.insns
        if body and body[-1].kind in ("ret", "jump", "cond_jump"):
            body = body[:-1]
        # Callee-saved registers pushed into the frame are prologue bookkeeping,
        # not logic; suppressing them in the entry block only keeps a real spill
        # visible everywhere else.
        prologue = block.start == self.cfg.entry
        for insn in body:
            decoded = self.fn.decode(insn.va)
            if decoded is None:
                self.dropped += 1
                continue
            text, extra = self._statement(decoded, insn)
            if not text:
                continue
            if prologue and _CALLEE_SAVED_STORE.fullmatch(text.replace(" ", "")):
                continue
            comment = insn.text + (f"  [{extra}]" if extra else "")
            self.lines.append(self._line(depth, text, comment))

    def _statement(self, decoded, insn: Instruction) -> tuple[str | None, str | None]:
        mnemonic = decoded.mnemonic.lower()
        operands = list(decoded.operands)
        if mnemonic in _SKIP:
            return None, None
        if mnemonic in ("cmp", "test"):
            if len(operands) >= 2:
                self._cmp = (
                    self._operand(decoded, operands[0]),
                    self._operand(decoded, operands[1]),
                    mnemonic,
                )
                self._flags = None
            return None, None

        if mnemonic.startswith("mov") and len(operands) == 2:
            dst = self._operand(decoded, operands[0], dst=True)
            if self._is_frame(dst, decoded, operands[0]):
                return None, None
            src = self._operand(decoded, operands[1])
            if src == dst:
                return None, None
            self._track(decoded, operands, mnemonic, dst, src)
            return f"{dst} = {src}", None

        if mnemonic == "lea" and len(operands) == 2:
            dst = self._operand(decoded, operands[0], dst=True)
            if self._is_frame(dst, decoded, operands[0]):
                return None, None
            src = self._operand(decoded, operands[1], address=True)
            self._track(decoded, operands, mnemonic, dst, src)
            # `&field` for a struct access, plain address arithmetic otherwise:
            # `arg0->0x10` is a value, `rbp+0x750` already is an address.
            if "->" in src:
                return f"{dst} = &{src}", None
            return f"{dst} = {src}", None

        if mnemonic in _BINARY and len(operands) == 2:
            dst = self._operand(decoded, operands[0], dst=True)
            if self._is_frame(dst, decoded, operands[0]):
                return None, None
            src = self._operand(decoded, operands[1])
            if mnemonic == "xor" and src == dst:
                self._track(decoded, operands, mnemonic, dst, "0")
                return f"{dst} = 0", None
            self._track(decoded, operands, mnemonic, dst, src)
            return f"{dst} {_BINARY[mnemonic]} {src}", None

        if mnemonic in ("inc", "dec") and len(operands) == 1:
            dst = self._operand(decoded, operands[0], dst=True)
            if self._is_frame(dst, decoded, operands[0]):
                return None, None
            delta = "+" if mnemonic == "inc" else "-"
            self._track(decoded, operands, mnemonic, dst, None)
            return f"{dst} {delta}= 1", None

        if mnemonic in ("neg", "not") and len(operands) == 1:
            dst = self._operand(decoded, operands[0], dst=True)
            prefix = "-" if mnemonic == "neg" else "~"
            self._track(decoded, operands, mnemonic, dst, None)
            return f"{dst} = {prefix}{dst}", None

        if mnemonic == "imul":
            if len(operands) == 1:
                return "rax = rax * " + self._operand(decoded, operands[0]), None
            dst = self._operand(decoded, operands[0], dst=True)
            if len(operands) == 2:
                src = self._operand(decoded, operands[1])
                self._track(decoded, operands, mnemonic, dst, src)
                return f"{dst} *= {src}", None
            src = self._operand(decoded, operands[1])
            imm = self._operand(decoded, operands[2])
            self._track(decoded, operands, mnemonic, dst, src)
            return f"{dst} = {src} * {imm}", None

        if mnemonic in ("div", "idiv") and len(operands) == 1:
            src = self._operand(decoded, operands[0])
            self._ret_reg = "rax"
            return f"rax = rax / {src}; rdx = rax % {src}", "approximate: implicit rax:rdx"

        if mnemonic == "mul" and len(operands) == 1:
            src = self._operand(decoded, operands[0])
            self._ret_reg = "rax"
            return f"rax = rax * {src}; rdx = high(qword)", "implicit rax:rdx"

        if mnemonic.startswith("set") and len(operands) == 1:
            dst = self._operand(decoded, operands[0], dst=True)
            cond = self._condition_suffix(mnemonic[3:])
            return f"{dst} = {cond}" if cond else f"{dst} = cc_{mnemonic[3:]}", None

        if mnemonic.startswith("cmov") and len(operands) == 2:
            dst = self._operand(decoded, operands[0], dst=True)
            src = self._operand(decoded, operands[1])
            cond = self._condition_suffix(mnemonic[4:])
            return f"{dst} = {cond} ? {src} : {dst}", None

        if mnemonic in ("xorps", "xorpd", "pxor") and len(operands) >= 2:
            dst = self._operand(decoded, operands[0], dst=True)
            src = self._operand(decoded, operands[1])
            if dst == src:
                return f"{dst} = 0", None

        if mnemonic == "call":
            return self._call(decoded, insn)

        # ---- the awkward-but-common instructions -------------------------
        # Hashes and checksums are full of rotates; leaving them as __asm__
        # makes a crypto loop unreadable, so they get an intrinsic form.  A
        # rotate changes CF/OF but *not* ZF/SF, so the cached comparison state is
        # deliberately left alone: a later `jz` still refers to an older test.
        if mnemonic in ("ror", "rol", "rcr", "rcl") and len(operands) == 2:
            dst = self._operand(decoded, operands[0], dst=True)
            amount = self._operand(decoded, operands[1])
            self._track(decoded, operands, mnemonic, dst, amount)
            return f"{dst} = __{mnemonic}({dst}, {amount})", None

        if mnemonic in ("bt", "bts", "btr", "btc") and len(operands) == 2:
            dst = self._operand(decoded, operands[0], dst=True)
            bit = self._operand(decoded, operands[1])
            if mnemonic == "bt":
                # Only CF is produced, which is exactly what `jc` tests next.
                self._cmp = (f"(({dst} >> {bit}) & 1)", "1", "cmp")
                self._flags = None
                return None, None
            self._track(decoded, operands, mnemonic, dst, bit)
            return f"{dst} = __{mnemonic}({dst}, {bit})", None

        if mnemonic in ("sbb", "adc") and len(operands) == 2:
            dst = self._operand(decoded, operands[0], dst=True)
            src = self._operand(decoded, operands[1])
            self._track(decoded, operands, mnemonic, dst, src)
            op = "-" if mnemonic == "sbb" else "+"
            return f"{dst} = {dst} {op} {src} {op} __cf", "carry flag assumed live"

        if mnemonic.endswith("cmpxchg") and len(operands) == 2:
            dst = self._operand(decoded, operands[0], dst=True)
            src = self._operand(decoded, operands[1])
            acc = "rax" if self.image.is_64 else "eax"
            return (
                f"if ({dst} == {acc}) {{ {dst} = {src}; }} else {{ {acc} = {dst}; }}",
                "lock cmpxchg (atomic compare-exchange)" if "lock" in insn.text else None,
            )

        if mnemonic in ("cdq", "cqo", "cwd"):
            size = "rax" if mnemonic == "cqo" else "eax"
            high = "rdx" if mnemonic == "cqo" else "edx"
            return f"{high} = {size} < 0 ? -1 : 0", "sign extension into the high half"

        if mnemonic in ("cwde", "cdqe", "cbw"):
            return None, "sign extension (operand width only)"

        if mnemonic == "rdtsc":
            self._ret_reg = "eax"
            return "edx:eax = __rdtsc()", "timestamp counter read"

        if mnemonic.startswith("rep") and len(mnemonic.split()) == 2:
            inner = mnemonic.split()[1]
            if inner.startswith(("stos", "movs", "lods", "scas", "cmps")):
                return f"__rep_{inner}(rdi, rsi, rcx)", "string instruction (rep prefix)"

        if mnemonic == "xchg" and len(operands) == 2:
            first = self._operand(decoded, operands[0], dst=True)
            second = self._operand(decoded, operands[1], dst=True)
            return f"swap({first}, {second})", None

        # Anything unmodelled stays visible instead of vanishing.
        self.dropped += 1
        raw = f"{mnemonic} {decoded.op_str}".strip().rstrip(";")
        return f"__asm__({raw!r});", "unmodelled instruction"

    def _call(self, decoded, insn: Instruction) -> tuple[str, str | None]:
        name: str | None = None
        if insn.ref is not None:
            name = self.image.resolve_import_name(insn.ref) or self.image.label(insn.ref)
        elif insn.target is not None:
            name = self._function_name(insn.target)
        else:
            for operand in decoded.operands:
                if operand.type in (X86_OP_REG, X86_OP_MEM):
                    name = f"(*{self._operand(decoded, operand)})"
                    break
        name = name or "unknown_call"
        if "!" in name:
            self.imports.append(name)
        else:
            self.calls.append(name)
        hint = None
        if self._args:
            hint = ", ".join(f"{k} = {v}" for k, v in sorted(self._args.items()))
            self._args = {}
        if name == "rax" or name == "rax()":
            hint = hint
        return f"{name}()", hint

    def _track(self, decoded, operands, mnemonic: str, dst: str, src: str | None) -> None:
        """Remember argument setup, flags state and where the return value lands."""
        plain = ""
        if operands and operands[0].type == X86_OP_REG:
            try:
                plain = (decoded.reg_name(operands[0].reg) or "").lower()
            except Exception:
                plain = ""
        if plain in _RAX:
            self.wrote_rax = True
            self._ret_reg = plain
        if dst.startswith("[") or "->" in dst:
            self.writes_memory = True
        if dst in ("arg0", "arg1", "arg2", "arg3") and src is not None and mnemonic.startswith("mov"):
            self._args[dst] = src
        if mnemonic in ("add", "sub", "and", "or", "xor", "inc", "dec", "imul",
                        "neg", "shl", "sal", "shr", "sar", "rol", "ror"):
            # The branch after this instruction tests *its result*, not an
            # earlier cmp, so a later `jz` means `dst == 0`.
            self._cmp = None
            self._flags = dst

    # -- conditions --------------------------------------------------------
    def _condition(self, insn: Instruction) -> _Cond | None:
        mnemonic = insn.mnemonic.lower()
        if not mnemonic.startswith("j"):
            return None
        suffix = mnemonic[1:]
        return self._condition_suffix(suffix)

    def _condition_suffix(self, suffix: str) -> _Cond | None:
        op = _CONDITIONS.get(suffix)
        if op is None:
            return None
        if op.startswith("overflow") or op.startswith("parity"):
            return _Cond(op)
        if self._cmp:
            lhs, rhs, kind = self._cmp
            if kind == "test":
                if rhs == lhs or op in ("==", "!="):
                    # `test x, x` tests x itself: the sign/zero of x is the flag.
                    return _Cond(lhs, op, "0")
                return _Cond(f"({lhs} & {rhs})", op, "0")
            return _Cond(lhs, op, rhs)
        if self._flags:
            # The preceding arithmetic set the flags: the branch tests its result.
            return _Cond(self._flags, op, "0")
        return _Cond(f"cc_{suffix}", "!=", "0")

    # -- operands ----------------------------------------------------------
    def _reg(self, decoded, reg_id: int, *, write: bool = False) -> str:
        """Register name, using ``arg0..arg3`` while the argument is still live.

        ``mov rcx, rax`` names the slot it overwrites (``arg0 = rax``) and from
        then on ``rcx`` is a scratch register, so later reads say ``rcx``.
        """
        try:
            name = (decoded.reg_name(reg_id) or "").lower()
        except Exception:
            return "?"
        base = _CANON.get(name, name)
        if write:
            # A write destroys the incoming argument: from here on the register
            # is scratch, so name it plainly and remember the clobber.
            self._clobbered.add(base)
            return name
        if base in self._clobbered:
            return name
        shown = ARG_ROLES.get(name, name)
        if shown.startswith("arg"):
            self.used_args.add(shown)
        return shown

    def _operand(self, decoded, operand, *, address: bool = False, dst: bool = False) -> str:
        if operand.type == X86_OP_REG:
            return self._reg(decoded, operand.reg, write=dst)
        if operand.type == X86_OP_IMM:
            return self._immediate(int(operand.imm))
        if operand.type == X86_OP_MEM:
            if dst:
                self.writes_memory = True
            return self._memory(decoded, operand, address=address)
        return "?"

    def _immediate(self, value: int) -> str:
        if value < 0:
            return f"-{abs(value):#x}"
        if self.image.contains(value) and self.image.is_executable_va(value):
            return self._function_name(value)
        return str(value) if value < 10 else f"{value:#x}"

    def _memory(self, decoded, operand, *, address: bool = False) -> str:
        mem = operand.mem
        base = self._reg(decoded, mem.base) if mem.base else ""
        index = self._reg(decoded, mem.index) if mem.index else ""
        scale = int(mem.scale or 0)
        if base in ("rip", "eip"):
            target = int(decoded.address) + int(decoded.size) + int(mem.disp)
            return self._target(target)
        if base and base.startswith("arg") and not index:
            disp = int(mem.disp)
            return f"{base}->{disp:#x}" if disp else f"{base}[0]"
        expression = base
        if index:
            term = f"{index}*{scale}" if scale > 1 else index
            expression = f"{expression}+{term}" if expression else term
        disp = int(mem.disp)
        if disp:
            expression = f"{expression}{disp:+#x}" if expression else f"{disp:#x}"
        if not expression:
            expression = "0x0"
        return expression if address else f"[{expression}]"

    def _target(self, target: int) -> str:
        image = self.image
        if not image.contains(target):
            return f"[{target:#x}]"
        import_name = image.resolve_import_name(target)
        if import_name:
            return import_name
        name = image.user_names.get(target)
        if name:
            return name
        string = self._string_at(target)
        if string is not None:
            self.strings.append(string)
            return f'"{string}"'
        if image.is_executable_va(target):
            # An address in a code section that was never discovered as a function
            # start is data living in .text (a jump table, a string, a global), not
            # a callee: labelling it `sub_x` would invent a function.
            if target in self.fn.index.function_starts:
                return self._function_name(target)
            return f"g_{target - image.base:04X}"
        return f"g_{target - image.base:04X}"

    def _string_at(self, va: int) -> str | None:
        data = self.image.read(va, MAX_STRING)
        if not data:
            return None
        ascii_out = []
        for byte in data:
            if byte == 0:
                break
            if 0x20 <= byte < 0x7F:
                ascii_out.append(chr(byte))
            else:
                ascii_out = []
                break
        if len(ascii_out) >= 4:
            return "".join(ascii_out)
        wide = []
        for position in range(0, len(data) - 1, 2):
            low, high = data[position], data[position + 1]
            if low == 0 and high == 0:
                break
            if high == 0 and 0x20 <= low < 0x7F:
                wide.append(chr(low))
            else:
                return None
        return "".join(wide) if len(wide) >= 4 else None

    def _function_name(self, va: int) -> str:
        name = self.image.user_names.get(va)
        if name:
            return name
        for export in self.image.exports:
            if export.va == va and export.name:
                return export.name
        return f"sub_{va - self.image.base:04X}"

    def _is_frame(self, text: str, decoded, operand) -> bool:
        """True when the destination is pure stack bookkeeping."""
        if operand.type != X86_OP_REG:
            return False
        return self._reg(decoded, operand.reg) in _FRAME_REGS

    # -- lines -------------------------------------------------------------
    def _indent(self, depth: int) -> str:
        # A long if/else chain nests linearly; cap the indent so a 700-block
        # function stays readable instead of marching off the right margin.
        return "    " * min(depth, MAX_INDENT)

    def _line(self, depth: int, text: str, comment: str | None) -> str:
        line = self._indent(depth) + (text if text.endswith(";") else text + ";")
        if self.include_comments and comment:
            line += f"  // {comment}"
        return line

    def _label_name(self, start: int) -> str:
        return f"L_{start - self.image.base:04X}"

    def _label(self, start: int, depth: int) -> None:
        if start in self.known_targets:
            self.lines.append(self._indent(max(1, depth - 1)) + self._label_name(start) + ":")

    def _goto(self, target: int, depth: int) -> None:
        self.goto_targets.add(target)
        self.lines.append(self._indent(depth) + f"goto {self._label_name(target)};")

    def _return_line(self) -> str:
        return f"return {self._ret_reg};" if self._ret_reg else "return;"


def _signature(fn: _Function, index: CodeIndex, name: str, emitter: _Emitter) -> str:
    roles: list[str] = []
    try:
        from .structs import infer_layout

        roles = [layout.role for layout in infer_layout(index, fn.start, limit=4000)
                 if layout.role.startswith("arg")]
    except Exception:
        roles = []
    roles = sorted(set(roles) | emitter.used_args, key=lambda role: role)
    params = ", ".join(f"int64_t {role}" for role in roles) if roles else "void"
    if not emitter._ret_reg:
        returns = "int64_t" if emitter.tail_returns else "void"
    else:
        returns = "int64_t" if emitter._ret_reg.startswith("r") else "int32_t"
    return f"{returns} {name}({params})"


def decompile(
    index: CodeIndex,
    va: int,
    *,
    include_comments: bool = True,
    max_blocks: int = MAX_BLOCKS,
) -> dict:
    """Lift the function containing ``va`` to pseudo-C.

    Returns ``text`` plus the structure that produced it (blocks, loops, calls,
    imports, strings) and an honest ``confidence``.
    """
    image = index.image
    if not index.disassembler.x86:
        raise Unavailable("pseudo-C recovery is implemented for x86/x64 only")
    start = index.function_start(va) or va
    if not image.is_executable_va(start):
        raise Unavailable(f"{start:#x} is not executable code in this image")

    fn = _Function(index, start)
    if not fn.blocks:
        raise Unavailable(f"no basic blocks recovered at {start:#x}")
    if len(fn.blocks) > max_blocks:
        note = (f"function has {len(fn.blocks)} basic blocks (limit {max_blocks}); structure "
                "recovery is not attempted — read it with `disassemble`")
        name = index.image.label(start) or f"sub_{start - index.image.base:X}"
        return {
            "function": hex(start),
            "name": name,
            "signature": f"void {name}(void)",
            "text": f"// {name}: {note}",
            "instructions": len(fn.insns),
            "loops": [],
            "calls": [],
            "imports": [],
            "strings": [],
            "writes_memory": False,
            "unmodelled": 0,
            "blocks": len(fn.blocks),
            "confidence": "skipped",
            "notes": [note],
        }

    cfg = _CFG(fn)
    emitter = _Emitter(fn, cfg, include_comments=include_comments)
    lines = emitter.render()

    name = emitter._function_name(start)
    signature = _signature(fn, index, name, emitter)
    end = max((insn.va + insn.size for insn in fn.insns), default=start)
    header = [
        f"// {signature}",
        f"// {start:#x} .. {end:#x}  {len(fn.blocks)} block(s), {len(cfg.loops)} loop(s)"
        + (f", {len(cfg.back_edges)} back edge(s)" if cfg.back_edges else ""),
    ]
    body = "\n".join(lines)
    text = "\n".join(header) + "\n" + f"{signature} {{\n{body}\n}}"

    notes = list(dict.fromkeys(emitter.note))
    if emitter.dropped:
        notes.append(
            f"{emitter.dropped} instruction(s) were not modelled and are kept as "
            "__asm__() or dropped for missing decode"
        )
    if cfg.loops:
        notes.append("loops are rendered as while()/while(1)+break; nested loops keep their exits")
    confidence = "medium"
    if not cfg.loops and emitter.dropped == 0 and len(fn.blocks) <= 64:
        confidence = "high"
    if emitter.dropped > len(fn.insns) // 4 or cfg.summary()["irreducible"]:
        confidence = "low"

    return {
        "function": hex(start),
        "name": name,
        "signature": signature,
        "text": text,
        "blocks": len(fn.blocks),
        "instructions": len(fn.insns),
        "loops": cfg.summary()["loops"],
        "calls": sorted(set(emitter.calls)),
        "imports": sorted(set(emitter.imports)),
        "strings": list(dict.fromkeys(emitter.strings))[:32],
        "writes_memory": emitter.writes_memory,
        "unmodelled": emitter.dropped,
        "confidence": confidence,
        "notes": notes,
    }
