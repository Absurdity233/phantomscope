"""Function fingerprinting: match, cluster and diff code without symbols.

DMA gives you the code that is running, not the PDB that says what it is.  Two
questions come up constantly and neither needs symbol names:

* **"have I seen this function before?"** — the same code shows up in a game
  module and in an injected DLL, or a build is re-shipped with a few bytes
  changed.  A *normalised* hash (branch targets and immediates abstracted away)
  matches the function across addresses, bases and minor recompilation.
* **"what changed between these two builds?"** — hash every function in both
  images, subtract, and the remainder is the patch.

Normalisation
-------------
Per instruction, the token stream keeps the mnemonic and the operand *shape*
(registers, memory forms) but replaces relative branch targets and immediates with
placeholders, so ``mov eax, 100`` and ``mov eax, 7`` hash the same while
``add eax, ecx`` and ``sub eax, ecx`` do not.  Immediates and branch targets are
kept separately as a *constants* set, which is what distinguishes two instances of
the same shape.

Similarity is the Jaccard index over mnemonic trigrams: a cheap, explainable
number that works when the instruction stream was edited but not rewritten.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ..models import Model
from .index import CodeIndex

#: Instructions that carry the semantics; operands keep free registers, lose
#: offsets.  Anything not listed still contributes its mnemonic.
_TRIGRAM = 3


@dataclass
class FunctionFingerprint(Model):
    function: int
    name: str | None = None
    size: int = 0
    instructions: int = 0
    blocks: int = 0
    callers: int = 0
    hash: str = ""            # normalised opcode+shape hash
    mnemonic_hash: str = ""    # opcode-only hash (coarser)
    constants: list[int] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        out = super().to_dict()
        out["function"] = hex(self.function)
        out["constants"] = [hex(value) if value >= 0 else value for value in self.constants]
        return out


def _tokens(index: CodeIndex, function_va: int) -> tuple[list[str], list[int], list[str], list[str]]:
    """Normalised tokens, constants, imports and strings for one function."""
    image = index.image
    instructions = index.disassemble_function(function_va)
    tokens: list[str] = []
    constants: list[int] = []
    imports: list[str] = []
    strings: list[str] = []
    for insn in instructions:
        tokens.append(insn.mnemonic)
        if insn.kind in ("call", "jump", "cond_jump"):
            tokens.append("branch")
            if insn.target is not None:
                constants.append(insn.target)
            continue
        decoded = index.disassembler.one(image.read(insn.va, 16), insn.va)
        if decoded is None:
            continue
        for operand in decoded.operands:
            try:
                kind = operand.type
            except Exception:
                continue
            if kind == 2:  # X86_OP_IMM
                tokens.append("imm")
                constants.append(int(operand.imm))
            elif kind == 3:  # X86_OP_MEM
                tokens.append("mem")
            else:
                tokens.append("reg")
        if insn.ref is not None:
            name = image.resolve_import_name(insn.ref)
            if name:
                imports.append(name)
            else:
                text = _string_at(image, insn.ref)
                if text:
                    strings.append(text)
    return tokens, constants, imports, strings


def _string_at(image, va: int, limit: int = 64) -> str | None:
    data = image.read(va, limit)
    if not data:
        return None
    run = bytearray()
    for byte in data:
        if byte == 0:
            break
        if 0x20 <= byte < 0x7F:
            run.append(byte)
        else:
            return None
    return run.decode("ascii") if len(run) >= 4 else None


def _digest(tokens: list[str]) -> str:
    return hashlib.sha1("|".join(tokens).encode("utf-8")).hexdigest()[:16]


def fingerprint(index: CodeIndex, va: int) -> FunctionFingerprint:
    """Fingerprint the function containing ``va``."""
    start = index.function_start(va) or va
    tokens, constants, imports, strings = _tokens(index, start)
    instructions = index.disassemble_function(start)
    mnemonics = [insn.mnemonic for insn in instructions]
    begin, end = index.function_ranges.get(start, (start, instructions[-1].va + instructions[-1].size
                                                     if instructions else start))
    return FunctionFingerprint(
        function=start,
        name=index.image.label(start),
        size=max(0, end - begin),
        instructions=len(instructions),
        blocks=len(index.blocks_for(start)),
        callers=len(index.callers(start)),
        hash=_digest(tokens),
        mnemonic_hash=_digest(mnemonics),
        constants=sorted(set(constants))[:64],
        imports=sorted(set(imports)),
        strings=sorted(set(strings))[:16],
    )


def all_fingerprints(index: CodeIndex, *, limit: int = 4000) -> dict[int, FunctionFingerprint]:
    """Fingerprint every discovered function (cached on the index)."""
    cached = getattr(index, "_fingerprints", None)
    if cached is not None:
        return cached
    out: dict[int, FunctionFingerprint] = {}
    for start in sorted(index.function_starts)[:limit]:
        try:
            out[start] = fingerprint(index, start)
        except Exception:  # a malformed function must not abort the sweep
            continue
    index._fingerprints = out  # type: ignore[attr-defined]
    return out


def _shingles(tokens: list[str]) -> set[tuple[str, ...]]:
    if len(tokens) < _TRIGRAM:
        return {tuple(tokens)} if tokens else set()
    return {tuple(tokens[i : i + _TRIGRAM]) for i in range(len(tokens) - _TRIGRAM + 1)}


def similarity(left: FunctionFingerprint, right: FunctionFingerprint,
               left_tokens: list[str] | None = None,
               right_tokens: list[str] | None = None) -> float:
    """Jaccard similarity of mnemonic trigrams (1.0 = identical shape)."""
    if left.hash and left.hash == right.hash:
        return 1.0
    a = _shingles(left_tokens or [])
    b = _shingles(right_tokens or [])
    if not a or not b:
        return 0.0
    return round(len(a & b) / len(a | b), 3)


def _token_cache() -> dict[int, list[str]]:
    """Per-call token memo: ``_tokens`` decodes every instruction, so the O(n*m)
    comparison loops must not redo it for the same function."""
    return {}


def _tokens_of(index: CodeIndex, va: int, cache: dict[int, list[str]]) -> list[str]:
    cached = cache.get(va)
    if cached is None:
        cached = _tokens(index, va)[0]
        cache[va] = cached
    return cached


def find_similar(index: CodeIndex, va: int, *, limit: int = 10,
                 min_similarity: float = 0.5) -> list[dict]:
    """Functions in the same image that look like the one at ``va``."""
    target = fingerprint(index, va)
    cache = _token_cache()
    target_tokens = _tokens_of(index, target.function, cache)
    rows: list[dict] = []
    for start, other in all_fingerprints(index).items():
        if start == target.function:
            continue
        score = similarity(target, other, target_tokens, _tokens_of(index, start, cache))
        if score < min_similarity:
            continue
        rows.append(
            {
                "function": hex(start),
                "name": other.name,
                "similarity": score,
                "same_hash": other.hash == target.hash,
                "size": other.size,
                "instructions": other.instructions,
            }
        )
    rows.sort(key=lambda row: (-row["similarity"], row["function"]))
    return rows[:limit]


def match_images(left: CodeIndex, right: CodeIndex, *, min_similarity: float = 0.6,
                 limit: int = 400) -> list[dict]:
    """Match functions of ``left`` against ``right`` by hash, then by shape."""
    left_map = all_fingerprints(left)
    right_map = all_fingerprints(right)
    by_hash: dict[str, list[int]] = {}
    for start, item in right_map.items():
        by_hash.setdefault(item.hash, []).append(start)

    tokens: dict[int, list[str]] = {}
    rows: list[dict] = []
    matched_right: set[int] = set()
    for start, item in sorted(left_map.items()):
        exact = [candidate for candidate in by_hash.get(item.hash, []) if candidate not in matched_right]
        if exact:
            matched_right.add(exact[0])
            rows.append({
                "left": hex(start), "right": hex(exact[0]), "similarity": 1.0,
                "kind": "identical", "left_size": item.size,
            })
            continue
        if len(rows) >= limit:
            break
        left_tokens = _tokens_of(left, start, tokens)
        best: tuple[float, int] | None = None
        for candidate, other in right_map.items():
            if candidate in matched_right:
                continue
            if abs(other.instructions - item.instructions) > max(6, item.instructions // 3):
                continue
            score = similarity(item, other, left_tokens,
                               _tokens_of(right, candidate, tokens))
            if best is None or score > best[0]:
                best = (score, candidate)
        if best is not None and best[0] >= min_similarity:
            matched_right.add(best[1])
            rows.append({
                "left": hex(start), "right": hex(best[1]), "similarity": best[0],
                "kind": "similar", "left_size": item.size,
            })
    rows.sort(key=lambda row: row["left"])
    return rows


def diff_images(left: CodeIndex, right: CodeIndex, *, min_similarity: float = 0.6) -> dict:
    """Structural diff of two builds: identical / similar / added / removed."""
    left_map = all_fingerprints(left)
    right_map = all_fingerprints(right)
    right_by_hash: dict[str, list[int]] = {}
    for start, item in right_map.items():
        right_by_hash.setdefault(item.hash, []).append(start)

    tokens: dict[int, list[str]] = {}
    identical: list[dict] = []
    similar: list[dict] = []
    removed: list[dict] = []
    paired: set[int] = set()

    for start, item in sorted(left_map.items()):
        candidates = [c for c in right_by_hash.get(item.hash, []) if c not in paired]
        if candidates:
            paired.add(candidates[0])
            identical.append({"left": hex(start), "right": hex(candidates[0]), "size": item.size})
            continue
        left_tokens = _tokens_of(left, start, tokens)
        best: tuple[float, int] | None = None
        for candidate, other in right_map.items():
            if candidate in paired:
                continue
            if abs(other.instructions - item.instructions) > max(6, item.instructions // 3):
                continue
            score = similarity(item, other, left_tokens,
                               _tokens_of(right, candidate, tokens))
            if best is None or score > best[0]:
                best = (score, candidate)
        if best is not None and best[0] >= min_similarity:
            paired.add(best[1])
            similar.append({
                "left": hex(start), "right": hex(best[1]),
                "similarity": best[0], "left_size": item.size,
                "right_size": right_map[best[1]].size,
            })
        else:
            removed.append({"left": hex(start), "size": item.size, "instructions": item.instructions})

    added = [
        {"right": hex(start), "size": item.size, "instructions": item.instructions}
        for start, item in sorted(right_map.items())
        if start not in paired
    ]
    return {
        "left_functions": len(left_map),
        "right_functions": len(right_map),
        "identical": identical,
        "similar": similar,
        "removed": removed,
        "added": added,
        "counts": {
            "identical": len(identical),
            "similar": len(similar),
            "removed": len(removed),
            "added": len(added),
        },
    }
