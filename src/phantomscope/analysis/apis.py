"""Import (API) reference resolution: which function calls what, and where.

x64 Windows code almost never calls ``kernel32!CreateFileW`` directly; it calls
``call qword ptr [rip+disp]`` through an import thunk, or loads the slot into a
register first (``mov rax, [rip+disp]`` / ``jmp rax`` for tail calls).  Raw
disassembly therefore shows an address, not an API name, and "find the code that
touches the network / the registry / the crypto provider" has no cheap answer.

This module resolves those indirect sites back to ``module!name`` using
:attr:`~phantomscope.analysis.pe.PEImage.imported_by_slot`, and offers the two
questions an analyst actually asks:

* **per function** — ``api_calls(va)``: every API this function reaches, with the
  call sites, so a function's purpose is visible from its imports;
* **per API** — ``find_api("VirtualProtect")``: every function that reaches a
  given API, which is how you find the anti-tamper code, the AES key setup or the
  thread that polls the network.

The index is built from :class:`~phantomscope.analysis.index.CodeIndex`, so it
inherits its reach: statically reachable code plus the linear sweep.  Code that
was never decoded (virtualised dispatchers, encrypted stubs) is not in it, and
``unresolved_indirect`` reports how many indirect calls were left unnamed.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Model
from .index import CodeIndex

#: Kinds reported by :func:`api_sites`.
KIND_CALL = "call"          # call qword ptr [iat]
KIND_JUMP = "jump"          # jmp qword ptr [iat]  (tail call)
KIND_LOAD = "load"          # mov reg, [iat]       (thunk setup)
KIND_INDIRECT = "indirect"  # mov reg, [iat]; call reg


@dataclass
class ApiCall(Model):
    """One reference to an imported function."""

    va: int
    function: int | None
    module: str
    name: str
    slot: int
    kind: str = KIND_CALL

    def to_dict(self) -> dict:
        out = super().to_dict()
        out["va"] = hex(self.va)
        out["slot"] = hex(self.slot)
        if self.function is not None:
            out["function"] = hex(self.function)
        return out

    @property
    def key(self) -> str:
        return f"{self.module}!{self.name}"


def _split(name: str) -> tuple[str, str]:
    module, _, symbol = name.partition("!")
    return module, symbol or name


def api_sites(index: CodeIndex) -> list[ApiCall]:
    """Every import reference in the image, sorted by address (cached)."""
    cached = getattr(index, "_api_sites", None)
    if cached is not None:
        return cached

    image = index.image
    sites: list[ApiCall] = []
    insns = index.insns
    for va in sorted(insns):
        insn = insns[va]
        if insn.ref is None:
            continue
        resolved = image.resolve_import_name(insn.ref)
        if not resolved:
            continue
        module, symbol = _split(resolved)
        kind = KIND_CALL
        if insn.kind == "call":
            kind = KIND_CALL
        elif insn.kind == "jump":
            kind = KIND_JUMP
        else:
            kind = KIND_LOAD
            following = insns.get(va + insn.size)
            if following is not None and following.mnemonic == "call":
                # mov reg, [iat]; call reg  — the slot and the call are adjacent.
                kind = KIND_INDIRECT
        sites.append(
            ApiCall(
                va=va,
                function=index.function_start(va),
                module=module,
                name=symbol,
                slot=insn.ref,
                kind=kind,
            )
        )

    index._api_sites = sites  # type: ignore[attr-defined]
    return sites


def api_calls(index: CodeIndex, function_va: int | None = None, *, limit: int = 2000) -> list[ApiCall]:
    """Import references inside one function (or the whole image).

    An address that is not part of a discovered function is *not* treated as
    "no filter": it filters to itself and returns nothing, because silently
    returning every API in the image would read as an answer.
    """
    start = None if function_va is None else (index.function_start(function_va) or function_va)
    out: list[ApiCall] = []
    for site in api_sites(index):
        if start is not None and not _inside(index, site.va, start):
            continue
        out.append(site)
        if len(out) >= limit:
            break
    return out


def _inside(index: CodeIndex, va: int, function: int) -> bool:
    begin, end = index.function_ranges.get(function, (function, function))
    return begin <= va < max(end, begin + 1)


def api_summary(index: CodeIndex, function_va: int | None = None) -> list[dict]:
    """Imports grouped by name: who calls it, how often, from where."""
    grouped: dict[str, dict] = {}
    for site in api_calls(index, function_va):
        entry = grouped.get(site.key)
        if entry is None:
            entry = {
                "api": site.key,
                "module": site.module,
                "name": site.name,
                "count": 0,
                "functions": [],
                "sites": [],
            }
            grouped[site.key] = entry
        entry["count"] += 1
        if site.function is not None and site.function not in entry["functions"]:
            entry["functions"].append(site.function)
        entry["sites"].append({"va": hex(site.va), "kind": site.kind})

    out = []
    for entry in grouped.values():
        entry["functions"] = [hex(va) for va in sorted(entry["functions"])]
        out.append(entry)
    out.sort(key=lambda item: (-item["count"], item["api"].lower()))
    return out


def find_api(index: CodeIndex, needle: str, *, limit: int = 200) -> list[dict]:
    """Call sites of every import whose ``module!name`` contains ``needle``.

    Returning the *call sites grouped by function* is what makes this useful:
    a function that calls ``VirtualProtect`` once and ``GetTickCount`` twice is a
    different animal from one that calls ``CryptDecrypt`` in a loop.
    """
    low = needle.lower().lstrip("!_")
    if not low:
        return []
    grouped: dict[int | None, dict] = {}
    for site in api_sites(index):
        haystack = site.key.lower()
        if low not in haystack and low not in site.name.lower():
            continue
        entry = grouped.get(site.function)
        if entry is None:
            entry = {"function": site.function, "apis": [], "sites": []}
            grouped[site.function] = entry
        if site.key not in entry["apis"]:
            entry["apis"].append(site.key)
        entry["sites"].append({"va": hex(site.va), "api": site.key, "kind": site.kind})
        if len(entry["sites"]) > 64:
            entry["sites"] = entry["sites"][:64]
    out = []
    for entry in grouped.values():
        if entry["function"] is not None:
            entry["function"] = hex(entry["function"])
        out.append(entry)
        if len(out) >= limit:
            break
    out.sort(key=lambda item: (item["function"] or ""))
    return out


def unresolved_indirect(index: CodeIndex, function_va: int | None = None) -> int:
    """Indirect calls that do not resolve to an IAT slot, as an honesty counter."""
    start = index.function_start(function_va) if function_va is not None else None
    count = 0
    for va, insn in index.insns.items():
        if insn.kind not in ("call", "jump"):
            continue
        if insn.ref is not None and index.image.resolve_import_name(insn.ref):
            continue
        if insn.target is not None:
            continue  # direct branch, not indirect at all
        if start is not None and not _inside(index, va, start):
            continue
        count += 1
    return count
