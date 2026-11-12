"""Pointer-chain resolution: from a static base to a live value.

``pointer_scan`` finds chains; this module *uses* them.  That matters because a
chain you cannot replay is trivia: the whole point of a "cheat table" entry is
that ``game.exe + 0x01A2B6C0 → +0x10 → +0x38 → +0x8`` still resolves to the same
field after a restart.

Two conventions are supported explicitly, because mixing them silently is how
pointer chains get misread:

* **Path form** (default, Cheat-Engine shaped).  Each offset is added *before*
  the next dereference, and the final offset selects the field::

      address = base
      for index, offset in enumerate(offsets):
          address += offset
          if index < len(offsets) - 1:
              address = read_pointer(address)     # fail loudly if unmapped

* **Replay form** (:func:`replay`).  A chain produced by
  ``DynamicEngine.pointer_scan`` is ``static_base + offsets[0]`` followed by pure
  dereferences, because that scan only matches *exact* pointer values.

Every level is reported with the address that was read and the pointer obtained,
so a chain that stops working says exactly which hop broke instead of returning
a plausible zero.
"""

from __future__ import annotations

import struct

from .. import utils
from ..errors import BackendError, InvalidArgument, NotFound

#: Deeper than this is not a chain, it is a way to hide a bug in the offsets.
MAX_DEPTH = 12
PTR_SIZE = 8


def parse_base(engine, pid: int, expression: str | int) -> tuple[int, str]:
    """Resolve ``"game.exe+0x1a2b"``, ``"0x7ff6..."`` or an int to a VA.

    Returns ``(va, canonical_expression)`` so the answer can be pasted back into
    :func:`resolve` later without being re-guessed.
    """
    if isinstance(expression, int):
        return expression, hex(expression)
    text = str(expression).strip()
    if not text:
        raise InvalidArgument("base is required")
    if "+" in text:
        left, _, offset = text.rpartition("+")
        delta = utils.parse_address(offset, name="offset")
        # ``0x7ff6...+0x10`` is an address expression, not a module name; only a
        # non-numeric left side is looked up as a module.
        try:
            head = utils.parse_int(left, name="base")
        except InvalidArgument:
            head = None
        if head is not None:
            return head + delta, hex(head + delta)
        module = engine.resolve_module(pid, left)
        return module.base + delta, f"{module.name}+{delta:#x}"
    va = utils.parse_address(text, name="base")
    return va, hex(va)


def read_pointer(engine, pid: int, address: int) -> int:
    """Read one pointer-sized value, raising a located error when it cannot."""
    data = engine.read_bytes(pid, address, PTR_SIZE)
    if len(data) < PTR_SIZE:
        raise BackendError(f"short pointer read at {address:#x} (got {len(data)} bytes)")
    return struct.unpack("<Q", data)[0]


def _locate(engine, pid: int, address: int) -> dict:
    """Module/region context for one address, without raising on lookup failure."""
    out: dict = {"address": hex(address)}
    try:
        info = engine.address_info(pid, address)
    except Exception:  # a broken chain must still describe itself
        return out
    if info.get("module"):
        out["module"] = info["module"]
        out["module_offset"] = info["module_offset"]
    if info.get("region"):
        region = info["region"]
        out["region_base"] = hex(region["base"])
        out["region_protection"] = region.get("protection")
        out["writable"] = info.get("writable")
    if info.get("symbol"):
        out["symbol"] = info["symbol"].get("symbol") or info["symbol"].get("function")
    return out


def resolve(engine, pid: int, base: str | int, offsets: list[int | str], *,
            value_type: str | None = None, read_size: int = 0) -> dict:
    """Walk a pointer path and report every hop.

    ``value_type`` (or ``read_size``) additionally reads the final address, which
    is what you actually wanted; without it the result stops at the address.
    """
    chain = [utils.parse_address(offset, name="offset") for offset in offsets]
    if len(chain) > MAX_DEPTH:
        raise InvalidArgument(f"chain has {len(chain)} offsets (limit {MAX_DEPTH})")
    start, expression = parse_base(engine, pid, base)

    levels: list[dict] = []
    address = start
    for index, offset in enumerate(chain):
        address += offset
        level = {"level": index, "offset": hex(offset), "at": hex(address), **_locate(engine, pid, address)}
        if index < len(chain) - 1:
            try:
                pointer = read_pointer(engine, pid, address)
            except (BackendError, NotFound) as exc:
                level["error"] = str(exc)
                levels.append(level)
                raise BackendError(
                    f"chain broke at level {index}: cannot read a pointer from {address:#x} "
                    f"({expression} + {', '.join(hex(o) for o in chain[: index + 1])})"
                ) from exc
            level["pointer"] = hex(pointer)
            levels.append(level)
            if pointer == 0:
                raise BackendError(
                    f"chain broke at level {index}: {address:#x} holds a null pointer"
                )
            address = pointer
            continue
        levels.append(level)

    result: dict = {
        "pid": pid,
        "base": expression,
        "base_va": hex(start),
        "offsets": [hex(offset) for offset in chain],
        "depth": len(chain),
        "address": hex(address),
        "levels": levels,
        "kind": "address",
    }
    result.update({k: v for k, v in _locate(engine, pid, address).items() if k != "address"})

    if value_type:
        size = utils.value_type_size(value_type)
        result["value"] = utils.unpack_value(engine.read_bytes(pid, address, size), value_type)
        result["type"] = value_type
        result["kind"] = "value"
    elif read_size > 0:
        data = engine.read_bytes(pid, address, read_size)
        result["hex"] = data.hex()
        result["size"] = len(data)
        result["dump"] = utils.hexdump(data, address)
        result["kind"] = "bytes"
    # A chain you can paste back into the CLI or a later scan.  This is what makes
    # a found address reproducible: the path survives, the address does not.
    result["template"] = {
        "base": expression,
        "offsets": [int(offset) for offset in chain],
        "value_type": value_type,
    }
    return result


def replay(engine, pid: int, chain: dict, *, value_type: str | None = None) -> dict:
    """Re-run a chain produced by ``pointer_scan`` and verify it still resolves.

    Those chains are ``static_base + first_offset`` followed by pure
    dereferences, so replay differs from :func:`resolve` in one place only: the
    remaining offsets are not added again.  ``target`` in the chain is checked
    against the replay result, which is the difference between "this chain looks
    right" and "this chain is right".
    """
    offsets = chain.get("offsets") or []
    if not offsets:
        raise InvalidArgument("chain has no offsets")
    if not chain.get("module_anchored"):
        raise InvalidArgument(
            "chain is not anchored in a module, so it cannot survive a restart; "
            "re-scan with `module=` to get one that does"
        )
    static_base = str(chain.get("static_base") or "")
    first = utils.parse_address(offsets[0], name="offset")
    address, expression = parse_base(engine, pid, f"{static_base}+{first:#x}")

    levels = [{"level": 0, "at": hex(address), **_locate(engine, pid, address)}]
    target_va = address
    for depth in range(len(offsets)):
        pointer = read_pointer(engine, pid, address)
        if pointer == 0:
            raise BackendError(f"chain broke at depth {depth}: {address:#x} holds a null pointer")
        if depth == len(offsets) - 1:
            target_va = pointer
        address = pointer
        levels.append({"level": depth + 1, "at": hex(address), "from": levels[-1]["at"],
                       **_locate(engine, pid, address)})

    # Every offset in a scanned chain is a slot whose content is the next address,
    # so after `len(offsets)` dereferences we are standing on the target itself.
    expected = chain.get("target")
    resolved = target_va
    result: dict = {
        "pid": pid,
        "static_base": expression,
        "offsets": offsets,
        "levels": levels,
        "address": hex(resolved),
        "target": expected,
        "resolved": hex(resolved),
        "matched": bool(expected) and int(str(expected), 0) == resolved,
    }
    if value_type:
        size = utils.value_type_size(value_type)
        result["value"] = utils.unpack_value(engine.read_bytes(pid, address, size), value_type)
        result["type"] = value_type
    return result


def resolve_many(engine, pid: int, chains: list[dict], *, value_type: str | None = None,
                 limit: int = 10) -> list[dict]:
    """Replay several chains, keeping the ones that still resolve.

    Broken candidates are reported with their error instead of being dropped:
    "chain 3 fails at depth 2" is information about the target, not noise.
    """
    out: list[dict] = []
    for index, chain in enumerate(chains[: max(1, limit)]):
        try:
            row = replay(engine, pid, chain, value_type=value_type)
            row["index"] = index
            out.append(row)
        except Exception as exc:
            out.append({"index": index, "static_base": chain.get("static_base"),
                        "offsets": chain.get("offsets"), "target": chain.get("target"),
                        "matched": None, "error": str(exc)})
    return out
