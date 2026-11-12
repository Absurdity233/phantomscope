"""Snapshot emulation: registers, single stepping and memory watchpoints.

MemProcFS over DMA cannot stop a thread, read its register context or single
step it, so a classic breakpoint debugger is not available.  What *is*
available is the ability to snapshot code and data, and to emulate that
snapshot locally.

This module wraps Unicorn to provide:

* a register file for x86/x64,
* ``step`` / ``run_until`` with a bounded instruction budget,
* mapped image sections and extra memory regions,
* API stubs: an imported function (``kernel32!VirtualProtect``) can be hooked
  with a callback, which is how you get "break on call" without a debugger,
* memory access hooks to emulate read/write watchpoints,
* string and pointer arguments decoded at or around the current RIP.

The emulator is optional: if Unicorn is missing, :class:`Unavailable` is raised.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..analysis.pe import PEImage
from ..errors import InvalidArgument, Unavailable

REGISTERS_X64 = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip")
FLAGSX64 = ("eflags",)

MAX_STEPS = 5_000_000

#: Unicorn access codes → words, so a fault reads as "unmapped write at 0x1234".
_ACCESS_NAMES = {
    16: "read", 17: "write", 18: "fetch",
    19: "read_unmapped", 20: "write_unmapped", 21: "fetch_unmapped",
    22: "write_protected",
}


def _unicorn():
    try:
        import unicorn  # type: ignore
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64  # noqa: F401
        from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE  # noqa: F401
        from unicorn import UC_PROT_ALL, UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE  # noqa: F401
        from unicorn.x86_const import (  # noqa: F401
            UC_X86_REG_EFLAGS, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
            UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
            UC_X86_REG_R15, UC_X86_REG_RAX, UC_X86_REG_RBP, UC_X86_REG_RBX,
            UC_X86_REG_RCX, UC_X86_REG_RDI, UC_X86_REG_RDX, UC_X86_REG_RIP,
            UC_X86_REG_RSI, UC_X86_REG_RSP,
        )
        return unicorn
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise Unavailable(
            "snapshot emulation needs the `unicorn` package (`pip install unicorn`)"
        ) from exc


REG_IDS: dict[str, int] = {}


def _register_ids(uc_mod) -> dict[str, int]:
    from unicorn import x86_const as x86

    mapping = {
        "rax": x86.UC_X86_REG_RAX,
        "rcx": x86.UC_X86_REG_RCX,
        "rdx": x86.UC_X86_REG_RDX,
        "rbx": x86.UC_X86_REG_RBX,
        "rsp": x86.UC_X86_REG_RSP,
        "rbp": x86.UC_X86_REG_RBP,
        "rsi": x86.UC_X86_REG_RSI,
        "rdi": x86.UC_X86_REG_RDI,
        "r8": x86.UC_X86_REG_R8,
        "r9": x86.UC_X86_REG_R9,
        "r10": x86.UC_X86_REG_R10,
        "r11": x86.UC_X86_REG_R11,
        "r12": x86.UC_X86_REG_R12,
        "r13": x86.UC_X86_REG_R13,
        "r14": x86.UC_X86_REG_R14,
        "r15": x86.UC_X86_REG_R15,
        "rip": x86.UC_X86_REG_RIP,
        "eflags": x86.UC_X86_REG_EFLAGS,
    }
    if uc_mod is not None:
        mapping = {k: v for k, v in mapping.items()}
    return mapping


@dataclass
class EmuSnapshot:
    image: PEImage
    regs: dict[str, int] = field(default_factory=dict)
    stack: bytes | None = None
    stack_base: int | None = None
    extra_regions: list[tuple[int, int, str, bytes]] = field(default_factory=list)

    def state(self) -> dict:
        return {
            "base": hex(self.image.base),
            "entry": hex(self.regs.get("rip", self.image.entry)),
            "regs": {k: hex(v) for k, v in self.regs.items()},
            "stack_base": hex(self.stack_base) if self.stack_base else None,
            "stack_size": len(self.stack or b""),
            "extra_regions": [hex(base) for base, _size, _prot, _data in self.extra_regions],
        }


class Emulator:
    """Snapshot emulator with a small debugging surface."""

    def __init__(self, snapshot: EmuSnapshot, *, stack_size: int = 0x10000) -> None:
        uc_mod = _unicorn()
        self._uc_mod = uc_mod
        self.snapshot = snapshot
        self.bits = 64 if snapshot.image.is_64 else 32
        self.stack_size = stack_size
        mode = uc_mod.UC_MODE_64 if self.bits == 64 else uc_mod.UC_MODE_32
        self.uc = uc_mod.Uc(uc_mod.UC_ARCH_X86, mode)
        self._reg_ids = _register_ids(uc_mod)
        self._watchpoints: list[dict] = []
        self._hooks: list[dict] = []
        self._import_calls: list[dict] = []
        self._faults: list[dict] = []
        self._closed = False
        self._stub_slots: dict[int, dict] = {}
        self._stub_hook = None
        self._last_rip: int | None = None
        self._finished = False
        self._coverage: dict[int, int] = {}
        self._edges: dict[int, dict[int, int]] = {}
        self._cov_handle = None
        self._cov_limit = 200_000
        self._cov_overflow = 0
        self._steps = 0
        self._map_image()
        self._install_fault_hook()

    # -- mapping -----------------------------------------------------------
    def _map_image(self) -> None:
        uc = self.uc
        page = 0x1000
        base = self.snapshot.image.base
        size = (self.snapshot.image.size + page - 1) & ~(page - 1)
        uc.mem_map(base, size, self._uc_mod.UC_PROT_ALL)
        uc.mem_write(base, bytes(self.snapshot.image.image))
        for region_base, region_size, _prot, data in self.snapshot.extra_regions:
            self.map(region_base, max(region_size, len(data)), data=data)

        stack_base = self.snapshot.stack_base or (0x7FFF_0000_0000 if self.bits == 64 else 0x7FFF_0000)
        if self.snapshot.stack is not None:
            uc.mem_map(stack_base, max(self.stack_size, len(self.snapshot.stack)),
                       self._uc_mod.UC_PROT_ALL)
            uc.mem_write(stack_base, self.snapshot.stack)
        else:
            try:
                uc.mem_map(stack_base, self.stack_size, self._uc_mod.UC_PROT_ALL)
            except Exception:
                pass
            self.snapshot.stack_base = stack_base
            self.snapshot.stack = bytes(self.stack_size)

        rip = self.snapshot.regs.get("rip", self.snapshot.image.entry)
        rsp = self.snapshot.regs.get("rsp", stack_base + 0x8000)
        self.write_regs({"rip": rip, "rsp": rsp, **self.snapshot.regs})

    def map(self, base: int, size: int, *, data: bytes = b"", protection: int | None = None) -> None:
        prot = protection if protection is not None else self._uc_mod.UC_PROT_ALL
        aligned = size if size % 0x1000 == 0 else (size + 0xFFF) & ~0xFFF
        self.uc.mem_map(base, aligned, prot)
        if data:
            self.uc.mem_write(base, data[:aligned])

    def map_heap(self, base: int, size: int) -> None:
        """Map a zeroed region (a heap or scratch page)."""
        self.map(base, size)

    # -- registers ---------------------------------------------------------
    def read_regs(self, names: Iterable[str] | None = None) -> dict[str, int]:
        names = list(names or REGISTERS_X64)
        out: dict[str, int] = {}
        for name in names:
            reg_id = self._reg_ids.get(name.lower())
            if reg_id is None:
                raise InvalidArgument(f"unknown register: {name}")
            out[name.lower()] = int(self.uc.reg_read(reg_id))
        return out

    def write_regs(self, values: dict[str, int]) -> None:
        for name, value in values.items():
            reg_id = self._reg_ids.get(name.lower())
            if reg_id is None:
                raise InvalidArgument(f"unknown register: {name}")
            self.uc.reg_write(reg_id, int(value) & 0xFFFFFFFFFFFFFFFF)

    def read(self, va: int, size: int) -> bytes:
        return bytes(self.uc.mem_read(va, size))

    def write(self, va: int, data: bytes) -> None:
        self.uc.mem_write(va, bytes(data))

    def read_u64(self, va: int) -> int:
        return int.from_bytes(self.read(va, 8), "little")

    def read_u32(self, va: int) -> int:
        return int.from_bytes(self.read(va, 4), "little")

    def read_cstring(self, va: int, limit: int = 256) -> str:
        out = bytearray()
        for index in range(limit):
            byte = self.read(va + index, 1)[0]
            if byte == 0:
                break
            out.append(byte)
        return out.decode("utf-8", "replace")

    # -- faults ------------------------------------------------------------
    def _install_fault_hook(self) -> None:
        """Record the *first* bad access instead of surfacing a bare UcError.

        When emulating real code the interesting failure is almost always "it
        dereferenced a pointer that was not mapped here" — a heap object that was
        never captured, or an uninitialised field.  Unicorn raises ``UC_ERR_READ_UNMAPPED``
        and the call stack in the message is useless; this hook turns it into
        ``{rip, access, address}``, which is a concrete thing to go and snapshot.
        """
        mod = self._uc_mod

        def on_unmapped(uc, access, address, size, value, user):
            self._faults.append({
                "kind": "unmapped",
                "access": _ACCESS_NAMES.get(access, str(access)),
                "address": hex(address),
                "size": size,
                "value": hex(value) if isinstance(value, int) and value else None,
                "rip": hex(uc.reg_read(self._reg_ids["rip"])),
            })
            uc.emu_stop()

        def on_invalid(*args):
            uc = args[0] if args else self.uc
            try:
                rip = hex(uc.reg_read(self._reg_ids["rip"]))
            except Exception:
                rip = None
            self._faults.append({"kind": "invalid_instruction", "rip": rip})
            uc.emu_stop()

        try:
            self.uc.hook_add(mod.UC_HOOK_MEM_UNMAPPED, on_unmapped)
        except Exception:  # pragma: no cover - older unicorn builds
            for name in ("UC_HOOK_MEM_READ_UNMAPPED", "UC_HOOK_MEM_WRITE_UNMAPPED"):
                hook_type = getattr(mod, name, None)
                if hook_type is not None:
                    self.uc.hook_add(hook_type, on_unmapped)
        hook_type = getattr(mod, "UC_HOOK_INSN_INVALID", None)
        if hook_type is not None:
            try:
                self.uc.hook_add(hook_type, on_invalid)
            except Exception:
                pass

    def faults(self, *, limit: int = 20) -> list[dict]:
        """Bad accesses seen so far, oldest first."""
        return self._faults[:limit]

    # -- execution coverage ------------------------------------------------
    def start_trace(self, *, max_addresses: int = 200_000) -> dict:
        """Record every executed instruction and every taken edge.

        A hook per instruction is expensive (a Python call per step), so this is
        opt-in: enable it when the question is *which path did the code take*,
        not when you are running a million-instruction function for a value.
        """
        if self._cov_handle is not None:
            return {"tracing": True, "unique": len(self._coverage), "already": True}
        self._cov_limit = max(1000, int(max_addresses))
        mod = self._uc_mod

        def hook(uc, addr, size, user):
            self._steps += 1
            hits = self._coverage.get(addr)
            if hits is None:
                if len(self._coverage) < self._cov_limit:
                    self._coverage[addr] = 1
                else:
                    self._cov_overflow += 1
            else:
                self._coverage[addr] = hits + 1
            previous = self._last_rip
            if previous is not None:
                successors = self._edges.get(previous)
                if successors is None:
                    self._edges[previous] = {addr: 1}
                else:
                    successors[addr] = successors.get(addr, 0) + 1
            self._last_rip = addr

        self._cov_handle = self.uc.hook_add(mod.UC_HOOK_CODE, hook)
        self._last_rip = None
        return {"tracing": True, "max_addresses": self._cov_limit}

    def stop_trace(self) -> dict:
        if self._cov_handle is not None:
            try:
                self.uc.hook_del(self._cov_handle)
            except Exception:
                pass
            self._cov_handle = None
        return {"tracing": False, "unique": len(self._coverage), "steps": self._steps}

    def reset_trace(self) -> dict:
        self._coverage.clear()
        self._edges.clear()
        self._steps = 0
        self._cov_overflow = 0
        self._last_rip = None
        return {"reset": True, "tracing": self._cov_handle is not None}

    def close(self) -> dict:
        """Release the unicorn engine and every hook it holds.

        Unicorn keeps a native engine per instance; dropping the Python object
        defers that release to the cyclic collector, which can then run inside a
        later ``mem_map`` and fault there.  Closing deterministically — before
        creating the next emulator — keeps long analysis sessions stable.
        """
        self.stop_trace()
        try:
            self.uc.emu_stop()
        except Exception:
            pass
        self._coverage.clear()
        self._edges.clear()
        self._hooks.clear()
        self._watchpoints.clear()
        self._faults.clear()
        self._import_calls.clear()
        self._closed = True
        return {"closed": True}

    @property
    def closed(self) -> bool:
        return self._closed

    def __enter__(self) -> "Emulator":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def coverage(self, *, hot: int = 20 ) -> dict:
        """What actually ran: unique instructions, hot spots and branch forks.

        ``forks`` are addresses with more than one successor, which is exactly the
        set of branch decisions the run took.  That is the cheap answer to "did
        the check pass", "does it take the decrypt path", "which switch case ran".
        """
        forks = []
        for address, successors in self._edges.items():
            if len(successors) < 2:
                continue
            forks.append({
                "va": hex(address),
                "hits": sum(successors.values()),
                "successors": [
                    {"va": hex(target), "hits": hits}
                    for target, hits in sorted(successors.items(), key=lambda item: -item[1])
                ],
            })
        top = sorted(self._coverage.items(), key=lambda item: -item[1])[:hot]
        executed = sorted(self._coverage)
        return {
            "tracing": self._cov_handle is not None,
            "steps": self._steps,
            "unique_instructions": len(self._coverage),
            "edges": sum(len(successors) for successors in self._edges.values()),
            "truncated": self._cov_overflow > 0,
            "overflow_visits": self._cov_overflow,
            "executed": [hex(va) for va in executed[:4096]],
            "executed_truncated": len(executed) > 4096,
            "hot": [{"va": hex(va), "hits": hits} for va, hits in top],
            "forks": forks[:hot * 4],
        }

    def reached(self, addresses: Iterable[int]) -> dict:
        """Split a list of addresses into those executed and those not.

        The everyday use is "which of these handlers was hit", or confirming that
        a decryption routine was never reached with the arguments you supplied.
        """
        wanted = [int(address) for address in addresses]
        hit = [hex(address) for address in wanted if address in self._coverage]
        missed = [hex(address) for address in wanted if address not in self._coverage]
        return {"tracing": self._cov_handle is not None, "reached": hit, "not_reached": missed,
                "count_reached": len(hit), "count_missed": len(missed)}

    # -- control -----------------------------------------------------------
    def step(self, count: int = 1) -> dict:
        start = self.read_regs(["rip"])["rip"]
        self.uc.emu_start(start, 0, count=max(1, int(count)))
        rip = self.read_regs(["rip"])["rip"]
        return {"from": hex(start), "to": hex(rip), "regs": {k: hex(v) for k, v in self.read_regs().items()}}

    def _run_with_stop(self, stop_at: int | None, *, max_steps: int,
                       timeout_us: int = 0) -> tuple[str, bool]:
        """Run, stopping at ``stop_at`` via a one-shot code hook.

        Unicorn's own ``until`` argument is not used: it misbehaves once an
        earlier ``emu_start`` has stopped at an address below the current one
        (which is exactly what a return-trap call does), making the next
        ``until`` silently ineffective.  A temporary hook is predictable.
        """
        hit = {"value": False}
        handle = None
        faults_before = len(self._faults)
        if stop_at is not None:
            def hook(uc, addr, size, user):
                hit["value"] = True
                uc.emu_stop()

            handle = self.uc.hook_add(self._uc_mod.UC_HOOK_CODE, hook,
                                      begin=int(stop_at), end=int(stop_at))
        try:
            self.uc.emu_start(self.read_regs(["rip"])["rip"], 0,
                              timeout=max(0, int(timeout_us)), count=int(max_steps))
            reason = "reached_target" if hit["value"] else "budget_exhausted"
        except Exception as exc:  # unicorn raises UcError on unmapped fetch etc.
            reason = f"stopped: {exc}"
        finally:
            if handle is not None:
                try:
                    self.uc.hook_del(handle)
                except Exception:
                    pass
        # A fault hook stops the run cleanly, so a fault would otherwise be
        # reported as "budget_exhausted".  Name it instead.
        if len(self._faults) > faults_before:
            fault = self._faults[-1]
            if fault.get("kind") == "unmapped":
                reason = f"fault: unmapped {fault['access']} at {fault['address']} (rip {fault['rip']})"
            else:
                reason = f"fault: {fault.get('kind')} (rip {fault.get('rip')})"
        return reason, hit["value"]

    def run_until(self, address: int, *, max_steps: int = 200_000, timeout_us: int = 0) -> dict:
        start = self.read_regs(["rip"])["rip"]
        reason, _hit = self._run_with_stop(int(address), max_steps=max_steps,
                                           timeout_us=timeout_us)
        rip = self.read_regs(["rip"])["rip"]
        return {"from": hex(start), "to": hex(rip), "reason": reason,
                "regs": {k: hex(v) for k, v in self.read_regs().items()}}

    def run(self, *, max_steps: int = MAX_STEPS) -> dict:
        start = self.read_regs(["rip"])["rip"]
        reason, _hit = self._run_with_stop(None, max_steps=max_steps)
        rip = self.read_regs(["rip"])["rip"]
        return {"from": hex(start), "to": hex(rip), "reason": reason,
                "regs": {k: hex(v) for k, v in self.read_regs().items()}}

    def breakpoint(self, address: int) -> None:
        """Stop when execution reaches ``address`` (simulated breakpoint)."""
        def hook(uc, addr, size, user):
            uc.emu_stop()

        self.uc.hook_add(self._uc_mod.UC_HOOK_CODE, hook,
                         begin=int(address), end=int(address))
        self._hooks.append({"kind": "breakpoint", "address": address})

    def hook_call(self, address: int, callback: Callable[["Emulator"], None],
                  *, stop: bool = False) -> None:
        """Call ``callback`` when execution reaches ``address``.

        This is the "import stub" mechanism: hook ``kernel32!VirtualProtect``
        to log its arguments and continue, or to force a return value.
        """
        def hook(uc, addr, size, user):
            if stop:
                uc.emu_stop()
            callback(self)

        self.uc.hook_add(self._uc_mod.UC_HOOK_CODE, hook, begin=int(address), end=int(address))
        self._hooks.append({"kind": "call", "address": address})

    def watchpoint(self, address: int, kind: str = "write", *, size: int = 8,
                   limit: int = 100) -> None:
        """Record accesses to a memory range (read / write / any)."""
        kind = kind.lower()
        if kind in ("write", "w"):
            hook_type = self._uc_mod.UC_HOOK_MEM_WRITE
        elif kind in ("read", "r"):
            hook_type = self._uc_mod.UC_HOOK_MEM_READ
        else:
            hook_type = self._uc_mod.UC_HOOK_MEM_READ | self._uc_mod.UC_HOOK_MEM_WRITE

        write_access = {
            self._uc_mod.UC_MEM_WRITE,
            self._uc_mod.UC_MEM_WRITE_UNMAPPED,
        }

        def hook(uc, access, addr, length, value, user):
            self._watchpoints.append(
                {
                    "va": hex(addr),
                    "length": length,
                    "value": hex(value) if value else None,
                    "rip": hex(uc.reg_read(self._reg_ids["rip"])),
                    "access": "write" if access in write_access else "read",
                }
            )
            if len(self._watchpoints) >= limit:
                uc.emu_stop()

        self.uc.hook_add(hook_type, hook, begin=int(address), end=int(address) + max(1, size) - 1)

    def watchpoints(self, *, limit: int = 200) -> list[dict]:
        return self._watchpoints[:limit]

    def hooks(self) -> list[dict]:
        return list(self._hooks)

    # -- import stubs ------------------------------------------------------
    def install_import_stubs(self, *, returns: dict[str, int] | None = None,
                             default: int = 0, log: bool = True) -> dict:
        """Make calls to imported functions return instead of faulting.

        A snapshot contains the image, not the module the image was linked
        against: its code is the target's, so ``call qword ptr [rip+iat]`` lands
        on an address that is not mapped here.  Overwriting the *IAT slot* with
        the address of a generated ``mov eax, imm; ret`` stub turns that fault
        into a normal return, and the code under analysis keeps running.

        ``returns`` keys are ``module!name``, bare ``name`` or an IAT slot
        address (hex string or int); unlisted imports return ``default``.  Every
        hit is recorded for :meth:`import_calls` with the argument registers.
        """
        image = self.snapshot.image
        slots = {
            int(imp.iat_va): f"{imp.module}!{imp.name or '#' + str(imp.ordinal)}"
            for imp in image.imports
            if imp.iat_va
        }
        if not slots:
            return {"installed": 0, "reason": "image has no import table"}

        wanted = dict(returns or {})
        page, per_slot = self._stub_page(), 0x20
        page_size = ((len(slots) * per_slot) + 0xFFF) & ~0xFFF
        try:
            self.uc.mem_map(page, page_size, self._uc_mod.UC_PROT_ALL)
        except Exception:
            pass  # a second call reuses the page
        self._stub_page_base = page
        self._stub_slots: dict[int, dict] = {}

        index = 0
        for slot, api in slots.items():
            stub = page + index * per_slot
            index += 1
            value = self._stub_return_value(api, slot, wanted, default)
            self._write_stub(stub, value)
            self._stub_slots[stub] = {"api": api, "slot": slot, "returns": value}
            self.write(slot, stub.to_bytes(8 if self.bits == 64 else 4, "little", signed=False))

        if log and self._stub_slots:
            lower = min(self._stub_slots)
            upper = max(self._stub_slots) + per_slot - 1

            def hook(uc, addr, size, user):
                # Only the stub's first instruction counts: the `ret` that follows
                # it is inside the same page range and must not log twice.
                entry = self._stub_slots.get(addr)
                if entry is not None:
                    args = self._stub_args()
                    self._import_calls.append({
                        "api": entry["api"],
                        "slot": hex(entry["slot"]),
                        "returns": hex(entry["returns"]),
                        "args": [hex(arg) for arg in args],
                    })

            self._stub_hook = self.uc.hook_add(self._uc_mod.UC_HOOK_CODE, hook,
                                               begin=lower, end=upper)

        return {
            "installed": len(self._stub_slots),
            "page": hex(page),
            "default_return": hex(default),
            "stubs": [
                {"api": info["api"], "slot": hex(info["slot"]), "stub": hex(stub),
                 "returns": hex(info["returns"])}
                for stub, info in sorted(self._stub_slots.items())
            ],
        }

    def _stub_return_value(self, api: str, slot: int, wanted: dict, default: int) -> int:
        short = api.split("!", 1)[-1]
        keys = (api, short, hex(slot), str(slot))
        for key in keys:
            if key in wanted:
                try:
                    return int(wanted[key]) & 0xFFFFFFFFFFFFFFFF
                except (TypeError, ValueError):
                    continue
        for key, value in wanted.items():
            try:
                if int(key, 0) == slot:
                    return int(value) & 0xFFFFFFFFFFFFFFFF
            except (TypeError, ValueError):
                continue
        return int(default) & 0xFFFFFFFFFFFFFFFF

    def _write_stub(self, address: int, value: int) -> None:
        if self.bits == 64:
            if value <= 0xFFFFFFFF:
                code = b"\xb8" + int(value).to_bytes(4, "little") + b"\xc3"
            else:
                code = b"\x48\xb8" + int(value).to_bytes(8, "little") + b"\xc3"
        else:
            code = b"\xb8" + (int(value) & 0xFFFFFFFF).to_bytes(4, "little") + b"\xc3"
        self.write(address, code + b"\xcc" * (0x20 - len(code)))

    def _stub_args(self) -> list[int]:
        names = ("rcx", "rdx", "r8", "r9") if self.bits == 64 else ()
        if not names:
            return []
        values = self.read_regs(list(names))
        return [values[name] for name in names]

    def _stub_page(self) -> int:
        candidates = ((0x6000_0000_0000, 0x6100_0000_0000, 0x6200_0000_0000)
                      if self.bits == 64 else (0x6000_0000, 0x6100_0000, 0x6200_0000))
        occupied = [(self.snapshot.image.base, self.snapshot.image.size)]
        occupied += [(start, max(size, len(data))) for start, size, _p, data in self.snapshot.extra_regions]
        for base in candidates:
            if not any(start <= base < start + max(size, 0x1000) for start, size in occupied):
                return base
        raise InvalidArgument("no free page for the import stubs")

    def import_calls(self, *, limit: int = 200) -> list[dict]:
        """Recorded import-stub hits, oldest first."""
        return self._import_calls[:limit]

    def stubs(self) -> list[dict]:
        return [
            {"api": info["api"], "slot": hex(info["slot"]), "stub": hex(stub),
             "returns": hex(info["returns"])}
            for stub, info in sorted(getattr(self, "_stub_slots", {}).items())
        ]

    # -- convenience -------------------------------------------------------
    def _trap_page(self) -> int:
        """A mapped, never-executed page used as the return address."""
        candidates = (0x5EAD_0000, 0x5EAE_0000, 0x5EAF_0000, 0x5EB0_0000)
        image_start = self.snapshot.image.base
        image_end = image_start + self.snapshot.image.size
        for base in candidates:
            if image_start <= base < image_end:
                continue
            if any(start <= base < start + max(size, 0x1000)
                   for start, size, _prot, _data in self.snapshot.extra_regions):
                continue
            return base
        raise InvalidArgument("no free page for the emulator return trap")

    def call(self, address: int, args: Iterable[int] = (), *, max_steps: int = 200_000) -> dict:
        """Call a function and run it until it returns.

        The return address points at a mapped trap page, so execution stops
        cleanly with ``reason == "returned"`` instead of faulting on an
        unmapped fetch.
        """
        data = list(args)
        trap = self._trap_page()
        if getattr(self, "_mapped_trap", None) != trap:
            try:
                self.uc.mem_map(trap, 0x1000, self._uc_mod.UC_PROT_ALL)
            except Exception:
                pass  # already mapped (a previous call on this emulator)
            self.uc.mem_write(trap, b"\xcc" * 0x10)
            self._mapped_trap = trap

        stack_pointer = self.read_regs(["rsp"])["rsp"] - 0x20
        if self.bits == 64:
            arg_regs = ["rcx", "rdx", "r8", "r9"]
            values = {"rax": 0, "rip": int(address), "rsp": stack_pointer}
            for index, value in enumerate(data[:4]):
                values[arg_regs[index]] = int(value)
            for index, value in enumerate(data[4:], start=4):
                self.write(stack_pointer + 0x28 + (index - 4) * 8,
                           int(value).to_bytes(8, "little"))
            self.write(stack_pointer, trap.to_bytes(8, "little"))
            self.write_regs(values)
        else:
            values = {"rip": int(address), "rsp": stack_pointer}
            for index, value in enumerate(data):
                self.write(stack_pointer + 4 + index * 4, int(value).to_bytes(4, "little"))
            self.write(stack_pointer, trap.to_bytes(4, "little"))
            self.write_regs(values)

        result = self.run_until(trap, max_steps=max_steps)
        returned = int(result["to"], 16) == trap
        if returned:
            result["reason"] = "returned"
            result["return_address"] = hex(trap)
        elif self._faults:
            result["fault"] = self._faults[-1]
        return {"retval": hex(self.read_regs(["rax"])["rax"]), **result}

    def dump_stack(self, length: int = 0x80) -> list[str]:
        rsp = self.read_regs(["rsp"])["rsp"]
        data = self.read(rsp, length)
        return [data[i : i + 8].hex() for i in range(0, len(data), 8)]


def emulator_for(image: PEImage, *, regs: dict[str, int] | None = None,
                 stack: bytes | None = None, stack_base: int | None = None,
                 extra_regions: list[tuple[int, int, str, bytes]] | None = None,
                 stack_size: int = 0x10000, auto_stubs: bool = False,
                 trace: bool = False) -> Emulator:
    """Create an :class:`Emulator` for a loaded image.

    ``auto_stubs`` installs an import stub for every IAT slot up front (see
    :meth:`Emulator.install_import_stubs`), which is what makes calling a real
    function that talks to the OS return instead of faulting.  ``trace`` starts
    instruction/edge recording immediately (see :meth:`Emulator.start_trace`).
    """
    snapshot = EmuSnapshot(
        image=image,
        regs=dict(regs or {}),
        stack=stack,
        stack_base=stack_base,
        extra_regions=list(extra_regions or []),
    )
    emulator = Emulator(snapshot, stack_size=int(stack_size))
    if auto_stubs:
        emulator.install_import_stubs()
    if trace:
        emulator.start_trace()
    return emulator


def emulator_available() -> bool:
    try:
        _unicorn()
        return True
    except Unavailable:
        return False
