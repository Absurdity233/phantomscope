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
        self._last_rip: int | None = None
        self._finished = False
        self._map_image()

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

    # -- control -----------------------------------------------------------
    def step(self, count: int = 1) -> dict:
        start = self.read_regs(["rip"])["rip"]
        self.uc.emu_start(start, 0, count=max(1, int(count)))
        rip = self.read_regs(["rip"])["rip"]
        return {"from": hex(start), "to": hex(rip), "regs": {k: hex(v) for k, v in self.read_regs().items()}}

    def run_until(self, address: int, *, max_steps: int = 200_000, timeout_us: int = 0) -> dict:
        start = self.read_regs(["rip"])["rip"]
        try:
            self.uc.emu_start(start, int(address), timeout=max(0, int(timeout_us)),
                              count=int(max_steps))
            reason = "reached_target"
        except Exception as exc:  # unicorn raises UcError on unmapped fetch etc.
            reason = f"stopped: {exc}"
        rip = self.read_regs(["rip"])["rip"]
        return {"from": hex(start), "to": hex(rip), "reason": reason,
                "regs": {k: hex(v) for k, v in self.read_regs().items()}}

    def run(self, *, max_steps: int = MAX_STEPS) -> dict:
        start = self.read_regs(["rip"])["rip"]
        try:
            self.uc.emu_start(start, 0, count=int(max_steps))
            reason = "budget_exhausted"
        except Exception as exc:
            reason = f"stopped: {exc}"
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

    # -- convenience -------------------------------------------------------
    def call(self, address: int, args: Iterable[int] = (), *, max_steps: int = 200_000) -> dict:
        """Set up a SysV-ish/Microsoft x64 call and run it until it returns."""
        data = list(args)
        stack_pointer = self.read_regs(["rsp"])["rsp"] - 0x20
        if self.bits == 64:
            arg_regs = ["rcx", "rdx", "r8", "r9"]
            values = {"rax": 0, "rip": int(address), "rsp": stack_pointer}
            for index, value in enumerate(data[:4]):
                values[arg_regs[index]] = int(value)
            for index, value in enumerate(data[4:], start=4):
                self.write(stack_pointer + 0x28 + (index - 4) * 8,
                           int(value).to_bytes(8, "little"))
            self.write(stack_pointer, (self.snapshot.image.base + 0xDEAD).to_bytes(8, "little"))
            self.write_regs(values)
        else:
            values = {"rip": int(address), "rsp": stack_pointer}
            for index, value in enumerate(data):
                self.write(stack_pointer + 4 + index * 4, int(value).to_bytes(4, "little"))
            self.write_regs(values)
        result = self.run_until(0, max_steps=max_steps)
        return {"retval": hex(self.read_regs(["rax"])["rax"]), **result}

    def dump_stack(self, length: int = 0x80) -> list[str]:
        rsp = self.read_regs(["rsp"])["rsp"]
        data = self.read(rsp, length)
        return [data[i : i + 8].hex() for i in range(0, len(data), 8)]


def emulator_for(image: PEImage, *, regs: dict[str, int] | None = None,
                 stack: bytes | None = None, stack_base: int | None = None,
                 extra_regions: list[tuple[int, int, str, bytes]] | None = None) -> Emulator:
    """Create an :class:`Emulator` for a loaded image."""
    snapshot = EmuSnapshot(
        image=image,
        regs=dict(regs or {}),
        stack=stack,
        stack_base=stack_base,
        extra_regions=list(extra_regions or []),
    )
    return Emulator(snapshot)


def emulator_available() -> bool:
    try:
        _unicorn()
        return True
    except Unavailable:
        return False
