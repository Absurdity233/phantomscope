"""x86-64 page-table walking.

A DMA device reads physical memory, so reaching a virtual address means
reproducing what the target CPU does: follow CR3 → PML4 → PDPT → PD → PT.
That is the whole job of this module, and it is the step that makes a physical
dump usable as a normal address space.

Supports:

* 4-level paging (48-bit VA, the default) and 5-level paging (57-bit, LA57),
* 4 KiB, 2 MiB and 1 GiB pages,
* the present bit, so a caller can distinguish "unmapped" from "zeros".

It does **not** implement SMEP/SMAP, PCID tags or the PCID/CR3 high bits beyond
masking them off, because none of that changes the translation result.
"""

from __future__ import annotations

from ..errors import InvalidArgument
from .image import PhysicalImage

PAGE = 0x1000
PTE_ADDR_MASK = 0x000F_FFFF_FFFF_F000  # bits 12..51 of a 4-level PTE
PAGE_PRESENT = 1 << 0
PAGE_LARGE = 1 << 7


class X64Pager:
    """Translate and read virtual addresses through a CR3."""

    def __init__(self, image: PhysicalImage, cr3: int, *, levels: int = 4,
                 user: bool = True) -> None:
        if levels not in (4, 5):
            raise InvalidArgument("paging levels must be 4 or 5")
        if cr3 <= 0:
            raise InvalidArgument(f"invalid CR3 {cr3:#x}")
        self.image = image
        self.cr3 = int(cr3) & PTE_ADDR_MASK
        self.levels = levels
        self.user = user  # when False, require the process to be in kernel mode

    # -- index extraction --------------------------------------------------
    def _indices(self, va: int) -> tuple[int, int, int, int, int | None]:
        pml5 = (va >> 48) & 0x1FF
        pml4 = (va >> 39) & 0x1FF
        pdpt = (va >> 30) & 0x1FF
        pd = (va >> 21) & 0x1FF
        pt = (va >> 12) & 0x1FF
        return (pml5 if self.levels == 5 else 0), pml4, pdpt, pd, pt

    @staticmethod
    def _flags_ok(entry: int, user: bool) -> bool:
        if not entry & PAGE_PRESENT:
            return False
        # Bit 2 is the user/supervisor bit.  In kernel mode both are valid.
        return True if not user else bool(entry & (1 << 2))

    # -- translation -------------------------------------------------------
    def translate(self, va: int) -> int | None:
        """Return the physical address backing ``va``, or ``None`` if unmapped."""
        va = int(va) & 0xFFFF_FFFF_FFFF_FFFF
        pml5, pml4, pdpt, pd, pt = self._indices(va)

        table = self.cr3
        if self.levels == 5:
            entry = self.image.read_u64(table + pml5 * 8)
            if not self._flags_ok(entry, self.user):
                return None
            table = entry & PTE_ADDR_MASK

        entry = self.image.read_u64(table + pml4 * 8)
        if not self._flags_ok(entry, self.user):
            return None
        table = entry & PTE_ADDR_MASK

        entry = self.image.read_u64(table + pdpt * 8)
        if not self._flags_ok(entry, self.user):
            return None
        if entry & PAGE_LARGE:
            return (entry & PTE_ADDR_MASK & ~0x3FFF_FFFF) | (va & 0x3FFF_FFFF)
        table = entry & PTE_ADDR_MASK

        entry = self.image.read_u64(table + pd * 8)
        if not self._flags_ok(entry, self.user):
            return None
        if entry & PAGE_LARGE:
            return (entry & PTE_ADDR_MASK & ~0x1F_FFFF) | (va & 0x1F_FFFF)
        table = entry & PTE_ADDR_MASK

        entry = self.image.read_u64(table + pt * 8)
        if not self._flags_ok(entry, self.user):
            return None
        return (entry & PTE_ADDR_MASK) | (va & 0xFFF)

    def is_present(self, va: int) -> bool:
        return self.translate(va) is not None

    # -- reads -------------------------------------------------------------
    def read(self, va: int, size: int, *, strict: bool = True) -> bytes:
        """Read ``size`` bytes of virtual memory, page by page.

        With ``strict`` (the default) an unmapped page raises instead of
        returning zeros, so a caller never mistakes a hole for data.
        """
        if size < 0:
            raise InvalidArgument("negative read size")
        out = bytearray()
        cursor = int(va)
        remaining = int(size)
        while remaining > 0:
            pa = self.translate(cursor)
            if pa is None:
                if strict:
                    raise InvalidArgument(
                        f"virtual address {cursor:#x} is not mapped in CR3 {self.cr3:#x}"
                    )
                out += bytes(min(remaining, PAGE - (cursor & 0xFFF)))
                step = min(remaining, PAGE - (cursor & 0xFFF))
                cursor += step
                remaining -= step
                continue
            step = min(remaining, PAGE - (cursor & 0xFFF))
            out += self.image.read(pa, step)
            cursor += step
            remaining -= step
        return bytes(out)

    def read_u64(self, va: int) -> int:
        return int.from_bytes(self.read(va, 8), "little")

    def read_u32(self, va: int) -> int:
        return int.from_bytes(self.read(va, 4), "little")

    def read_cstring(self, va: int, limit: int = 256) -> str:
        out = bytearray()
        for index in range(limit):
            char = self.read(va + index, 1, strict=False)
            if not char or char[0] == 0:
                break
            out.append(char[0])
        return out.decode("utf-8", "replace")

    # -- enumeration -------------------------------------------------------
    def walk_range(self, start: int, size: int, *, step: int = 0x1000,
                   limit: int = 4096) -> list[dict]:
        """Translate a range and report which pages are present.

        This is the cheapest way to sketch a process's address space with no OS
        structures: a 4 KiB stride over a region tells you exactly where the
        holes are.
        """
        out: list[dict] = []
        for offset in range(0, size, step):
            va = start + offset
            pa = self.translate(va)
            if pa is None:
                continue
            out.append({"va": hex(va), "pa": hex(pa)})
            if len(out) >= limit:
                break
        return out

    def describe(self) -> dict:
        return {
            "cr3": hex(self.cr3),
            "levels": self.levels,
            "user_only": self.user,
        }
