"""A :class:`MemoryBackend` over raw physical memory.

This is the DMA-native backend: it exposes exactly what a device can do —
address arbitrary physical memory — and nothing an operating system would
normally supply.  Nothing here reads a process list or a module list; those are
reconstructed, when possible, by the code above it.

Addressing convention
---------------------
The generic :meth:`read` / :meth:`write` take a ``pid`` that this backend reads
as follows:

``pid == 0``
    ``va`` is a **physical** address.  No page tables involved.
``pid != 0``
    ``pid`` is a **CR3** (directory-table base), so ``va`` is a virtual address
    translated through that address space.

The explicit methods (:meth:`read_physical`, :meth:`read_virtual`) are the
preferred interface; the convention exists so the backend still satisfies the
shared contract and can be used with the rest of the toolkit.
"""

from __future__ import annotations

from typing import Iterable

from ..backend import Capabilities, MemoryBackend
from ..errors import BackendError, InvalidArgument, Unavailable
from ..models import ModuleInfo, ProcessInfo, Region
from .image import PAGE, PhysicalImage, parse_memmap
from .paging import X64Pager
from .pescan import PEImageHit, read_image_bytes, scan_pe_images


class PhysicalBackend(MemoryBackend):
    """Read/write a raw physical memory image, with optional paging support."""

    kind = "physical"
    caps = Capabilities(
        processes=False,
        modules=False,
        regions=False,
        threads=False,
        callstack=False,
        kernel=False,
        symbols=False,
        write=True,
        physical=True,
        handles=False,
        heaps=False,
    )

    def __init__(self, device: str = "", options: Iterable[str] | None = None,
                 *, name: str = "physical", memmap: str | None = None) -> None:
        super().__init__(name)
        self.device = device
        self.options = [str(o) for o in (options or [])]
        self.memmap = memmap or self._memmap_from_options()
        self.image: PhysicalImage | None = None
        self.bits = 64
        self.cr3: int | None = None
        self._pager: X64Pager | None = None
        self._image_cache: list[PEImageHit] | None = None

    # -- construction ------------------------------------------------------
    def _memmap_from_options(self) -> str | None:
        """Accept ``memmap=...`` either as an option or as ``device?memmap=``."""
        for option in self.options:
            text = str(option).strip()
            if text.startswith("memmap="):
                return text.split("=", 1)[1]
            if text.startswith("-memmap="):
                return text.split("=", 1)[1]
        if "?memmap=" in self.device:
            return self.device.split("?memmap=", 1)[1]
        return None

    def open(self) -> None:
        if self.is_open:
            return
        path = self.device.split("?", 1)[0]
        if not path:
            raise InvalidArgument(
                "the physical backend needs a dump path, e.g. "
                "session_open(backend='physical', device='C:/dumps/win10.raw')"
            )
        segments = parse_memmap(self.memmap) if self.memmap else []
        try:
            self.image = PhysicalImage(path, segments or None)
        except BackendError:
            raise
        except Exception as exc:  # pragma: no cover - filesystem edge cases
            raise BackendError(f"cannot open physical image {path!r}: {exc}") from exc
        self.device = self.image.path
        self._open = True

    def close(self) -> None:
        if self.image is not None:
            self.image.close()
        self.image = None
        self._open = False
        self._pager = None
        self._image_cache = None
        self.cr3 = None

    def _require(self) -> PhysicalImage:
        self.require_open()
        if self.image is None:  # pragma: no cover - defensive
            raise BackendError("physical image is not open")
        return self.image

    def info(self) -> dict:
        image = self._require()
        out = image.info()
        out.update({"kind": self.kind, "device": self.device, "bits": self.bits})
        if self.cr3 is not None:
            out["cr3"] = hex(self.cr3)
        if self._image_cache is not None:
            out["pe_images_cached"] = len(self._image_cache)
        return out

    # -- addressing --------------------------------------------------------
    def set_cr3(self, cr3: int) -> None:
        """Select the address space used by :meth:`read_virtual`."""
        if cr3 <= 0:
            raise InvalidArgument("CR3 must be positive")
        self.cr3 = int(cr3)
        self._pager = None

    def pager(self, cr3: int | None = None, *, levels: int = 4,
              user: bool = True) -> X64Pager:
        base = int(cr3 if cr3 is not None else (self.cr3 or 0))
        if base <= 0:
            raise InvalidArgument(
                "no CR3 selected; pass cr3=... or set one with a prior translate"
            )
        if cr3 is None and self._pager is not None:
            return self._pager
        pager = X64Pager(self._require(), base, levels=levels, user=user)
        if cr3 is None:
            self._pager = pager
        return pager

    # -- physical IO -------------------------------------------------------
    def read_physical(self, pa: int, size: int) -> bytes:
        return self._require().read(int(pa), int(size))

    def write_physical(self, pa: int, data: bytes) -> int:
        return self._require().write(int(pa), bytes(data))

    def physical_map(self) -> list[Region]:
        image = self._require()
        return [
            Region(base=base, size=size, protection="rw-", tag="PHYS", kind="physical")
            for base, size in image.map()
        ]

    # -- virtual IO --------------------------------------------------------
    def translate(self, va: int, *, cr3: int | None = None, levels: int = 4,
                  user: bool = True) -> int | None:
        return self.pager(cr3, levels=levels, user=user).translate(int(va))

    def read_virtual(self, va: int, size: int, *, cr3: int | None = None,
                     levels: int = 4, user: bool = True, strict: bool = True) -> bytes:
        return self.pager(cr3, levels=levels, user=user).read(int(va), int(size), strict=strict)

    def write_virtual(self, va: int, data: bytes, *, cr3: int | None = None,
                      levels: int = 4, user: bool = True) -> int:
        """Write virtual memory, page by page, refusing unmapped pages."""
        pager = self.pager(cr3, levels=levels, user=user)
        payload = bytes(data)
        written = 0
        while written < len(payload):
            current = int(va) + written
            pa = pager.translate(current)
            if pa is None:
                raise BackendError(f"virtual address {current:#x} is not mapped")
            step = min(len(payload) - written, PAGE - (current & 0xFFF))
            self.write_physical(pa, payload[written : written + step])
            written += step
        return written

    def walk(self, va: int, size: int, *, cr3: int | None = None, levels: int = 4,
             step: int = PAGE, limit: int = 4096) -> list[dict]:
        return self.pager(cr3, levels=levels).walk_range(int(va), int(size), step=step, limit=limit)

    # -- structure discovery ----------------------------------------------
    def images(self, *, refresh: bool = False, limit: int = 500,
               min_size: int = PAGE, max_size: int = 0x80_0000) -> list[PEImageHit]:
        """Structurally scan the dump for PE images (cached)."""
        if self._image_cache is None or refresh:
            self._image_cache = scan_pe_images(
                self._require(), limit=limit, min_size=min_size, max_size=max_size
            )
        return self._image_cache[:limit]

    def capture_image(self, pa: int, *, size: int | None = None,
                      base_va: int | None = None) -> tuple[bytes, int, PEImageHit]:
        """Return ``(image_bytes, base_va, hit)`` for a PE at physical ``pa``.

        The bytes come back exactly as laid out in memory (RVA-indexed), and the
        returned base is the address the image *thinks* it is loaded at — the
        PE ``ImageBase`` from its header, unless ``base_va`` overrides it.  Using
        the physical address as the base would be wrong: RVA-addressed analysis
        would then report addresses that no page table can translate.
        """
        image = self._require()
        hit = next((h for h in self.images() if h.pa == int(pa)), None)
        if hit is None:
            blob = image.read(int(pa), 0x1000)
            from .pescan import _parse  # local import keeps the fast path cheap

            hit = _parse(blob, int(pa), min_size=PAGE, max_size=0x80_0000)
            if hit is None:
                raise InvalidArgument(f"no valid PE image header at physical {pa:#x}")
        length = int(size) if size else hit.size
        base = int(base_va) if base_va else hit.image_base_va or hit.pa
        return image.read(hit.pa, length), base, hit

    # -- MemoryBackend contract -------------------------------------------
    def list_processes(self) -> list[ProcessInfo]:
        raise Unavailable(
            "a physical memory image has no process list; use "
            "`translate`/`read_virtual` with a CR3, or open the dump through the "
            "memprocfs backend for OS-level views"
        )

    def read(self, pid: int, va: int, size: int) -> bytes:
        if int(pid) == 0:
            return self.read_physical(int(va), int(size))
        return self.read_virtual(int(va), int(size), cr3=int(pid))

    def write(self, pid: int, va: int, data: bytes) -> int:
        if int(pid) == 0:
            return self.write_physical(int(va), bytes(data))
        return self.write_virtual(int(va), bytes(data), cr3=int(pid))

    def list_modules(self, pid: int) -> list[ModuleInfo]:
        """Physical addressing has no module list; report discovered images.

        The result is a *scan*, not an OS module list: names are absent, and a
        hit may be a driver or an embedded payload rather than a loaded module.
        """
        return [
            ModuleInfo(name=f"image_{hit.pa:x}", base=hit.pa, size=hit.size, file_size=hit.size)
            for hit in self.images(limit=256)
        ]

    def resolve_symbol(self, pid: int, module: str, name: str) -> int | None:
        return None

    # -- scanning ----------------------------------------------------------
    def scan(self, pattern: str, *, limit: int = 200, start: int | None = None,
             size: int | None = None, chunk: int = 4 * 1024 * 1024,
             max_bytes: int = 512 * 1024 * 1024) -> list[dict]:
        """AOB-scan physical memory, returning physical addresses.

        Matches never straddle a read chunk, so the caller gets exact physical
        addresses; wildcards (``??``) are supported.  ``max_bytes`` bounds the
        total work so a huge dump cannot hang a session.
        """
        from ..analysis.scan import parse_pattern, scan_bytes

        try:
            tokens = parse_pattern(pattern)
        except ValueError as exc:
            raise InvalidArgument(str(exc)) from exc
        if not tokens:
            raise InvalidArgument(f"empty pattern: {pattern!r}")
        image = self._require()
        hits: list[dict] = []
        examined = 0
        overlap = max(0, len(tokens) - 1)

        for segment in image.segments:
            begin = segment.pa if start is None else max(segment.pa, int(start))
            end = segment.end if size is None else min(
                segment.end, int(start if start is not None else segment.pa) + int(size)
            )
            if begin >= end:
                continue
            # Only matches that start at or after ``floor`` are new: earlier
            # ones were already found by the previous chunk's tail.
            floor = begin
            offset = begin
            while offset < end and examined < max_bytes:
                length = min(chunk, end - offset)
                data = image.read(offset, length)
                examined += length
                for hit in scan_bytes(data, tokens, base=offset,
                                      limit=max(1, limit - len(hits))):
                    if hit >= floor:
                        hits.append({"pa": hit, "hex": hex(hit)})
                        if len(hits) >= limit:
                            return hits
                floor = offset + max(1, length - overlap)
                offset = floor
        return hits
