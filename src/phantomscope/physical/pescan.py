"""Find PE images in a physical dump without any OS help.

Over DMA you often have no module list: the kernel has not told you where
``ntoskrnl.exe`` is, and there may not even *be* a running kernel (pre-boot,
hibernation, a corrupted dump).  A PE header is a strong enough signal to find
images structurally.

The scan is deliberately conservative — page-aligned ``MZ``, a sane
``e_lfanew``, a valid ``PE\\0\\0`` signature, a known machine type and a
``SizeOfImage`` that fits the dump.  False positives are possible but rare, and
each hit carries the evidence (machine, subsystem, timestamp) needed to judge
it.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .image import PhysicalImage

MACHINES = {
    0x014C: "x86",
    0x8664: "x64",
    0xAA64: "arm64",
    0x01C4: "arm",
}

SUBSYSTEMS = {
    1: "native",
    2: "windows_gui",
    3: "windows_cui",
    9: "windows_ce",
    10: "efi_application",
    11: "efi_boot_service_driver",
    12: "efi_runtime_driver",
    13: "efi_rom",
}

PAGE = 0x1000


@dataclass
class PEImageHit:
    """A structurally valid PE image found at a physical address."""

    pa: int
    size: int
    machine: int
    arch: str
    timestamp: int
    subsystem: str | None
    sections: int
    characteristics: int
    entry_rva: int
    image_base_va: int
    magic: int

    @property
    def end(self) -> int:
        return self.pa + self.size

    def to_dict(self) -> dict:
        return {
            "pa": hex(self.pa),
            "size": self.size,
            "arch": self.arch,
            "machine": hex(self.machine),
            "timestamp": self.timestamp,
            "subsystem": self.subsystem,
            "sections": self.sections,
            "entry_rva": hex(self.entry_rva),
            "image_base": hex(self.image_base_va),
            "64bit": self.magic == 0x20B,
        }


def _parse(blob: bytes, pa: int, *, min_size: int, max_size: int) -> PEImageHit | None:
    """Validate a candidate header window; ``blob`` starts at the ``MZ``."""
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", blob, 0x3C)[0]
    if e_lfanew < 0x40 or e_lfanew > 0x400 or e_lfanew + 24 > len(blob):
        return None
    if blob[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return None

    (machine,) = struct.unpack_from("<H", blob, e_lfanew + 4)
    if machine not in MACHINES:
        return None
    (section_count,) = struct.unpack_from("<H", blob, e_lfanew + 6)
    if not 1 <= section_count <= 96:
        return None
    (timestamp,) = struct.unpack_from("<I", blob, e_lfanew + 8)
    (optional_size,) = struct.unpack_from("<H", blob, e_lfanew + 20)
    (characteristics,) = struct.unpack_from("<H", blob, e_lfanew + 22)

    opt = e_lfanew + 24
    if opt + 0x40 > len(blob) or optional_size < 0x40:
        return None
    (magic,) = struct.unpack_from("<H", blob, opt)
    if magic not in (0x10B, 0x20B):
        return None
    if (machine == 0x8664) != (magic == 0x20B):
        return None  # x64 must be PE32+, x86 must be PE32

    (entry_rva,) = struct.unpack_from("<I", blob, opt + 16)
    if magic == 0x20B:
        (image_base,) = struct.unpack_from("<Q", blob, opt + 24)
    else:
        (image_base,) = struct.unpack_from("<I", blob, opt + 28)
    (size_of_image,) = struct.unpack_from("<I", blob, opt + 56)
    (subsystem,) = struct.unpack_from("<H", blob, opt + 68)

    if not min_size <= size_of_image <= max_size:
        return None
    if size_of_image % PAGE:
        return None
    if entry_rva >= size_of_image:
        return None

    return PEImageHit(
        pa=pa,
        size=size_of_image,
        machine=machine,
        arch=MACHINES[machine],
        timestamp=timestamp,
        subsystem=SUBSYSTEMS.get(subsystem, hex(subsystem)),
        sections=section_count,
        characteristics=characteristics,
        entry_rva=entry_rva,
        image_base_va=image_base,
        magic=magic,
    )


def scan_pe_images(image: PhysicalImage, *, min_size: int = 0x1000,
                   max_size: int = 0x80_0000, limit: int = 500,
                   header_window: int = 0x1000) -> list[PEImageHit]:
    """Scan every mapped page for a PE image header.

    ``max_size`` caps ``SizeOfImage`` so a corrupt header cannot make a caller
    read gigabytes; ``limit`` caps the number of hits returned.
    """
    hits: list[PEImageHit] = []
    seen: set[int] = set()
    for base, size in image.map(page_aligned_only=True):
        for offset in range(0, size, PAGE):
            pa = base + offset
            if pa in seen:
                continue
            if image.read(pa, 2) != b"MZ":
                continue
            blob = image.read(pa, min(header_window, image.max_address - pa))
            hit = _parse(blob, pa, min_size=min_size, max_size=max_size)
            if hit is None:
                continue
            seen.add(pa)
            hits.append(hit)
            if len(hits) >= limit:
                return hits
    hits.sort(key=lambda h: h.pa)
    return hits


def read_image_bytes(image: PhysicalImage, hit: PEImageHit, *, strict: bool = True) -> bytes:
    """Return the image exactly as it is laid out in memory (RVA-indexed).

    This is what :meth:`phantomscope.analysis.engine.StaticEngine.load_capture`
    expects, so a PE found by this scanner can be handed straight to the
    static engine with no conversion step.
    """
    if strict and not all(
        image.contains(pa) for pa in (hit.pa, hit.end - 1)
    ):
        raise ValueError(
            f"image at {hit.pa:#x} (+{hit.size:#x}) extends past the captured physical range"
        )
    return image.read(hit.pa, hit.size)
