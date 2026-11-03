"""Physical-memory views: the layer *below* an operating system.

Everything in this package works on raw physical addresses, the way a DMA
device sees the target.  There is no process list, no module list and no symbol
table unless something reconstructs them — which is exactly the constraint that
makes DMA reverse engineering different from debugging.

* :class:`PhysicalImage` — a (possibly sparse) raw physical memory dump.
* :class:`X64Pager` — x86-64 page-table walking, the way you turn a CR3 into
  usable virtual addresses when no OS tells you the mapping.
* :func:`scan_pe_images` — find PE images by structure alone, with no OS help.
* :class:`PhysicalBackend` — a :class:`~phantomscope.backend.MemoryBackend`
  over a dump file, so the MCP surface and the static engine can consume it.
"""

from .backend import PhysicalBackend
from .image import PhysicalImage, Segment, parse_memmap
from .paging import X64Pager
from .pescan import PEImageHit, scan_pe_images

__all__ = [
    "PEImageHit",
    "PhysicalBackend",
    "PhysicalImage",
    "Segment",
    "X64Pager",
    "parse_memmap",
    "scan_pe_images",
]
