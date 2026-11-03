"""Build a synthetic physical memory dump for testing the physical layer.

No DMA hardware and no Windows image required: the script writes a raw file
containing a PE image at a known physical address, a page-table tree that maps
it at a known virtual address, and enough surrounding data to exercise the
scanner, the pager and the static engine.

    python tools/make_demo_dump.py out.raw
    python -m phantomscope.mcp_server   # session_open(backend='physical', device='out.raw')

The script prints the CR3, the virtual base and the physical address of the
image so those values can be pasted straight into tool calls.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from phantomscope.backends.demo import build_minimal_pe, map_pe_file  # noqa: E402

PAGE = 0x1000
DUMP_SIZE = 0x40_0000
PE_PA = 0x10_0000
CR3 = 0x20_0000
PML4_PA = CR3
PDPT_PA = CR3 + PAGE
PD_PA = CR3 + 2 * PAGE
PT_PA = CR3 + 3 * PAGE
IMAGE_VA = 0x7FF6_0000_0000


def _entry(pa: int, flags: int = 0x7) -> bytes:
    return struct.pack("<Q", (pa & 0x000F_FFFF_FFFF_F000) | flags)


def build(path: str) -> dict:
    data = bytearray(DUMP_SIZE)
    image = map_pe_file(build_minimal_pe())
    data[PE_PA : PE_PA + len(image)] = image

    for index in range(0x200):
        data[PT_PA + index * 8 : PT_PA + index * 8 + 8] = _entry(PE_PA + index * PAGE)

    pml4e = (IMAGE_VA >> 39) & 0x1FF
    pdpte = (IMAGE_VA >> 30) & 0x1FF
    pde = (IMAGE_VA >> 21) & 0x1FF
    data[PML4_PA + pml4e * 8 : PML4_PA + pml4e * 8 + 8] = _entry(PDPT_PA)
    data[PDPT_PA + pdpte * 8 : PDPT_PA + pdpte * 8 + 8] = _entry(PD_PA)
    data[PD_PA + pde * 8 : PD_PA + pde * 8 + 8] = _entry(PT_PA)

    with open(path, "wb") as handle:
        handle.write(bytes(data))
    return {
        "path": os.path.abspath(path),
        "size": DUMP_SIZE,
        "cr3": CR3,
        "image_va": IMAGE_VA,
        "image_pa": PE_PA,
        "image_size": len(image),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", default="demo_phys.raw")
    parser.add_argument("--memmap", action="store_true",
                        help="print a memmap= string for the physical backend")
    args = parser.parse_args()

    info = build(args.output)
    print(f"wrote {info['path']} ({info['size']:#x} bytes)")
    print(f"  CR3          {info['cr3']:#x}")
    print(f"  image VA     {info['image_va']:#x}")
    print(f"  image PA     {info['image_pa']:#x}  ({info['image_size']:#x} bytes)")
    if args.memmap:
        print(f"  memmap       memmap=0x0,{info['size']:#x}")
    print()
    print("session_open(backend='physical', device='%s')" % info["path"])
    print("physical_images()")
    print("translate(va='%#x', cr3='%#x')" % (info["image_va"], info["cr3"]))
    print("capture_image(pa='%#x', key='demo')" % info["image_pa"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
