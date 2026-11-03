"""Static analysis facade used by the MCP server and the CLI.

Holds a registry of loaded images (files or memory captures) and their
lazily-built :class:`~phantomscope.analysis.index.CodeIndex` instances, so a
single MCP session can keep an analysed binary warm across tool calls.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from ..errors import InvalidArgument, NotFound
from ..utils import hexdump
from .index import CodeIndex, IndexCache
from .pe import PEImage, load_pe_from_bytes, load_pe_from_file
from .scan import extract_strings, find_rtti, scan_image
from .structs import globals_touched, infer_layout


@dataclass
class ImageEntry:
    key: str
    image: PEImage
    source: str


class StaticEngine:
    def __init__(self, *, max_instructions: int = 1_500_000) -> None:
        self.images: dict[str, ImageEntry] = {}
        self.cache = IndexCache(max_instructions=max_instructions)

    # -- registry ----------------------------------------------------------
    def load_file(self, path: str, *, key: str | None = None, base: int | None = None) -> PEImage:
        full = os.path.abspath(path)
        image = load_pe_from_file(full, base=base)
        self.images[key or full] = ImageEntry(key=key or full, image=image, source="file")
        return image

    def load_capture(self, key: str, data: bytes, base: int, *, path: str | None = None) -> PEImage:
        image = load_pe_from_bytes(data, base=base, path=path, mapped=True)
        self.images[key] = ImageEntry(key=key, image=image, source="memory")
        return image

    def get(self, key: str) -> PEImage:
        try:
            return self.images[key].image
        except KeyError:
            known = ", ".join(sorted(self.images)[:10]) or "<none>"
            raise NotFound(f"no image named {key!r}; loaded images: {known}") from None

    def keys(self) -> list[str]:
        return sorted(self.images)

    def unload(self, key: str) -> bool:
        return self.images.pop(key, None) is not None

    def index(self, key: str) -> CodeIndex:
        return self.cache.get(self.get(key))

    # -- high level operations --------------------------------------------
    def summary(self, key: str) -> dict:
        return self.get(key).summary()

    def sections(self, key: str) -> list[dict]:
        return [section.to_dict() for section in self.get(key).sections]

    def imports(self, key: str, *, module: str | None = None) -> list[dict]:
        image = self.get(key)
        if module:
            needle = module.lower()
            return [i.to_dict() for i in image.imports if needle in i.module.lower()]
        return [i.to_dict() for i in image.imports]

    def exports(self, key: str) -> list[dict]:
        return [e.to_dict() for e in self.get(key).exports]

    def strings(self, key: str, *, min_length: int = 4, limit: int = 5000,
                include_code: bool = False) -> list[dict]:
        hits = extract_strings(
            self.get(key), min_length=min_length, limit=limit, include_code=include_code
        )
        return [{"va": hex(h["va"]), "text": h["text"], "encoding": h["encoding"],
                 "section": h["section"]} for h in hits]

    def search_string(self, key: str, needle: str, *, limit: int = 200) -> list[dict]:
        low = needle.lower()
        return [h for h in self.strings(key, limit=limit * 20) if low in h["text"].lower()][:limit]

    def functions(self, key: str, *, offset: int = 0, limit: int = 200) -> list[dict]:
        return [f.to_dict() for f in self.index(key).functions(offset=offset, limit=limit)]

    def function_info(self, key: str, va: int) -> dict | None:
        info = self.index(key).function(va)
        return info.to_dict() if info else None

    def disassemble(self, key: str, va: int | None, *, count: int = 40,
                    function: bool = False) -> list[dict]:
        image = self.get(key)
        if function:
            if va is None:
                raise InvalidArgument("va is required for function disassembly")
            insns = self.index(key).disassemble_function(va, limit=count)
        else:
            start = image.entry if va is None else va
            insns = self.index(key).disassembler.disassemble_range(image, start, count * 8, limit=count)
        return [i.to_dict() for i in insns]

    def xrefs_to(self, key: str, va: int, *, limit: int = 100, include_pointers: bool = True) -> list[dict]:
        return [x.to_dict() for x in self.index(key).xrefs_to(va, limit=limit,
                                                             include_pointers=include_pointers)]

    def xrefs_from(self, key: str, va: int, *, limit: int = 200) -> list[dict]:
        return [x.to_dict() for x in self.index(key).xrefs_from(va, limit=limit)]

    def callers(self, key: str, va: int) -> list[str]:
        return [hex(v) for v in self.index(key).callers(va)]

    def callees(self, key: str, va: int) -> list[str]:
        return [hex(v) for v in self.index(key).callees(va)]

    def blocks(self, key: str, va: int) -> list[dict]:
        return [b.to_dict() for b in self.index(key).blocks_for(va)]

    def scan(self, key: str, pattern: str, *, limit: int = 500,
             sections: list[str] | None = None, executable_only: bool = False) -> list[dict]:
        return [h.to_dict() for h in scan_image(
            self.get(key), pattern, limit=limit, sections=sections, executable_only=executable_only
        )]

    def rtti(self, key: str, *, limit: int = 500) -> list[dict]:
        return [r.to_dict() for r in find_rtti(self.get(key), limit=limit)]

    def read(self, key: str, va: int, size: int) -> dict:
        image = self.get(key)
        data = image.read(va, size)
        return {"va": hex(va), "size": len(data), "hex": data.hex(), "dump": hexdump(data, va)}

    def address_info(self, key: str, va: int) -> dict:
        image = self.get(key)
        section = image.section_for_va(va)
        function = self.index(key).function(va)
        out: dict[str, Any] = {
            "va": hex(va),
            "in_image": image.contains(va),
            "section": section.name if section else None,
            "section_offset": f"{va - section.va:#x}" if section else None,
            "rva": f"{va - image.base:#x}",
            "executable": bool(section and section.executable),
            "function": function.to_dict() if function else None,
        }
        name = image.resolve_import_name(va)
        if name:
            out["import"] = name
        if not image.contains(va):
            out["hint"] = "address is outside the image; it may be heap, stack or another module"
        return out

    # -- structure layout inference ---------------------------------------
    def struct_layout(self, key: str, va: int, *, limit: int = 8000) -> list[dict]:
        """Candidate struct layouts touched by the function containing ``va``."""
        index = self.index(key)
        start = index.function_start(va) or va
        return [layout.to_dict() for layout in infer_layout(index, start, limit=limit)]

    def globals_touched(self, key: str, va: int, *, limit: int = 2000) -> list[dict]:
        """Module globals (RIP-relative references) used by a function."""
        index = self.index(key)
        start = index.function_start(va) or va
        return [ref.to_dict() for ref in globals_touched(index, start, limit=limit)]
