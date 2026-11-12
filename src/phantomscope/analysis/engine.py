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
from . import apis, detect, fingerprint, layout_map
from .annotations import AnnotationStore
from .index import CodeIndex, IndexCache
from .pe import PEImage, load_pe_from_bytes, load_pe_from_file
from .pseudo import MAX_BLOCKS, decompile
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
        self.annotations: dict[str, AnnotationStore] = {}
        self._patches: list[dict] = []

    # -- registry ----------------------------------------------------------
    def load_file(self, path: str, *, key: str | None = None, base: int | None = None) -> PEImage:
        full = os.path.abspath(path)
        image = load_pe_from_file(full, base=base)
        name = key or full
        self.images[name] = ImageEntry(key=name, image=image, source="file")
        self.annotations[name] = AnnotationStore.for_image(image)
        self.annotations[name].apply_to(image)
        return image

    def load_capture(self, key: str, data: bytes, base: int, *, path: str | None = None) -> PEImage:
        image = load_pe_from_bytes(data, base=base, path=path, mapped=True)
        self.images[key] = ImageEntry(key=key, image=image, source="memory")
        self.annotations[key] = AnnotationStore()
        self.annotations[key].apply_to(image)
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
        self.annotations.pop(key, None)
        return self.images.pop(key, None) is not None

    def save_image(self, key: str, path: str, *, raw: bool = False) -> dict:
        """Write a loaded image to disk as a file IDA/Ghidra/pefile will open.

        The point of dumping a module is to hand it to another tool; a bare memory
        buffer with RVA layout is not that.  ``raw=True`` keeps the mapped layout
        (useful when you want the exact bytes you captured).
        """
        return self.get(key).save(path, raw=raw)

    # -- patching ----------------------------------------------------------
    def apply_patch(self, key: str, va: int, data: bytes, *,
                    note: str | None = None) -> dict:
        """Overwrite bytes in a loaded image, keeping the original for rollback.

        The static twin of ``DynamicEngine.write``: a static image can be patched
        and written back out with :meth:`save_image`, which is how a byte edit
        becomes a working file instead of a screenshot of a hex view.

        Patching the *image* is deliberate: an RVA-indexed image is where the code
        actually lives, so the offset you see in ``disassemble`` is the offset you
        patch.  ``save_image`` then demaps it, which moves the byte to the right
        place in the file.
        """
        image = self.get(key)
        rva = va - image.base
        if rva < 0 or rva + len(data) > image.size:
            raise InvalidArgument(
                f"{va:#x} is outside {key!r} (base {image.base:#x}, size {image.size:#x})"
            )
        before = bytes(image.image[rva : rva + len(data)])
        image.image[rva : rva + len(data)] = bytes(data)
        # The index cached per image describes the old bytes: a patched function
        # would still report its pre-patch instructions.  Drop it so the next query
        # reanalyses, which is also what makes the patch visible to decompile.
        self.cache.invalidate(image)
        record = {
            "key": key,
            "va": hex(va),
            "rva": hex(rva),
            "old": before.hex(),
            "new": bytes(data).hex(),
            "size": len(data),
            "note": note,
        }
        self._patches.append(record)
        return record

    def patch_list(self) -> list[dict]:
        """Every static patch made through this engine, oldest first."""
        return list(self._patches)

    def patch_restore(self, index: int | None = None, *, all: bool = False) -> dict:
        """Undo one patch by index, or every outstanding patch with ``all=True``."""
        if all:
            targets = list(reversed(self._patches))
        elif index is not None:
            if not 0 <= index < len(self._patches):
                raise NotFound(f"no patch with index {index}")
            targets = [self._patches[index]]
        else:
            raise InvalidArgument("pass an index or all=True")
        restored = 0
        for record in targets:
            image = self.get(record["key"])
            rva = int(record["rva"], 16)
            image.image[rva : rva + record["size"]] = bytes.fromhex(record["old"])
            self.cache.invalidate(image)
            self._patches.remove(record)
            restored += 1
        return {"restored": restored, "remaining": len(self._patches)}

    def index(self, key: str) -> CodeIndex:
        return self.cache.get(self.get(key))

    def annotation_store(self, key: str) -> AnnotationStore:
        store = self.annotations.get(key)
        if store is None:
            image = self.get(key)
            store = AnnotationStore()
            store.apply_to(image)
            self.annotations[key] = store
        return store

    # -- annotations -------------------------------------------------------
    def rename_function(self, key: str, va: int, name: str) -> dict:
        """Name a function; the name is used by every later tool and persisted."""
        image = self.get(key)
        if not image.contains(va):
            raise InvalidArgument(f"{va:#x} is outside the image")
        store = self.annotation_store(key)
        try:
            store.rename(va, name)
        except ValueError as exc:
            raise InvalidArgument(str(exc)) from exc
        store.apply_to(image)
        return {
            "va": hex(va),
            "name": name,
            "saved": store.save(),
            "sidecar": store.sidecar,
        }

    def set_comment(self, key: str, va: int, text: str) -> dict:
        image = self.get(key)
        store = self.annotation_store(key)
        store.comment(va, text)
        store.apply_to(image)
        return {"va": hex(va), "comment": text, "saved": store.save(), "sidecar": store.sidecar}

    def add_note(self, key: str, text: str, va: int | None = None) -> dict:
        store = self.annotation_store(key)
        store.note(text, va)
        return {"note": text, "va": hex(va) if va is not None else None, "saved": store.save()}

    def annotation_list(self, key: str) -> dict:
        return self.annotation_store(key).to_dict()

    def clear_annotations(self, key: str, va: int | None = None) -> dict:
        image = self.get(key)
        store = self.annotation_store(key)
        removed = store.clear(va)
        store.apply_to(image)
        return {"removed": removed, "saved": store.save()}


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
        rows = [f.to_dict() for f in self.index(key).functions(offset=offset, limit=limit)]
        names = self.annotation_store(key).functions
        for row in rows:
            name = names.get(row["va"])
            if name:
                row["name"] = name
        return rows

    def function_info(self, key: str, va: int) -> dict | None:
        info = self.index(key).function(va)
        if info is None:
            return None
        row = info.to_dict()
        name = self.annotation_store(key).functions.get(row["va"])
        if name:
            row["name"] = name
        return row

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

    def merge_layout(self, key: str, va: int, inferred: dict, *,
                     limit: int = 8000) -> list[dict]:
        """Merge this function's access pattern with a live ``infer_struct`` result.

        Neither half is a struct on its own: the code knows which offsets exist and
        at what width, the memory knows what is *in* them.  See
        :mod:`phantomscope.analysis.layout_map`.
        """
        merged = layout_map.merge(self.struct_layout(key, va, limit=limit), inferred)
        for layout in merged:
            layout["vectors"] = layout_map.vector_groups(layout["fields"])
        return merged

    def globals_touched(self, key: str, va: int, *, limit: int = 2000) -> list[dict]:
        """Module globals (RIP-relative references) used by a function."""
        index = self.index(key)
        start = index.function_start(va) or va
        return [ref.to_dict() for ref in globals_touched(index, start, limit=limit)]

    # -- pseudo-C recovery -------------------------------------------------
    def decompile(self, key: str, va: int, *, include_comments: bool = True,
                  max_blocks: int | None = None) -> dict:
        """Lift one function to pseudo-C (see :mod:`phantomscope.analysis.pseudo`)."""
        return decompile(self.index(key), va, include_comments=include_comments,
                         max_blocks=max_blocks or MAX_BLOCKS)

    # -- import / API resolution -------------------------------------------
    def api_calls(self, key: str, va: int | None = None, *, limit: int = 2000) -> list[dict]:
        return apis.api_summary(self.index(key), va)[:limit]

    def api_sites(self, key: str, va: int | None = None, *, limit: int = 2000) -> list[dict]:
        return [site.to_dict() for site in apis.api_calls(self.index(key), va, limit=limit)]

    def find_api(self, key: str, needle: str, *, limit: int = 200) -> dict:
        index = self.index(key)
        return {
            "needle": needle,
            "sites": apis.find_api(index, needle, limit=limit),
            "unresolved_indirect": apis.unresolved_indirect(index),
        }

    # -- string cross references -------------------------------------------
    def string_refs(self, key: str, *, contains: str = "", va: str | int | None = None,
                    min_length: int = 4, limit: int = 200,
                    include_code: bool = True) -> dict:
        """Strings and the code that references them.

        ``include_code`` is on by default: a licence key or URL is often stored
        inline in ``.text``, and skipping executable sections would hide exactly
        the strings worth finding.
        """
        index = self.index(key)
        image = self.get(key)
        if va is not None:
            target = int(va, 16) if isinstance(va, str) else int(va)
            refs = index.xrefs_to(target, limit=limit)
            text = None
            raw = image.read(target, 96)
            if raw:
                text = raw.split(b"\x00", 1)[0].decode("ascii", "replace")
            return {"va": hex(target), "text": text,
                    "refs": [ref.to_dict() for ref in refs]}
        needle = contains.lower()
        rows: list[dict] = []
        for item in extract_strings(image, min_length=min_length, limit=20000,
                                    include_code=include_code):
            if needle and needle not in item["text"].lower():
                continue
            refs = index.xrefs_to(item["va"], limit=20)
            rows.append({
                "va": hex(item["va"]),
                "text": item["text"],
                "encoding": item["encoding"],
                "section": item["section"],
                "refs": [{"from": hex(ref.from_va), "function": hex(ref.function) if ref.function else None}
                         for ref in refs],
            })
            if len(rows) >= limit:
                break
        return {"contains": contains, "count": len(rows), "strings": rows}

    # -- similarity, matching and diffing ----------------------------------
    def fingerprint(self, key: str, va: int) -> dict:
        return fingerprint.fingerprint(self.index(key), va).to_dict()

    def find_similar(self, key: str, va: int, *, limit: int = 10,
                     min_similarity: float = 0.5) -> list[dict]:
        return fingerprint.find_similar(self.index(key), va, limit=limit,
                                        min_similarity=min_similarity)

    def match_images(self, left: str, right: str, *, min_similarity: float = 0.6,
                     limit: int = 400) -> dict:
        rows = fingerprint.match_images(self.index(left), self.index(right),
                                        min_similarity=min_similarity, limit=limit)
        return {"left": left, "right": right, "count": len(rows), "matches": rows}

    def diff_images(self, left: str, right: str, *, min_similarity: float = 0.6) -> dict:
        out = fingerprint.diff_images(self.index(left), self.index(right),
                                      min_similarity=min_similarity)
        out["left_key"] = left
        out["right_key"] = right
        return out

    # -- triage ------------------------------------------------------------
    def packing_report(self, key: str) -> dict:
        return detect.packing_report(self.index(key))

    def crypto_constants(self, key: str, *, limit: int = 40) -> list[dict]:
        return detect.crypto_constants(self.index(key), limit=limit)

    def search_immediates(self, key: str, value: int, *, width: int = 4,
                          limit: int = 200) -> dict:
        return detect.search_immediates(self.index(key), value, width=width, limit=limit)
