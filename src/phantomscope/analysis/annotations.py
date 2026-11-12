"""Persistent annotations: function names, comments and notes.

Reverse engineering is a naming loop.  You look at a function, decide it is
``decrypt_config``, and from then on every tool should call it that — otherwise
the next tool call hands you ``sub_7FF600001015`` again and you redo the work.
Over DMA there is no debugger symbol table to lean on, so phantomscope keeps its
own:

* ``functions`` / ``function_info`` / ``address_info`` / ``decompile`` prefer the
  annotated name over the export name and over ``sub_<rva>``;
* ``disassemble`` appends annotated names and comments as trailing comments;
* names survive a process restart because they are written to a JSON sidecar
  next to a PE that was loaded from disk (``<file>.phantomscope.json``).

A memory capture has no local file to sit next to, so its annotations live for
the life of the session only — exporting them is a deliberate gap, not a check
that failed silently.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from .pe import PEImage

SIDECAR_SUFFIX = ".phantomscope.json"

#: Identifier characters accepted for a rename.  ``?``, ``@``, ``$`` and ``.``
#: are allowed because real Microsoft symbols carry prefixes such as
#: ``_guard_dispatch`` or ``??_7Type@@6B@``.
_NAME_RE = re.compile(r"^[A-Za-z_?$@][\w?$@.:<>-]{0,199}$")


@dataclass
class Annotation:
    """One user annotation."""

    kind: str          # "function" / "comment" / "note"
    va: int | None
    text: str

    def to_dict(self) -> dict:
        out = {"kind": self.kind, "text": self.text}
        if self.va is not None:
            out["va"] = hex(self.va)
        return out


class AnnotationStore:
    """Names and comments for one image, with an optional JSON sidecar."""

    def __init__(self, sidecar: str | None = None) -> None:
        self.sidecar = sidecar
        self.functions: dict[int, str] = {}
        self.comments: dict[int, str] = {}
        self.notes: list[Annotation] = []
        self._dirty = False
        if sidecar and os.path.isfile(sidecar):
            self._read_sidecar(sidecar)

    # -- construction ------------------------------------------------------
    @classmethod
    def for_image(cls, image: PEImage) -> "AnnotationStore":
        """Store bound to the sidecar of a PE loaded from local disk.

        A mapped image is a capture of someone else's module: its ``path`` is a
        path on the *target*, so no sidecar is created for it.
        """
        sidecar = None
        if image.path and not image.mapped and os.path.isfile(image.path):
            sidecar = os.path.abspath(image.path) + SIDECAR_SUFFIX
        return cls(sidecar)

    # -- mutation ----------------------------------------------------------
    def rename(self, va: int, name: str) -> None:
        name = name.strip()
        if not _NAME_RE.match(name):
            raise ValueError(
                f"{name!r} is not a usable symbol name (letters, digits and _?$@.:<>- only)"
            )
        self.functions[int(va)] = name
        self._dirty = True

    def comment(self, va: int, text: str) -> None:
        self.comments[int(va)] = text
        self._dirty = True

    def note(self, text: str, va: int | None = None) -> None:
        self.notes.append(Annotation(kind="note", va=va, text=text))
        self._dirty = True

    def clear(self, va: int | None = None) -> int:
        """Drop annotations for one address, or every annotation when omitted."""
        if va is None:
            removed = len(self.functions) + len(self.comments) + len(self.notes)
            self.functions.clear()
            self.comments.clear()
            self.notes.clear()
        else:
            va = int(va)
            removed = int(self.functions.pop(va, None) is not None)
            removed += int(self.comments.pop(va, None) is not None)
            keep = [n for n in self.notes if n.va != va]
            removed += len(self.notes) - len(keep)
            self.notes = keep
        self._dirty = True
        return removed

    # -- queries -----------------------------------------------------------
    def name_for(self, va: int) -> str | None:
        return self.functions.get(int(va))

    def comment_for(self, va: int) -> str | None:
        return self.comments.get(int(va))

    def apply_to(self, image: PEImage) -> None:
        """Publish names/comments on the image so the disassembler can use them."""
        image.user_names = dict(self.functions)
        image.user_comments = dict(self.comments)

    def to_dict(self) -> dict:
        return {
            "sidecar": self.sidecar,
            "functions": {hex(va): name for va, name in sorted(self.functions.items())},
            "comments": {hex(va): text for va, text in sorted(self.comments.items())},
            "notes": [n.to_dict() for n in self.notes],
            "counts": {
                "functions": len(self.functions),
                "comments": len(self.comments),
                "notes": len(self.notes),
            },
        }

    # -- persistence -------------------------------------------------------
    def save(self) -> bool:
        """Write the sidecar when one is configured and something changed."""
        if not self.sidecar or not self._dirty:
            return False
        payload = {
            "version": 1,
            "functions": {hex(va): name for va, name in sorted(self.functions.items())},
            "comments": {hex(va): text for va, text in sorted(self.comments.items())},
            "notes": [
                {"va": hex(n.va) if n.va is not None else None, "text": n.text}
                for n in self.notes
            ],
        }
        directory = os.path.dirname(self.sidecar)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.sidecar, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        self._dirty = False
        return True

    def _read_sidecar(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, ValueError):
            return  # a corrupt sidecar must not stop the image from loading
        for key, name in (payload.get("functions") or {}).items():
            try:
                self.functions[int(key, 16)] = str(name)
            except (TypeError, ValueError):
                continue
        for key, text in (payload.get("comments") or {}).items():
            try:
                self.comments[int(key, 16)] = str(text)
            except (TypeError, ValueError):
                continue
        for entry in payload.get("notes") or []:
            if not isinstance(entry, dict):
                continue
            raw = entry.get("va")
            try:
                va = int(raw, 16) if isinstance(raw, str) else raw
            except ValueError:
                va = None
            self.notes.append(Annotation(kind="note", va=va, text=str(entry.get("text", ""))))
