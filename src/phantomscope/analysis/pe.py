"""PE image model.

A :class:`PEImage` exposes a *mapped* view of the image: a flat buffer indexed
by RVA, so :meth:`PEImage.read` works identically for a file on disk and for a
module captured from live memory through DMA.

``pefile`` parses the headers and rich directories.  For memory images the
buffer is first "de-mapped" into a temporary file layout, so import and export
directories resolve correctly instead of pointing at file offsets.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import pefile

from ..errors import InvalidArgument, NotFound
from ..models import ExportInfo, ImportInfo, SectionInfo

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

MACHINES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "arm",
    0x01C4: "armv7",
    0xAA64: "arm64",
}

DLL_CHARACTERISTICS = {
    0x0020: "HIGH_ENTROPY_VA",
    0x0040: "DYNAMIC_BASE",
    0x0080: "FORCE_INTEGRITY",
    0x0100: "NX_COMPAT",
    0x0200: "NO_ISOLATION",
    0x0400: "NO_SEH",
    0x0800: "NO_BIND",
    0x1000: "APPCONTAINER",
    0x2000: "WDM_DRIVER",
    0x4000: "GUARD_CF",
    0x8000: "TERMINAL_SERVER_AWARE",
}

SUBSYSTEMS = {
    1: "native",
    2: "windows_gui",
    3: "windows_cui",
    7: "posix",
    9: "windows_ce",
    10: "efi_application",
    14: "xbox",
}


def is_pe(data: bytes) -> bool:
    return len(data) >= 0x40 and data[:2] == b"MZ"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    value = 0.0
    for count in counts:
        if count:
            p = count / total
            value -= p * math.log2(p)
    return round(value, 2)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _demap(image: bytes) -> bytes:
    """Lay an RVA-indexed memory image out as a raw file image for pefile."""
    probe = pefile.PE(data=bytes(image), fast_load=True)
    size_of_headers = max(0x200, _as_int(probe.OPTIONAL_HEADER.SizeOfHeaders, 0x400))
    file_size = size_of_headers
    for section in probe.sections:
        file_size = max(file_size, _as_int(section.PointerToRawData) + _as_int(section.SizeOfRawData))
    raw = bytearray(file_size)
    header_len = min(size_of_headers, len(image))
    raw[:header_len] = image[:header_len]
    for section in probe.sections:
        src = _as_int(section.VirtualAddress)
        dst = _as_int(section.PointerToRawData)
        length = _as_int(section.SizeOfRawData)
        if length <= 0 or src >= len(image) or dst >= file_size:
            continue
        chunk = image[src : src + min(length, len(image) - src)]
        raw[dst : dst + min(len(chunk), file_size - dst)] = chunk[: file_size - dst]
    return bytes(raw)


@dataclass
class PEImage:
    """A parsed PE image with a mapped (RVA-indexed) memory view."""

    path: str | None
    data: bytes
    base: int
    image: bytearray
    pe: pefile.PE
    arch: str
    entry_rva: int = 0
    sections: list[SectionInfo] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    exports: list[ExportInfo] = field(default_factory=list)
    imported_by_slot: dict[int, str] = field(default_factory=dict)
    mapped: bool = True

    # -- geometry ----------------------------------------------------------
    @property
    def size(self) -> int:
        return len(self.image)

    @property
    def bits(self) -> int:
        return 64 if self.arch in ("x64", "arm64") else 32

    @property
    def is_64(self) -> bool:
        return self.bits == 64

    @property
    def entry(self) -> int:
        return self.base + self.entry_rva

    def rva_to_va(self, rva: int) -> int:
        return self.base + rva

    def va_to_rva(self, va: int) -> int:
        return va - self.base

    def contains(self, va: int) -> bool:
        return self.base <= va < self.base + self.size

    def is_executable_va(self, va: int) -> bool:
        section = self.section_for_va(va)
        return bool(section and section.executable)

    def read(self, va: int, size: int) -> bytes:
        rva = va - self.base
        if rva < 0 or rva >= len(self.image):
            return b""
        return bytes(self.image[rva : rva + size])

    def read_rva(self, rva: int, size: int) -> bytes:
        if rva < 0 or rva >= len(self.image):
            return b""
        return bytes(self.image[rva : rva + size])

    def section_for_va(self, va: int) -> SectionInfo | None:
        for section in self.sections:
            if section.va <= va < section.va + max(section.vsize, 0x1000):
                return section
        return None

    def executable_ranges(self) -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        for section in self.sections:
            if section.executable and section.vsize:
                out.append((section.va, section.va + section.vsize))
        if not out:
            out.append((self.base, self.base + self.size))
        return out

    # -- metadata ----------------------------------------------------------
    def has_signature(self) -> bool:
        try:
            directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
            ]
            return bool(directory.VirtualAddress and directory.Size)
        except Exception:
            return False

    def tls_callbacks(self) -> list[int]:
        """Absolute VAs of TLS callbacks (these run before the entry point)."""
        try:
            callbacks_va = int(self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks)
        except Exception:
            return []
        if not callbacks_va:
            return []
        rva = callbacks_va - self.base if callbacks_va >= self.base else callbacks_va
        out: list[int] = []
        width = 8 if self.is_64 else 4
        for _ in range(64):
            chunk = self.read_rva(rva, width)
            if len(chunk) < width:
                break
            value = int.from_bytes(chunk, "little")
            if not value:
                break
            out.append(value)
            rva += width
        return out

    def pdb_path(self) -> str | None:
        try:
            for entry in self.pe.DIRECTORY_ENTRY_DEBUG:
                if int(entry.struct.Type) == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                    raw = getattr(entry.entry, "PdbFileName", None)
                    if raw:
                        return raw.rstrip(b"\x00").decode("ascii", "replace")
        except Exception:
            pass
        return None

    def version_info(self) -> dict[str, str]:
        out: dict[str, str] = {}
        try:
            for file_info in self.pe.FileInfo or []:
                for entry in file_info:
                    if getattr(entry, "Key", None) == b"StringFileInfo":
                        for table in entry.StringTable or []:
                            for key, value in table.entries.items():
                                out[key.decode("ascii", "replace")] = value.decode("utf-8", "replace")
        except Exception:
            pass
        return out

    def security_flags(self) -> list[str]:
        flags = int(self.pe.OPTIONAL_HEADER.DllCharacteristics or 0)
        return [name for bit, name in DLL_CHARACTERISTICS.items() if flags & bit]

    def compile_time(self) -> str | None:
        stamp = int(self.pe.FILE_HEADER.TimeDateStamp or 0)
        if not stamp:
            return None
        try:
            return datetime.fromtimestamp(stamp, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None

    def overlay_size(self) -> int:
        if self.mapped:
            return 0
        end = 0
        try:
            for section in self.pe.sections:
                end = max(end, int(section.PointerToRawData) + int(section.SizeOfRawData))
        except Exception:
            return 0
        return max(0, len(self.data) - end)

    def has_rich_header(self) -> bool:
        return getattr(self.pe, "RICH_HEADER", None) is not None

    def summary(self) -> dict:
        return {
            "path": self.path,
            "base": hex(self.base),
            "arch": self.arch,
            "entry": hex(self.entry),
            "image_size": self.size,
            "machine": hex(int(self.pe.FILE_HEADER.Machine or 0)),
            "subsystem": SUBSYSTEMS.get(int(self.pe.OPTIONAL_HEADER.Subsystem or 0), "unknown"),
            "characteristics": hex(int(self.pe.FILE_HEADER.Characteristics or 0)),
            "compile_time": self.compile_time(),
            "pdb_path": self.pdb_path(),
            "security_flags": self.security_flags(),
            "signed": self.has_signature(),
            "rich_header": self.has_rich_header(),
            "version_info": self.version_info(),
            "overlay_size": self.overlay_size(),
            "sections": [s.to_dict() for s in self.sections],
            "import_module_count": len({i.module for i in self.imports}),
            "import_count": len(self.imports),
            "export_count": len(self.exports),
            "import_modules": sorted({i.module for i in self.imports}),
            "tls_callbacks": [hex(c) for c in self.tls_callbacks()],
        }

    def find_export(self, name: str) -> ExportInfo | None:
        for export in self.exports:
            if export.name and export.name == name:
                return export
        return None

    def resolve_import_name(self, va: int) -> str | None:
        """Map an IAT slot VA to ``module!name``."""
        return self.imported_by_slot.get(va) or self.imported_by_slot.get(va - self.base)

    def rebase(self, new_base: int) -> None:
        """Change the reported image base (e.g. after ASLR) without touching RVAs."""
        delta = new_base - self.base
        if delta == 0:
            return
        self.base = new_base
        for section in self.sections:
            section.va += delta
        for imp in self.imports:
            if imp.iat_va is not None:
                imp.iat_va += delta
        for export in self.exports:
            if export.va is not None:
                export.va += delta


def _build_sections(pe: pefile.PE, base: int) -> list[SectionInfo]:
    sections: list[SectionInfo] = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("ascii", "replace")
        va = base + int(section.VirtualAddress)
        vsize = int(section.Misc_VirtualSize) or int(section.SizeOfRawData)
        characteristics = int(section.Characteristics)
        raw = section.get_data()
        sections.append(
            SectionInfo(
                name=name or "<unnamed>",
                va=va,
                vsize=vsize,
                raw_offset=int(section.PointerToRawData),
                raw_size=int(section.SizeOfRawData),
                executable=bool(characteristics & IMAGE_SCN_MEM_EXECUTE),
                writable=bool(characteristics & IMAGE_SCN_MEM_WRITE),
                readable=bool(characteristics & IMAGE_SCN_MEM_READ),
                entropy=entropy(raw[:0x20000]) if raw else None,
            )
        )
    return sections


def _collect_imports(pe: pefile.PE, base: int) -> tuple[list[ImportInfo], dict[int, str]]:
    imports: list[ImportInfo] = []
    by_slot: dict[int, str] = {}
    try:
        directory = pe.DIRECTORY_ENTRY_IMPORT
    except AttributeError:
        return imports, by_slot
    for entry in directory:
        module = (entry.dll or b"").decode("ascii", "replace")
        for symbol in entry.imports:
            name = symbol.name.decode("ascii", "replace") if symbol.name else None
            iat_va = (base + int(symbol.address)) if symbol.address else None
            imports.append(
                ImportInfo(
                    module=module,
                    name=name,
                    ordinal=int(symbol.ordinal) if not name else None,
                    iat_va=iat_va,
                )
            )
            if iat_va is not None:
                by_slot[iat_va] = f"{module}!{name or '#' + str(symbol.ordinal)}"
    return imports, by_slot


def _collect_exports(pe: pefile.PE, base: int) -> list[ExportInfo]:
    exports: list[ExportInfo] = []
    try:
        directory = pe.DIRECTORY_ENTRY_EXPORT
    except AttributeError:
        return exports
    for symbol in getattr(directory, "symbols", []) or []:
        name = symbol.name.decode("ascii", "replace") if symbol.name else None
        exports.append(
            ExportInfo(
                name=name,
                ordinal=int(symbol.ordinal),
                va=(base + int(symbol.address)) if symbol.address else None,
                forwarder=symbol.forwarder.decode("ascii", "replace") if symbol.forwarder else None,
            )
        )
    return exports


def _parse(data: bytes, base: int | None, path: str | None, *, mapped: bool) -> PEImage:
    if not is_pe(data):
        raise InvalidArgument("not a PE image (missing MZ header)")
    try:
        probe = pefile.PE(data=bytes(data), fast_load=True)
    except Exception as exc:
        raise InvalidArgument(f"failed to parse PE headers: {exc}") from exc

    image_base = int(probe.OPTIONAL_HEADER.ImageBase)
    size_of_image = int(probe.OPTIONAL_HEADER.SizeOfImage or len(data))
    if size_of_image <= 0:
        size_of_image = len(data)

    if mapped:
        image = bytearray(data[:size_of_image])
        if len(image) < size_of_image:
            image.extend(b"\x00" * (size_of_image - len(image)))
        raw_for_pe = _demap(bytes(image))
    else:
        image = bytearray(size_of_image)
        header_size = min(int(probe.OPTIONAL_HEADER.SizeOfHeaders or 0x400), len(data))
        image[:header_size] = data[:header_size]
        for section in probe.sections:
            src = int(section.PointerToRawData)
            dst = int(section.VirtualAddress)
            raw = bytes(data[src : src + int(section.SizeOfRawData)])
            if dst < size_of_image and raw:
                image[dst : dst + min(len(raw), size_of_image - dst)] = raw[: size_of_image - dst]
        raw_for_pe = bytes(data)

    try:
        pe = pefile.PE(data=raw_for_pe, fast_load=False)
    except Exception as exc:
        raise InvalidArgument(f"failed to parse PE directories: {exc}") from exc

    arch = MACHINES.get(int(pe.FILE_HEADER.Machine), f"machine_{int(pe.FILE_HEADER.Machine):#x}")
    actual_base = image_base if base is None else int(base)
    imports, by_slot = _collect_imports(pe, actual_base)
    exports = _collect_exports(pe, actual_base)
    sections = _build_sections(pe, actual_base)

    return PEImage(
        path=path,
        data=data,
        base=actual_base,
        image=image,
        pe=pe,
        arch=arch,
        entry_rva=int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        sections=sections,
        imports=imports,
        exports=exports,
        imported_by_slot=by_slot,
        mapped=mapped,
    )


def load_pe_from_file(path: str | os.PathLike[str], base: int | None = None) -> PEImage:
    full = os.path.abspath(str(path))
    if not os.path.isfile(full):
        raise NotFound(f"file not found: {full}")
    with open(full, "rb") as handle:
        data = handle.read()
    return _parse(data, base, full, mapped=False)


def load_pe_from_bytes(
    data: bytes, base: int | None = None, *, path: str | None = None, mapped: bool = False
) -> PEImage:
    """Load a PE from memory.

    ``mapped=True`` means ``data`` is an RVA-indexed image captured from a live
    process; ``mapped=False`` means it is a raw file image.
    """
    return _parse(bytes(data), base, path, mapped=mapped)
