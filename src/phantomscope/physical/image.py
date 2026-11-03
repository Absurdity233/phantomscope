"""A raw physical-memory image, optionally sparse.

A DMA capture is a blob of physical RAM.  It is not necessarily contiguous: a
PCILeech ``-memmap`` dump, a winpmem raw image and a crash dump all describe
segments that sit at specific physical addresses.  :class:`PhysicalImage`
normalises those into one addressable space.

Reads outside every segment return zeros *and* are counted, so callers can tell
"the dump contains zeros here" from "the dump does not contain this address" —
a distinction that matters when you are hunting for structures.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from ..errors import BackendError, InvalidArgument

PAGE = 0x1000


@dataclass(frozen=True)
class Segment:
    """One physical range stored at ``file_offset``."""

    file_offset: int
    pa: int
    size: int

    @property
    def end(self) -> int:
        return self.pa + self.size


def parse_memmap(spec: str) -> list[Segment]:
    """Parse a memory-map specification into segments.

    Accepted forms::

        "0x1000,0x1ff000"                     one segment, file offset 0
        "0x1000,0x1ff000;0x200000,0x100000"   several segments, packed in order
        "auto"                                identity map from the first page

    Sizes are in bytes.  Segments are stored back to back in the file, in the
    order they are listed.
    """
    text = (spec or "").strip()
    if not text:
        return []
    if text.lower() == "auto":
        return []  # resolved by the caller, which knows the file size

    segments: list[Segment] = []
    cursor = 0
    for piece in text.replace("\n", ";").split(";"):
        piece = piece.strip()
        if not piece:
            continue
        parts = [p.strip() for p in piece.split(",")]
        if len(parts) < 2:
            raise InvalidArgument(
                f"bad memmap entry {piece!r}; expected 'pa,size' (both hex or decimal)"
            )
        try:
            pa = int(parts[0], 0)
            size = int(parts[1], 0)
        except ValueError as exc:
            raise InvalidArgument(f"bad memmap entry {piece!r}: {exc}") from exc
        if pa < 0 or size <= 0:
            raise InvalidArgument(f"bad memmap entry {piece!r}: pa must be >= 0 and size > 0")
        segments.append(Segment(file_offset=cursor, pa=pa, size=size))
        cursor += size
    if not segments:
        raise InvalidArgument(f"memmap {spec!r} produced no segments")
    return segments


class PhysicalImage:
    """Addressable view over a raw physical dump."""

    def __init__(self, path: str, segments: list[Segment] | None = None) -> None:
        self.path = os.path.abspath(path)
        if not os.path.isfile(self.path):
            raise BackendError(f"no such image file: {self.path}")
        # Unbuffered: the image is also written through a second handle, and a
        # buffered reader can serve stale bytes for a seek inside its window.
        self._fh = open(self.path, "rb", buffering=0)
        self._size = os.path.getsize(self.path)
        self.segments = segments or [Segment(file_offset=0, pa=0, size=self._size)]
        self.read_misses = 0
        self.write_count = 0
        self._validate()

    # -- lifecycle ---------------------------------------------------------
    def _validate(self) -> None:
        for segment in self.segments:
            if segment.file_offset < 0 or segment.file_offset + segment.size > self._size:
                raise InvalidArgument(
                    f"segment {segment.pa:#x}+{segment.size:#x} needs bytes "
                    f"{segment.file_offset:#x}..{segment.file_offset + segment.size:#x} "
                    f"but the file is {self._size:#x} bytes"
                )
            if segment.size % PAGE:
                raise InvalidArgument(
                    f"segment {segment.pa:#x} size {segment.size:#x} is not page aligned"
                )
        ordered = sorted(self.segments, key=lambda s: s.pa)
        for previous, current in zip(ordered, ordered[1:]):
            if previous.end > current.pa:
                raise InvalidArgument(
                    f"segments overlap at {current.pa:#x} "
                    f"(previous ends {previous.end:#x})"
                )

    def close(self) -> None:
        if self._fh is not None and not self._fh.closed:
            self._fh.close()

    def __enter__(self) -> "PhysicalImage":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # -- geometry ----------------------------------------------------------
    @property
    def file_size(self) -> int:
        return self._size

    @property
    def mapped_bytes(self) -> int:
        return sum(segment.size for segment in self.segments)

    @property
    def max_address(self) -> int:
        return max((segment.end for segment in self.segments), default=0)

    def map(self, *, page_aligned_only: bool = False) -> list[tuple[int, int]]:
        """Return ``(pa, size)`` ranges in ascending order."""
        ranges = [(segment.pa, segment.size) for segment in self.segments]
        if page_aligned_only:
            ranges = [r for r in ranges if r[0] % PAGE == 0]
        return sorted(ranges)

    def segment_for(self, pa: int) -> Segment | None:
        for segment in self.segments:
            if segment.pa <= pa < segment.end:
                return segment
        return None

    def contains(self, pa: int) -> bool:
        return self.segment_for(pa) is not None

    # -- IO ----------------------------------------------------------------
    def read(self, pa: int, size: int) -> bytes:
        """Read ``size`` bytes at physical ``pa``; gaps read as zeros."""
        if size < 0:
            raise InvalidArgument("negative read size")
        if size == 0:
            return b""
        out = bytearray(size)
        done = 0
        while done < size:
            current = pa + done
            segment = self.segment_for(current)
            if segment is None:
                self.read_misses += 1
                # Skip to the next segment (or the end) in one step.
                following = [s for s in self.segments if s.pa > current]
                step = (min(s.pa for s in following) if following else pa + size) - current
                done += max(1, min(step, size - done))
                continue
            offset = segment.file_offset + (current - segment.pa)
            available = min(segment.end - current, size - done)
            self._fh.seek(offset)
            chunk = self._fh.read(available)
            out[done : done + len(chunk)] = chunk
            done += len(chunk)
        return bytes(out)

    def write(self, pa: int, data: bytes) -> int:
        """Write into the image, changing the file on disk.

        Writes that straddle a gap are refused rather than silently split: a
        partial physical write is almost never what the caller meant.
        """
        if not self.contains(pa) or not self.contains(pa + len(data) - 1):
            raise BackendError(f"write crosses an unmapped physical range at {pa:#x}")
        segment = self.segment_for(pa)
        offset = segment.file_offset + (pa - segment.pa)
        with open(self.path, "r+b") as handle:
            handle.seek(offset)
            handle.write(bytes(data))
        self.write_count += 1
        return len(data)

    # -- typed helpers -----------------------------------------------------
    def read_u64(self, pa: int) -> int:
        return struct.unpack("<Q", self.read(pa, 8))[0]

    def read_u32(self, pa: int) -> int:
        return struct.unpack("<I", self.read(pa, 4))[0]

    def read_u16(self, pa: int) -> int:
        return struct.unpack("<H", self.read(pa, 2))[0]

    def is_zero(self, pa: int, size: int) -> bool:
        return self.read(pa, size) == bytes(size)

    def info(self) -> dict:
        return {
            "path": self.path,
            "file_size": self._size,
            "mapped_bytes": self.mapped_bytes,
            "max_address": hex(self.max_address),
            "segments": [
                {"pa": hex(s.pa), "size": hex(s.size), "file_offset": hex(s.file_offset)}
                for s in self.segments
            ],
            "read_misses": self.read_misses,
            "writes": self.write_count,
        }
