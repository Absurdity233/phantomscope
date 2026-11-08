"""Session management: one backend + one dynamic engine + one static engine.

An MCP client normally works against a single session, but named sessions let
one server hold e.g. a live FPGA target and an offline dump at the same time.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from ..analysis.engine import StaticEngine
from ..backend import MemoryBackend
from ..backends.factory import create_backend
from ..errors import InvalidArgument, NotFound
from ..models import SessionInfo
from .engine import DynamicEngine


@dataclass
class Session:
    name: str
    backend: MemoryBackend
    static: StaticEngine = field(default_factory=StaticEngine)
    dynamic: DynamicEngine | None = None
    attached_pid: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    #: Snapshot emulators over this session's images, keyed by image key.  They
    #: live here so closing the session releases the emulated memory with it.
    emulators: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.dynamic is None:
            self.dynamic = DynamicEngine(self.backend)

    def open(self) -> "Session":
        self.backend.open()
        return self

    def close(self) -> None:
        try:
            self.backend.close()
        except Exception:
            pass

    def info(self) -> dict:
        out = SessionInfo(
            name=self.name,
            kind=self.backend.kind,
            device=getattr(self.backend, "device", None),
            bits=getattr(self.backend, "bits", None),
            capabilities=self.backend.caps.to_dict(),
        ).to_dict()
        if self.attached_pid is not None:
            out["attached_pid"] = self.attached_pid
        try:
            out["processes"] = len(self.backend.list_processes())
        except Exception:
            pass
        out["images"] = self.static.keys()
        out["patches"] = len(self.dynamic.patches()) if self.dynamic else 0
        return out


class SessionManager:
    """Thread-safe registry of sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()
        self._default: str | None = None

    # -- lifecycle ---------------------------------------------------------
    def open(
        self,
        *,
        name: str = "default",
        kind: str = "memprocfs",
        device: str = "fpga",
        options: list[str] | None = None,
        forensic: int = 0,
        wait_initialize: bool = False,
        make_default: bool = True,
    ) -> Session:
        with self._lock:
            existing = self._sessions.get(name)
            if existing is not None:
                existing.close()
            backend = create_backend(
                kind,
                device=device,
                options=options,
                forensic=forensic,
                wait_initialize=wait_initialize,
                name=name,
            )
            session = Session(name=name, backend=backend)
            session.open()
            self._sessions[name] = session
            if make_default or self._default is None:
                self._default = name
            return session

    def close(self, name: str | None = None) -> bool:
        with self._lock:
            target = name or self._default
            if target is None:
                return False
            session = self._sessions.pop(target, None)
            if session is None:
                return False
            session.close()
            if self._default == target:
                self._default = next(iter(self._sessions), None)
            return True

    def close_all(self) -> None:
        with self._lock:
            for session in list(self._sessions.values()):
                session.close()
            self._sessions.clear()
            self._default = None

    # -- access ------------------------------------------------------------
    def get(self, name: str | None = None) -> Session:
        with self._lock:
            target = name or self._default
            if target is None:
                raise InvalidArgument("no session is open; call session_open first")
            session = self._sessions.get(target)
            if session is None:
                known = ", ".join(sorted(self._sessions)) or "<none>"
                raise NotFound(f"no session named {target!r}; open sessions: {known}")
            return session

    def list(self) -> list[dict]:
        with self._lock:
            return [session.info() for session in self._sessions.values()]

    def all(self) -> list["Session"]:
        """Snapshot of the open sessions (their order is registration order)."""
        with self._lock:
            return list(self._sessions.values())

    @property
    def default(self) -> str | None:
        return self._default

    def reset(self) -> None:
        """Drop all state (used by tests)."""
        self.close_all()
