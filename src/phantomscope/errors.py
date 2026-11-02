"""Exception hierarchy shared by every phantomscope layer."""

from __future__ import annotations


class PhantomError(Exception):
    """Base class for all phantomscope errors."""

    code = "error"

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def to_dict(self) -> dict[str, str]:
        out = {"error": self.code, "message": self.message}
        if self.detail:
            out["detail"] = self.detail
        return out


class InvalidArgument(PhantomError):
    code = "invalid_argument"


class NotFound(PhantomError):
    code = "not_found"


class Unavailable(PhantomError):
    """The backend or optional dependency cannot provide the requested feature."""

    code = "unavailable"


class BackendError(PhantomError):
    code = "backend_error"


class AccessDenied(BackendError):
    code = "access_denied"
