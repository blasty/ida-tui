"""TUI-facing error hierarchy and lightweight database session model.

The Code Mode adapter normalizes ``ida_codemode.client`` transport and execution
errors into these types so the domain and Textual layers do not depend on HTTP or
registry implementation details.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class IDAError(Exception):
    """Base class for all client errors."""


class IDAConnectionError(IDAError):
    """The transport could not be established or was lost."""


class IDATimeoutError(IDAError):
    """A request exceeded its deadline."""


class IDAProtocolError(IDAError):
    """Malformed or unexpected HTTP / JSON-RPC framing."""


class IDARPCError(IDAError):
    """The JSON-RPC envelope carried an ``error`` object."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(f"JSON-RPC error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


class IDAToolError(IDAError):
    """A tool call returned ``result.isError == true`` (a hard failure)."""

    def __init__(self, tool: str, message: str):
        super().__init__(f"tool {tool!r} failed: {message}")
        self.tool = tool
        self.message = message


class IDASessionError(IDAError):
    """No IDB session is open, or several are and none was pinned."""


# --------------------------------------------------------------------------- #
# Session model
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Session:
    session_id: str
    filename: str
    input_path: str
    is_active: bool = False
    is_analyzing: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "Session":
        return cls(
            session_id=d.get("session_id", ""),
            filename=d.get("filename", ""),
            input_path=d.get("input_path", ""),
            is_active=bool(d.get("is_active", False)),
            is_analyzing=bool(d.get("is_analyzing", False)),
        )
