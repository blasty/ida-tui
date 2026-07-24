"""idatui — a minimal keyboard-first TUI for IDA Pro over ida-pro-mcp (idalib)."""

from .errors import (
    IDAError,
    IDAConnectionError,
    IDATimeoutError,
    IDAProtocolError,
    IDARPCError,
    IDAToolError,
    IDASessionError,
    Session,
)
from .client import IDAClient, KeepAlive  # deprecated mcp transport
from .domain import (
    Program,
    FunctionIndex,
    DisasmModel,
    Func,
    Line,
    Ref,
    Struct,
    Decompilation,
    LIST_PAGE,
    DISASM_BLOCK,
)

__all__ = [
    "Program",
    "FunctionIndex",
    "DisasmModel",
    "Func",
    "Line",
    "Ref",
    "Struct",
    "Decompilation",
    "LIST_PAGE",
    "DISASM_BLOCK",
    "IDAClient",
    "IDAError",
    "IDAConnectionError",
    "IDATimeoutError",
    "IDAProtocolError",
    "IDARPCError",
    "IDAToolError",
    "IDASessionError",
    "Session",
    "KeepAlive",
]
