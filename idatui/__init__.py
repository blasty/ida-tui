"""idatui — a minimal keyboard-first TUI for IDA Pro over ida-pro-mcp (idalib)."""

from .client import (
    IDAClient,
    IDAError,
    IDAConnectionError,
    IDATimeoutError,
    IDAProtocolError,
    IDARPCError,
    IDAToolError,
    IDASessionError,
    Session,
    KeepAlive,
)
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
