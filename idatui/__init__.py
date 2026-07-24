"""idatui — a minimal keyboard-first TUI for IDA Pro, driving idalib via a
private unix-socket worker (idatui.worker / WorkerClient)."""

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
    "IDAError",
    "IDAConnectionError",
    "IDATimeoutError",
    "IDAProtocolError",
    "IDARPCError",
    "IDAToolError",
    "IDASessionError",
    "Session",
]
