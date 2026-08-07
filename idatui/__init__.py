"""idatui — a keyboard-first TUI using shared IDA Code Mode databases."""

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
from .codemode_client import CodeModeClient
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
    "CodeModeClient",
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
