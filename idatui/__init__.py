"""idatui — a keyboard-first TUI using shared IDA Nexus databases."""

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
from .nexus_client import NexusClient
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
    "NexusClient",
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
