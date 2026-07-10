#!/usr/bin/env python3
"""Inject idatui's extra ida-pro-mcp tools into the installed server package.

ida-pro-mcp exposes no delete-type tool, which idatui's struct editor needs for
the 'D' in CRUD. Rather than vendor/fork the server, we keep the tool source here
and append it (idempotently) to the installed ``api_types.py``. That module is
imported by every worker (``python -m ida_pro_mcp.idalib_server``), so the tool
registers itself via ``@tool`` on the shared ``MCP_SERVER`` — no server code is
forked, and re-running this (spawn.sh does, on every start) re-applies it after a
reinstall/upgrade of ida-pro-mcp.

Run with the *same* interpreter the server uses (the idalib-mcp entry point's
``/usr/bin/python``), so it patches the file the workers actually import.
Safe to run repeatedly; a no-op once applied.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys

BEGIN = "# >>> idatui-ext: begin (auto-injected by server/patch_server.py) >>>"
END = "# <<< idatui-ext: end <<<"

# Appended to ida_pro_mcp/ida_mcp/api_types.py, which already imports
# ``Annotated``, ``tool``, ``idasync`` and ``ida_typeinf`` at module scope.
SNIPPET = f'''

{BEGIN}
@tool
@idasync
def del_type(
    name: Annotated[str, "Local type name to delete (struct/union/enum/typedef)"],
) -> dict:
    """Delete a named local type from the local type library."""
    til = ida_typeinf.get_idati()
    ok = ida_typeinf.del_named_type(til, name, ida_typeinf.NTF_TYPE)
    if not ok:
        return {{"name": name, "error": f"Type '{{name}}' not found or could not be deleted"}}
    return {{"name": name, "deleted": True}}
{END}
'''


def api_types_path() -> pathlib.Path | None:
    """Locate ida_pro_mcp/ida_mcp/api_types.py without importing it (importing the
    submodule would pull in IDA, which isn't available outside a worker)."""
    spec = importlib.util.find_spec("ida_pro_mcp")  # top-level pkg is IDA-free
    if spec is None or not spec.submodule_search_locations:
        return None
    p = pathlib.Path(spec.submodule_search_locations[0]) / "ida_mcp" / "api_types.py"
    return p if p.exists() else None


def main() -> int:
    path = api_types_path()
    if path is None:
        print("idatui: ida_pro_mcp not found; skipping del_type injection", file=sys.stderr)
        return 0
    text = path.read_text()
    if BEGIN in text:
        return 0  # already applied
    try:
        path.write_text(text.rstrip() + "\n" + SNIPPET)
    except OSError as e:
        print(f"idatui: could not patch {path}: {e}", file=sys.stderr)
        return 1
    print(f"idatui: injected del_type into {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
