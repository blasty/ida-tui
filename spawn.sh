#!/bin/sh
# Start the ida-pro-mcp supervisor. IDA_MCP_MAX_WORKERS raises the ceiling on
# concurrently-open binaries (default 4); idle workers self-exit and free slots.
#
# Location-independent: resolves paths relative to this script, not $PWD, so it
# behaves the same whether run by hand or from the systemd unit (see
# systemd/idatui-mcp.service).
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

IDA_MCP_HOST="${IDA_MCP_HOST:-127.0.0.1}"
IDA_MCP_PORT="${IDA_MCP_PORT:-8745}"
IDA_MCP_TARGET="${IDA_MCP_TARGET:-$SCRIPT_DIR/bin/ls}"

# Ensure idatui's extra server tools (del_type, needed by the struct editor) are
# present in the installed ida-pro-mcp. Idempotent; patches the api_types.py that
# the /usr/bin/python workers import. See server/patch_server.py.
/usr/bin/python "$SCRIPT_DIR/server/patch_server.py" || \
  echo "warn: server patch skipped (del_type may be unavailable)"

cd "$SCRIPT_DIR"
exec env IDA_MCP_MAX_WORKERS="${IDA_MCP_MAX_WORKERS:-8}" \
  uv run idalib-mcp --host "$IDA_MCP_HOST" --port "$IDA_MCP_PORT" "$IDA_MCP_TARGET"
