#!/bin/sh
# Start the ida-pro-mcp supervisor. IDA_MCP_MAX_WORKERS raises the ceiling on
# concurrently-open binaries (default 4); idle workers self-exit and free slots.

# Ensure idatui's extra server tools (del_type, needed by the struct editor) are
# present in the installed ida-pro-mcp. Idempotent; patches the api_types.py that
# the /usr/bin/python workers import. See server/patch_server.py.
/usr/bin/python "$(dirname "$0")/server/patch_server.py" || \
  echo "warn: server patch skipped (del_type may be unavailable)"

IDA_MCP_MAX_WORKERS="${IDA_MCP_MAX_WORKERS:-8}" \
  uv run idalib-mcp --host 127.0.0.1 --port 8745 $(pwd)/bin/ls
