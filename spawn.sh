#!/bin/sh
# Start the ida-pro-mcp supervisor. IDA_MCP_MAX_WORKERS raises the ceiling on
# concurrently-open binaries (default 4); idle workers self-exit and free slots.
IDA_MCP_MAX_WORKERS="${IDA_MCP_MAX_WORKERS:-8}" \
  uv run idalib-mcp --host 127.0.0.1 --port 8745 $(pwd)/bin/ls
