#!/usr/bin/env bash
# Control the ida-pro-mcp server for stress testing. Assumes ~/ida-venv + spawn.sh.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PORT=8745
LOG=/tmp/ida-stress-spawn.log

wait_port() {  # wait_port <up|down> <secs>
  local want="$1" secs="${2:-40}" i
  for ((i=0; i<secs*2; i++)); do
    if ss -ltn 2>/dev/null | grep -q ":$PORT "; then
      [ "$want" = up ] && return 0
    else
      [ "$want" = down ] && return 0
    fi
    sleep 0.5
  done
  return 1
}

wait_ready() {  # wait until hexrays_ready via the client
  local secs="${1:-60}" i
  for ((i=0; i<secs; i++)); do
    if python3 -c "
import sys; sys.path.insert(0,'$REPO')
from idatui.client import IDAClient
try:
    c=IDAClient(); c.connect()
    ss=[s for s in c.list_sessions() if s.session_id]
    if ss:
        c.set_db(ss[0].session_id)
        if c.health().get('hexrays_ready'): print(ss[0].session_id); sys.exit(0)
except Exception: pass
sys.exit(1)
" 2>/dev/null; then return 0; fi
    sleep 1
  done
  return 1
}

case "${1:-}" in
  start)
    cd "$REPO"
    source ~/ida-venv/bin/activate 2>/dev/null
    nohup ./spawn.sh >"$LOG" 2>&1 &
    wait_port up 40 || { echo "PORT_TIMEOUT"; tail -5 "$LOG"; exit 1; }
    wait_ready 90 || { echo "READY_TIMEOUT"; tail -5 "$LOG"; exit 1; }
    ;;
  stop)
    # Kill the whole tree: uv wrapper, supervisor, worker.
    pkill -9 -f 'idalib_server' 2>/dev/null
    pkill -9 -f 'idalib-mcp'    2>/dev/null
    pkill -9 -f 'uv run idalib' 2>/dev/null
    wait_port down 20 || { echo "STOP_TIMEOUT"; exit 1; }
    ;;
  kill9)
    # Hard kill only the worker (simulate a crash of the analysis process).
    pkill -9 -f 'idalib_server' 2>/dev/null
    ;;
  ready)
    wait_ready "${2:-60}"
    ;;
  *)
    echo "usage: $0 {start|stop|kill9|ready [secs]}"; exit 2;;
esac
