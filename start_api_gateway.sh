#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${HOME:-/data/data/com.termux/files/home}/security-sentinel"
VENV_PY="${HOME:-/data/data/com.termux/files/home}/.venv-sentinel/bin/python"
ENV_FILE="${REPO_DIR}/.env"
LOG_FILE="${REPO_DIR}/api_gateway.log"
PID_FILE="${REPO_DIR}/api_gateway.pid"

cd "$REPO_DIR"

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "[!] API Gateway is already running (PID: $(cat "$PID_FILE"))."
    exit 0
fi

if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
fi

export HOST="${HOST:-127.0.0.1}"
export PORT="${PORT:-8000}"

PY_BIN="$VENV_PY"
if [ ! -x "$PY_BIN" ]; then
    PY_BIN="python3"
fi

nohup "$PY_BIN" src/scripts/run_api.py > "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"

sleep 1
if kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "[SUCCESS] API Gateway started in background (PID: $(cat "$PID_FILE"))."
    echo "[*] Listening on: http://${HOST}:${PORT}"
    echo "[*] Log stream: $LOG_FILE"
else
    echo "[ERROR] API Gateway failed to start. Inspect logs: cat $LOG_FILE" >&2
    exit 1
fi
