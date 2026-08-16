#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="./api_gateway.log"
PID_FILE="./api_gateway.pid"

if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
    echo "[!] API Gateway is already running (PID: $(cat "$PID_FILE"))."
    exit 0
fi

nohup python3 src/scripts/run_api.py > "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"

echo "[SUCCESS] API Gateway started in background (PID: $(cat "$PID_FILE"))."
echo "[*] Listening on: http://0.0.0.0:8080"
echo "[*] Log stream: $LOG_FILE"
