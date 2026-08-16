#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="./sentinel_daemon.log"
PID_FILE="./sentinel_daemon.pid"

if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
    echo "[!] Sentinel daemon is already running (PID: $(cat "$PID_FILE"))."
    exit 0
fi

nohup python3 src/scripts/run_sentinel.py ./monitored ./quarantine > "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"

echo "[SUCCESS] Sentinel daemon started in background (PID: $(cat "$PID_FILE"))."
echo "[*] Monitoring directory: ./monitored -> Quarantining to: ./quarantine"
echo "[*] Log stream: $LOG_FILE"
