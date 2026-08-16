#!/usr/bin/env bash
PID_FILE="./sentinel_daemon.pid"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID"
        echo "[SUCCESS] Sentinel daemon (PID: $PID) stopped."
    else
        echo "[!] Process $PID not active."
    fi
    rm -f "$PID_FILE"
else
    echo "[!] No active daemon PID file found."
fi
