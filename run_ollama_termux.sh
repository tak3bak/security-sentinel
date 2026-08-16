#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# Configuration
OLLAMA_LOG="${HOME}/.ollama/ollama.log"
PID_FILE="${HOME}/.ollama/ollama.pid"

mkdir -p "${HOME}/.ollama"

# Optimized Environment Variables
export OLLAMA_HOST="0.0.0.0:11434"
export OLLAMA_FLASH_ATTENTION="1"
export OLLAMA_KV_CACHE_TYPE="q8_0"
export OLLAMA_NUM_PARALLEL="4"
export OLLAMA_KEEP_ALIVE="24h"
export OLLAMA_GPU_OVERHEAD="536870912"

start_daemon() {
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "[WARN] Ollama is already running (PID: $(cat "$PID_FILE"))."
        return 0
    fi

    echo "[INFO] Acquiring Termux wake-lock..."
    termux-wake-lock || true

    echo "[INFO] Launching Ollama daemon with quantized KV cache & FlashAttention..."
    nohup ollama serve > "$OLLAMA_LOG" 2>&1 &
    echo $! > "$PID_FILE"

    sleep 2
    if kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "[SUCCESS] Ollama running on ${OLLAMA_HOST} (PID: $(cat "$PID_FILE"))."
    else
        echo "[ERROR] Ollama failed to start. Inspect logs: cat ${OLLAMA_LOG}" >&2
        exit 1
    fi
}

stop_daemon() {
    if [ -f "$PID_FILE" ]; then
        PID="$(cat "$PID_FILE")"
        echo "[INFO] Stopping Ollama daemon (PID: ${PID})..."
        kill "$PID" 2>/dev/null || true
        rm -f "$PID_FILE"
        echo "[INFO] Releasing Termux wake-lock..."
        termux-wake-unlock || true
        echo "[SUCCESS] Ollama stopped."
    else
        echo "[WARN] No PID file found. Killing any stray ollama processes..."
        pkill -f "ollama serve" 2>/dev/null || true
        termux-wake-unlock || true
    fi
}

status_daemon() {
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "[STATUS] Active (PID: $(cat "$PID_FILE"))"
        echo "[STATUS] Active Environment:"
        tr '\0' '\n' < "/proc/$(cat "$PID_FILE")/environ" | grep -E '^OLLAMA_' || true
    else
        echo "[STATUS] Inactive"
    fi
}

case "${1:-start}" in
    start)
        start_daemon
        ;;
    stop)
        stop_daemon
        ;;
    restart)
        stop_daemon
        sleep 1
        start_daemon
        ;;
    status)
        status_daemon
        ;;
    logs)
        tail -f "$OLLAMA_LOG"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}" >&2
        exit 1
        ;;
esac
