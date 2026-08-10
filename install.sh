#!/usr/bin/env bash
set -euo pipefail

echo "==> Initializing setup in user space..."

INSTALL_DIR="${HOME}/.local/share/sentinel_app"
mkdir -p "$INSTALL_DIR"

if ! command -v python3 &> /dev/null; then
    echo "Error: Python3 is required."
    exit 1
fi

echo "==> Creating virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

if [ -f "requirements.txt" ]; then
    echo "==> Installing dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
fi

echo "==> Setup complete! Venv at: $INSTALL_DIR/venv"
