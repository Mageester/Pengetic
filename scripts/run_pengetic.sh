#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
OPEN_BROWSER="${OPEN_BROWSER:-0}"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON="$ROOT_DIR/.venv/bin/python"
elif [[ -x "$ROOT_DIR/.venv/bin/python3" ]]; then
  PYTHON="$ROOT_DIR/.venv/bin/python3"
elif [[ -x "$ROOT_DIR/.venv/Scripts/python.exe" ]]; then
  PYTHON="$ROOT_DIR/.venv/Scripts/python.exe"
elif [[ -x "$ROOT_DIR/.venv/Scripts/python" ]]; then
  PYTHON="$ROOT_DIR/.venv/Scripts/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
  PYTHON="$(command -v python)"
else
  echo "Python is required. Run scripts/install_linux.sh first."
  exit 1
fi

if [[ "$OPEN_BROWSER" == "1" ]]; then
  if command -v xdg-open >/dev/null 2>&1; then
    (sleep 2; xdg-open "http://${HOST}:${PORT}/" >/dev/null 2>&1 || true) &
  fi
fi

"$PYTHON" -m pengetic serve --host "$HOST" --port "$PORT" --no-reload
