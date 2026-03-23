#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

log() {
  printf '%s\n' "$1" >&2
}

find_command() {
  local name="$1"
  shift
  local candidate
  for candidate in "$name" "$@"; do
    if command -v "$candidate" >/dev/null 2>&1; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

require_command() {
  local name="$1"
  shift
  local candidate
  candidate="$(find_command "$name" "$@")" || {
    log "$name: missing (required)"
    exit 1
  }
  log "$name: $("$candidate" --version 2>&1 | head -n 1)"
  printf '%s' "$candidate"
}

optional_command() {
  local name="$1"
  shift
  local candidate
  if candidate="$(find_command "$name" "$@")"; then
    log "$name: $("$candidate" --version 2>&1 | head -n 1)"
  else
    log "$name: missing (optional)"
  fi
}

log "Pengetic Linux bootstrap"
PYTHON_BIN="$(require_command "python3")"
NODE_BIN="$(require_command "node" "node.exe")"
NPM_BIN="$(require_command "npm" "npm.cmd")"
optional_command "git"
optional_command "ollama" "ollama.exe"

if ! "$PYTHON_BIN" - <<'PY'; then
import sys
raise SystemExit(0 if sys.version_info >= (3, 12) else 1)
PY
  log "Python 3.12 or newer is required."
  exit 1
fi

VENV_DIR="$ROOT_DIR/.venv"
if [[ ! -d "$VENV_DIR" ]]; then
  log "Creating virtual environment at $VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

find_venv_python() {
  local candidate
  for candidate in \
    "$VENV_DIR/bin/python" \
    "$VENV_DIR/bin/python3" \
    "$VENV_DIR/Scripts/python.exe" \
    "$VENV_DIR/Scripts/python"; do
    if [[ -x "$candidate" ]]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

VENV_PYTHON="$(find_venv_python)" || {
  log "Virtual environment bootstrap failed: no Python executable was created under $VENV_DIR."
  exit 1
}

log "Upgrading pip"
"$VENV_PYTHON" -m pip install --upgrade pip

log "Installing Pengetic in editable mode"
"$VENV_PYTHON" -m pip install -e .

log "Installing frontend dependencies"
pushd "$ROOT_DIR/frontend" >/dev/null
"$NPM_BIN" install
log "Building frontend production bundle"
"$NPM_BIN" run build
popd >/dev/null

log "Running Pengetic doctor"
"$VENV_PYTHON" -m pengetic doctor --check-ollama

log ""
log "Install complete."
log "Launch Pengetic with:"
log "  ./scripts/run_pengetic.sh"
log "or:"
log "  $VENV_PYTHON -m pengetic serve"
