#!/bin/bash
set -e
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$PROJECT_DIR/venv/bin/python3"
cd "$PROJECT_DIR"
if [ -f "$VENV_PYTHON" ]; then $VENV_PYTHON "$PROJECT_DIR/mapper.py" "$@"; else echo "Error: Virtual environment not found. Please run make setup."; exit 1; fi
