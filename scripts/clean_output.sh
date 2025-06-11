#!/bin/bash
# Quick shell script wrapper for the Python cleanup script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Run the Python cleanup script, passing any arguments
python3 scripts/clean_output.py "$@"