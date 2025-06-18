#!/bin/bash
# Host-side script to open URLs passed from Docker container
# This script will be mounted inside the container and used to open URLs on the host

if [ -z "$1" ]; then
    echo "Usage: $0 <URL>"
    exit 1
fi

# Use xdg-open if available (Linux), open on macOS, or start on Windows
if command -v xdg-open > /dev/null; then
    xdg-open "$1" 2>/dev/null
elif command -v open > /dev/null; then
    open "$1" 2>/dev/null
elif command -v start > /dev/null; then
    start "$1" 2>/dev/null
else
    echo "No suitable command found to open URLs"
    exit 1
fi