#!/bin/bash
# Docker health check script for NetworkMapper

# Check if Python is working
python3 -c "import sys; sys.exit(0)" || exit 1

# Check if NetworkMapper can be imported
python3 -c "import mapper" || exit 1

# Check if critical network tools are available
which nmap >/dev/null 2>&1 || exit 1
which masscan >/dev/null 2>&1 || exit 1
which arp-scan >/dev/null 2>&1 || exit 1

# Check if output directory is writable
touch /app/output/.healthcheck 2>/dev/null && rm -f /app/output/.healthcheck || exit 1

# All checks passed
exit 0