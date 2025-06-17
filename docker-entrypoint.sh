#!/bin/bash
# Docker entrypoint script for NetworkMapper v2
# Handles privilege management and network configuration

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running in Docker
if [ ! -f /.dockerenv ]; then
    log_error "This script should only be run inside a Docker container"
    exit 1
fi

# Ensure output directory permissions
if [ -d "/app/output" ]; then
    sudo chown -R netmapper:netmapper /app/output 2>/dev/null || true
fi

# Network interface detection
if [ -z "$INTERFACE" ]; then
    # Try to detect the default interface
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -z "$INTERFACE" ]; then
        # Fallback to first non-loopback interface
        INTERFACE=$(ip link show | grep -E "^[0-9]+" | grep -v "lo:" | head -n1 | cut -d: -f2 | tr -d ' ')
    fi
fi

if [ -n "$INTERFACE" ]; then
    log_info "Using network interface: $INTERFACE"
    export INTERFACE
else
    log_warn "No network interface detected. Some features may not work correctly."
fi

# Check network capabilities
check_capabilities() {
    log_info "Checking network capabilities..."
    
    # Test if we can use raw sockets
    if sudo -n nmap --iflist &>/dev/null; then
        log_info "✓ Nmap capabilities: OK"
    else
        log_warn "⚠ Nmap may have limited functionality"
    fi
    
    if sudo -n masscan --iflist &>/dev/null; then
        log_info "✓ Masscan capabilities: OK"
    else
        log_warn "⚠ Masscan may not work properly"
    fi
    
    if sudo -n arp-scan --version &>/dev/null; then
        log_info "✓ ARP-scan capabilities: OK"
    else
        log_warn "⚠ ARP-scan may not work properly"
    fi
}

# Print welcome message
print_welcome() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "           NetworkMapper v2 - Docker Container"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    log_info "Container initialized successfully"
    log_info "Output directory: /app/output (mounted volume)"
    echo ""
}

# Handle special commands
case "${1}" in
    "check")
        # Just check capabilities and exit
        check_capabilities
        exit 0
        ;;
    "shell"|"bash")
        # Interactive shell
        log_info "Starting interactive shell..."
        exec /bin/bash
        ;;
    "test")
        # Run tests
        log_info "Running test suite..."
        shift
        exec pytest "$@"
        ;;
esac

# Main execution
print_welcome

# If no arguments provided, show interactive menu
if [ $# -eq 0 ] || [ "$1" = "python3" -a "$2" = "mapper.py" -a $# -eq 2 ]; then
    log_info "Starting NetworkMapper interactive mode..."
    check_capabilities
    echo ""
    exec python3 mapper.py
else
    # Pass through all arguments
    if [[ "$1" == "python3" ]] || [[ "$1" == "python" ]]; then
        # Direct Python execution
        exec "$@"
    elif [[ "$1" == "mapper.py" ]] || [[ "$1" == "./mapper.py" ]]; then
        # Run mapper.py with remaining arguments
        shift
        exec python3 mapper.py "$@"
    else
        # Assume arguments are for mapper.py
        exec python3 mapper.py "$@"
    fi
fi