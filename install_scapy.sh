#!/bin/bash
# Install scapy for traffic analysis support

echo "Installing scapy for passive traffic analysis..."
echo "This may require sudo privileges for system dependencies."
echo

# Check if we're in a virtual environment
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "✓ Virtual environment detected: $VIRTUAL_ENV"
else
    echo "⚠ No virtual environment detected. It's recommended to use a virtual environment."
    echo "  Create one with: python3 -m venv venv && source venv/bin/activate"
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Install system dependencies if needed (for packet capture)
if command -v apt-get &> /dev/null; then
    echo "Installing system dependencies (Debian/Ubuntu)..."
    sudo apt-get update
    sudo apt-get install -y tcpdump python3-dev libpcap-dev
elif command -v yum &> /dev/null; then
    echo "Installing system dependencies (RHEL/CentOS)..."
    sudo yum install -y tcpdump python3-devel libpcap-devel
elif command -v brew &> /dev/null; then
    echo "Installing system dependencies (macOS)..."
    brew install libpcap
fi

# Install scapy
echo
echo "Installing scapy..."
pip install scapy==2.5.0

# Verify installation
echo
echo "Verifying installation..."
python3 -c "from scapy.all import sniff; print('✓ Scapy installed successfully')" 2>/dev/null || {
    echo "❌ Scapy installation failed"
    echo "You may need to install it manually with: pip install scapy"
    exit 1
}

echo
echo "✅ Scapy installation complete!"
echo "Passive traffic analysis is now available in NetworkMapper."
echo
echo "Note: Running passive traffic analysis requires root/sudo privileges."