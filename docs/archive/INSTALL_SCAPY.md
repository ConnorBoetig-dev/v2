# Installing Scapy for Passive Traffic Analysis

The passive traffic analysis feature requires Scapy, a powerful packet manipulation library. Here's how to install it:

## Installation Methods

### 1. Using pip (Recommended)
```bash
# Install scapy with all optional dependencies
pip install scapy[complete]

# Or minimal installation
pip install scapy
```

### 2. Using apt (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install python3-scapy
```

### 3. Using your virtual environment
```bash
# Activate your virtual environment first
source venv/bin/activate

# Then install scapy
pip install scapy[complete]
```

## Additional Dependencies

For full functionality, you may also want:

```bash
# For better packet capture performance
sudo apt install tcpdump

# For network interface detection
pip install netifaces

# For HTTP packet parsing
pip install scapy-http
```

## Permissions

Passive traffic analysis requires root/sudo privileges to capture packets:

```bash
# Run NetworkMapper with sudo
sudo python3 mapper.py

# Or if using virtual environment
sudo venv/bin/python3 mapper.py
```

## Testing Scapy Installation

```python
# Test if scapy is properly installed
python3 -c "from scapy.all import sniff; print('Scapy installed successfully!')"
```

## Troubleshooting

### If you see "Scapy is required for passive traffic analysis"
- Scapy is not installed in your Python environment
- Install using one of the methods above

### If you see "This feature requires root/sudo privileges"
- Packet capture requires elevated permissions
- Run the application with sudo

### If passive analysis still doesn't work
- Check that your network interface is correctly detected
- Try specifying the interface manually in the code
- Ensure no firewall is blocking packet capture

## Alternative: Run Without Passive Analysis

If you don't need passive traffic analysis, you can simply:
1. Choose "No" when asked about enabling passive traffic analysis
2. The rest of NetworkMapper will work normally without scapy

## Security Note

Packet capture requires elevated privileges because it accesses network hardware directly. Always be cautious when running applications with sudo, and only use passive analysis on networks you own or have permission to monitor.