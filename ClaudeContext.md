# NetworkMapper v2

A Python-based CLI tool for network discovery, device classification, and change tracking with interactive visualizations.

## 🚀 Quick Start

```bash
# Clone the repository
git clone <repository-url>
cd network_mapper

# Run automated setup
python3 setup.py

# Activate virtual environment
source venv/bin/activate

# Start NetworkMapper
python3 mapper.py
```

## 📋 Features

- **Network Discovery**: Fast host discovery using nmap or masscan
- **Device Classification**: Automatic identification of routers, switches, servers, IoT devices
- **Change Tracking**: Detect new, missing, and modified devices between scans
- **Interactive Visualization**: 2D (D3.js) and 3D (Three.js) network maps
- **Asset Management**: Annotate devices with notes, tags, and criticality flags
- **Report Generation**: HTML reports that auto-open in your browser

## 🔧 System Requirements

- Python 3.8+
- nmap (required)
- masscan (optional, for faster discovery)
- arp-scan (optional, for MAC address discovery)

## 📁 Project Structure

```
network_mapper/
├── mapper.py              # Main CLI interface
├── core/                  # Core scanning and analysis logic
├── utils/                 # Utility functions
├── templates/             # HTML report templates
├── static/                # CSS/JS assets
└── output/               # Scan results and reports
```

## 🎯 Usage Examples

### Basic Network Discovery
```bash
python3 mapper.py
# Select: 1 (Run Network Scan)
# Enter: 192.168.1.0/24
# Select: 1 (Discovery Scan)
```

### Full Inventory Scan
```bash
python3 mapper.py
# Select: 1 (Run Network Scan)
# Enter: 192.168.1.0/24
# Select: 2 (Inventory Scan)
```

### View Network Changes
```bash
python3 mapper.py
# Select: 3 (Check Changes)
```

## 📊 Scan Types

1. **Discovery Scan** (~30 seconds)
   - Host discovery only
   - Uses ping scan
   - No root required

2. **Inventory Scan** (~5 minutes)
   - Service and OS detection
   - Top 1000 ports
   - Requires sudo

3. **Deep Scan** (~15 minutes)
   - Full port scan
   - Script scanning
   - Requires sudo

## 🏷️ Device Annotation

Mark critical infrastructure and add notes:

```bash
python3 mapper.py
# Select: 4 (Annotate Devices)
# Follow prompts to tag devices
```

## 📈 Reports

Reports include:
- Device inventory table
- Network topology visualization (2D)
- 3D network view
- Subnet summaries
- Change history

Reports are saved to `output/reports/` and automatically open in your browser.

## 🔌 Extending NetworkMapper

### Add New Device Types

Edit `core/classifier.py`:
```python
self.port_signatures['iot_camera'] = {
    'ports': [80, 554, 8080],
    'services': ['http', 'rtsp'],
    'keywords': ['camera', 'ipcam']
}
```

### Add Custom Scan Profiles

Edit `core/scanner.py`:
```python
self.scan_profiles['web_servers'] = {
    'nmap': ['-sS', '-p', '80,443,8080,8443'],
    'description': 'Web server detection'
}
```

## ⚠️ Important Notes

- Always ensure you have permission to scan networks
- Some scan types require sudo/administrator privileges
- Scans are saved locally in JSON format for easy processing
- All data is stored in files (no database required)

## 🐛 Troubleshooting

**"Permission Denied" errors**
- Some scans require sudo access
- The tool will prompt when needed

**No devices found**
- Check network connectivity
- Verify the target subnet is correct
- Try a slower scan timing (-T2)

**Missing dependencies**
- Run `python3 setup.py` to check requirements
- Install missing tools with your package manager

## 📄 License

This tool is for authorized network administration only. Always ensure you have permission to scan networks.