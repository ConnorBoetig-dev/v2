# NetworkMapper v2

A comprehensive Python-based network discovery and security assessment tool that combines multiple scanning technologies with advanced visualization and vulnerability analysis.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)

## Features

- **🔍 Multi-Scanner Support**: Intelligent use of nmap, masscan, and arp-scan
- **🎯 Smart Device Classification**: Identifies 16+ device types using ML-like signatures
- **🔐 Vulnerability Assessment**: Real-time CVE correlation using free APIs (OSV, CIRCL)
- **📊 Interactive Visualizations**: 2D/3D network maps and traffic flow animations
- **📈 Change Tracking**: Monitors network changes between scans with advanced comparison tools
- **🔌 SNMP Integration**: Device enrichment with SNMP v1/v2c/v3 support
- **📑 Advanced Reporting**: HTML, PDF, Excel, CSV, and JSON exports
- **🎨 Professional UI**: Rich CLI with progress tracking and intuitive menus
- **🌊 Passive Analysis**: Discover stealth devices and map traffic flows in real-time

## Scan Types

### 🚀 Discovery Scan (Default)
- **Duration**: ~30 seconds
- **Purpose**: Quick network reconnaissance
- **Best for**: Initial discovery, finding new devices
- **Options**: Standard (nmap) or High-Speed (masscan)

### 📋 Inventory Scan
- **Duration**: ~5 minutes
- **Purpose**: Detailed device profiling with services and OS detection
- **Best for**: Asset management, documentation, compliance
- **Requires**: sudo/admin privileges

### 🔒 Deep Scan
- **Duration**: ~15 minutes
- **Purpose**: Comprehensive security assessment
- **Best for**: Security audits, vulnerability discovery
- **Features**: Scans top 5000 ports with NSE scripts

### 🔗 ARP Scan
- **Duration**: ~10 seconds
- **Purpose**: Layer 2 discovery for local networks
- **Best for**: Finding hidden devices, IoT discovery
- **Note**: Local networks only

### Additional Features
- **SNMP Enrichment**: Automatic device information gathering
- **Vulnerability Scanning**: CVE correlation with CVSS scores
- **Passive Analysis**: Real-time traffic capture and flow mapping

## Quick Start

### 🐳 Easiest Method - Docker (Recommended for Sharing)

```bash
# Clone the repository
git clone https://github.com/yourusername/networkmapper-v2.git
cd networkmapper-v2

# Build and run with Docker (no setup required!)
make docker-build
make docker-run
```

### 💻 Local Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/networkmapper-v2.git
cd networkmapper-v2

# Automated setup
make setup

# Run the tool
./venv/bin/python mapper.py
```

## Installation

### System Requirements
- Python 3.8 or higher
- Operating System: Linux, macOS, or Windows (with WSL)
- Network access and appropriate permissions for scanning

### Required System Packages
```bash
# Core scanner (required)
sudo apt install nmap

# Optional but recommended
sudo apt install arp-scan    # For Layer 2 discovery
sudo apt install masscan     # For high-speed scanning
```

### Python Dependencies
```bash
# Install all dependencies (includes testing and development tools)
pip3 install -r requirements.txt

# For production only (minimal dependencies)
pip3 install typer rich python-nmap requests jinja2 pyyaml reportlab openpyxl pandas pysnmp flask
```

### Platform-Specific Installation

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv nmap arp-scan masscan

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

#### macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install system packages
brew install python nmap arp-scan

# Masscan on macOS (build from source)
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
sudo make install

# Install Python dependencies
pip3 install -r requirements.txt
```

#### Windows (WSL2)
```bash
# In WSL2 Ubuntu terminal
sudo apt update
sudo apt install python3 python3-pip nmap arp-scan
pip3 install -r requirements.txt
```

### Docker Installation
```bash
# Build the container
docker build -t networkmapper .

# Run with host network access
docker run -it --network host --privileged networkmapper

# Or with volume for persistent data
docker run -it --network host --privileged -v $(pwd)/output:/app/output networkmapper
```

### Verify Installation
```bash
# Check Python version
python3 --version  # Should be 3.8+

# Check scanners
which nmap         # Should show path
which arp-scan     # Optional
which masscan      # Optional

# Test the application
python3 mapper.py --help
```

## Usage

### Interactive Mode (Recommended)
```bash
python3 mapper.py
```

### Command Line Options
```bash
# Disable SNMP enrichment
python3 mapper.py --disable-snmp

# Specify SNMP settings
python3 mapper.py --snmp-community private --snmp-version v2c
```

### Using Helper Scripts
```bash
./quick_start.sh    # Quick setup and launch
./run_demo.sh       # Run demo scenarios
python scripts/verify_installation.py  # Verify setup
python scripts/test_core_functionality.py  # Test features
```

## Scan Types

1. **Discovery Scan** (~30 seconds)
   - Quick host discovery
   - Basic port scanning
   - Ideal for initial mapping

2. **Inventory Scan** (~5 minutes)
   - Comprehensive port scanning
   - Service version detection
   - OS fingerprinting

3. **Deep Scan** (~15 minutes)
   - All ports (1-65535)
   - Advanced service detection
   - Script scanning

4. **ARP Scan** (~10 seconds)
   - Layer 2 discovery
   - Local network only
   - MAC address collection

## Key Features Explained

### Vulnerability Assessment
- **Primary API**: OSV (Google) - no key required
- **Fallback API**: CIRCL CVE Search - community maintained
- **Local Patterns**: Built-in detection for common vulnerabilities
- **Automatic Caching**: 24-hour cache to minimize API calls

### SNMP Integration
- Interactive configuration wizard
- Support for v1, v2c, and v3
- Secure credential storage
- Automatic device enrichment

### Report Types
- **Network Map**: Interactive D3.js visualization
- **Security Report**: Vulnerability analysis and risk assessment
- **Services Report**: Network service distribution
- **Comparison Report**: Changes between scans

### Export Formats
- **PDF**: Executive reports with charts
- **Excel**: Multi-sheet workbooks with formatting
- **CSV**: Compatible with any spreadsheet app
- **JSON**: Complete data for integration

## Remote Access Setup

NetworkMapper includes a built-in web server for accessing reports remotely.

### 1. Local Network Access
After completing a scan, the web server automatically starts:
```bash
python3 mapper.py
# Note the URLs displayed after scan completion:
# Local: http://localhost:5000
# Network: http://YOUR-IP:5000
```

Access from any device on the same network using the network URL.

### 2. Remote Access (Secure Methods)

#### SSH Port Forwarding (Recommended)
From your remote machine:
```bash
ssh -L 8080:localhost:5000 user@scanner-host
# Then open http://localhost:8080 in your browser
```

#### VPN Access
If you have VPN access to the network:
```bash
# Connect to VPN, then access directly
http://scanner-host-ip:5000
```

### 3. Cloud Deployment

#### Quick Cloud Setup (AWS/GCP/Azure)
1. Launch Ubuntu 20.04+ VM instance
2. Configure security group to allow SSH (port 22) from your IP
3. Install NetworkMapper:
```bash
ssh ubuntu@your-vm-ip
sudo apt update && sudo apt install python3-pip nmap arp-scan git -y
git clone <your-repo>
cd networkmapper-v2
pip3 install -r requirements.txt
```

4. Run scan and access via SSH tunnel:
```bash
# On VM
python3 mapper.py

# From your machine
ssh -L 8080:localhost:5000 ubuntu@your-vm-ip
# Open http://localhost:8080
```

### 4. Alternative Access Methods

#### File Transfer
If remote web access isn't available:
```bash
# Copy reports to local machine
scp user@scanner-host:~/networkmapper-v2/output/reports/*.html .
scp user@scanner-host:~/networkmapper-v2/output/exports/*.pdf .
```

#### Simple HTTP Server
For one-time sharing of static reports:
```bash
cd output/reports
python3 -m http.server 8000
# Access via http://scanner-host:8000
```

### Security Notes
- Default configuration only binds to localhost for security
- Use SSH tunneling for remote access instead of exposing ports
- Reports may contain sensitive network information
- Only scan networks you own or have permission to scan

## Documentation

- [Detailed Documentation](CLAUDE.md) - Architecture and implementation details
- [API Documentation](API_DOCUMENTATION.md) - Vulnerability API reference
- [Usage Examples](USAGE_EXAMPLES.md) - Comprehensive usage guide
- [Test Summary](TEST_SUMMARY.md) - Testing documentation

## Project Structure

```
networkmapper-v2/
├── mapper.py              # Main application with modern UI
├── modern_interface.py    # Sleek CLI interface components
├── core/                  # Core scanning modules
│   ├── scanner.py        # Network scanning orchestration
│   ├── parser.py         # Result parsing
│   ├── classifier.py     # Device classification
│   ├── tracker.py        # Change tracking
│   └── annotator.py      # Device annotations
├── utils/                 # Utility modules
├── templates/             # HTML report templates
├── tests/                 # Test suite
├── demos/                 # Demo and example scripts
├── scripts/               # Utility and testing scripts
├── tools/                 # External tools and binaries
└── output/               # Scan results and reports
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Quick functionality test
python scripts/test_core_functionality.py

# Full system test
python scripts/test_full_system.py

# Verify installation
python scripts/verify_installation.py
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security Considerations

- Only scan networks you own or have permission to scan
- SNMP credentials are stored locally (use SNMPv3 for encryption)
- Vulnerability data is cached locally
- No data is sent to external services except service names for CVE lookup

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Some scans require root privileges
sudo python3 mapper.py
```

**No Devices Found**
- Verify target format (e.g., 192.168.1.0/24)
- Check network connectivity
- Try ARP scan for local networks

**Slow Scans**
- Use Discovery scan for large networks
- Enable masscan for faster discovery
- Scan during off-peak hours

**Missing Vulnerabilities**
- Ensure internet connectivity for API access
- Check if services were detected properly
- Review cached data in `output/cache/`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- nmap for powerful network scanning
- OSV and CIRCL for free vulnerability data
- D3.js for beautiful visualizations
- Rich for the amazing CLI interface

## Support

- Create an issue for bug reports
- Check existing issues before creating new ones
- Include scan logs when reporting problems
- See [USAGE_EXAMPLES.md](USAGE_EXAMPLES.md) for detailed help

---

Made with ❤️ by the NetworkMapper team