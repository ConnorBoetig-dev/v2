# NetworkMapper v2

A comprehensive Python-based network discovery and security assessment tool that combines multiple scanning technologies with advanced visualization and vulnerability analysis.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)

## Features

- **🔍 Multi-Scanner Support**: Intelligent use of nmap, masscan, and arp-scan
- **🎯 Smart Device Classification**: Identifies 16+ device types using ML-like signatures
- **🔐 Vulnerability Assessment**: Real-time CVE correlation using free APIs (OSV, CIRCL)
- **📊 Interactive Visualizations**: Network topology maps with D3.js
- **📈 Change Tracking**: Monitors network changes between scans
- **🔌 SNMP Integration**: Device enrichment with SNMP v1/v2c/v3 support
- **📑 Advanced Reporting**: HTML, PDF, Excel, CSV, and JSON exports
- **🎨 Professional UI**: Rich CLI with progress tracking and intuitive menus

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/networkmapper-v2.git
cd networkmapper-v2

# Install dependencies
pip3 install -r requirements.txt

# Run NetworkMapper
python3 mapper.py
```

## Installation

### Requirements
- Python 3.8+
- nmap
- arp-scan (optional, for Layer 2 discovery)
- masscan (optional, for high-speed scanning)

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install python3 python3-pip nmap arp-scan
pip3 install -r requirements.txt
```

### macOS
```bash
brew install python nmap arp-scan
pip3 install -r requirements.txt
```

### Docker
```bash
docker build -t networkmapper .
docker run -it --network host networkmapper
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

### Using Make Commands
```bash
make help       # Show all available commands
make run        # Run NetworkMapper
make demo       # Generate demo data
make test       # Run test suite
make lint       # Check code quality
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

## Documentation

- [Detailed Documentation](CLAUDE.md) - Architecture and implementation details
- [API Documentation](API_DOCUMENTATION.md) - Vulnerability API reference
- [Usage Examples](USAGE_EXAMPLES.md) - Comprehensive usage guide
- [Test Summary](TEST_SUMMARY.md) - Testing documentation

## Project Structure

```
networkmapper-v2/
├── mapper.py              # Main application
├── core/                  # Core scanning modules
│   ├── scanner.py        # Network scanning orchestration
│   ├── parser.py         # Result parsing
│   ├── classifier.py     # Device classification
│   ├── tracker.py        # Change tracking
│   └── annotator.py      # Device annotations
├── utils/                 # Utility modules
│   ├── vulnerability_scanner.py  # CVE correlation
│   ├── snmp_config.py           # SNMP configuration
│   ├── export_manager.py        # Export functionality
│   └── visualization.py         # Network visualization
├── templates/             # HTML report templates
├── tests/                 # Test suite
└── output/               # Scan results and reports
```

## Testing

```bash
# Run all tests
make test

# Run specific module tests
make test-scanner
make test-vulnerability
make test-snmp

# Run with coverage
make coverage

# Quick smoke tests
make quick
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