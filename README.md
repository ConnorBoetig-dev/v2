# NetworkMapper v2

A comprehensive Python-based network discovery and security assessment tool that combines multiple scanning technologies with advanced visualization and vulnerability analysis.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)


## Quick Start

Get up and running with NetworkMapper in under a minute. Choose the method that best fits your needs.

### 🐳 Docker Method (Recommended for All Users)

This is the easiest and most reliable way to run NetworkMapper, as it works on any system (Windows, macOS, Linux) with zero setup.

1.  **Install Docker:** If you don't have Docker, run our setup script to install it automatically:
    ```bash
    # Make sure the script is executable first
    chmod +x ./scripts/docker.sh
    ./scripts/docker.sh
    ```

2.  **Build & Run:** Use our simple `Makefile` command to build the image and start the application:
    ```bash
    make docker-run
    ```

That's it! The interactive menu will start. For more advanced Docker usage, please see our detailed **[Docker Setup Guide](./DOCKER_README.md)**.

### 💻 Local Python Method (For Developers)

This method is for users who want to run the tool directly in a local Python environment.

1.  **Run the Setup Script:** This script will check dependencies and set up your environment.
    ```bash
    chmod +x ./scripts/setup.sh
    ./scripts/setup.sh
    ```

2.  **Install the `mapper` Command:** This final step makes the tool available system-wide.
    ```bash
    make install
    ```

3.  **Run from Anywhere:** You can now run the tool from any directory.
    ```bash
    mapper
    ```

---

## Installation

Choose one of the following installation paths.

### 🐳 Option 1: Docker Installation (Recommended)

Using Docker is the most straightforward way to get started. It bundles all dependencies and configurations into a self-contained environment.

Our `Makefile` simplifies the entire process.

1.  **Install Docker:**
    Run our automated script to install Docker and Docker Compose if you don't have them.
    ```bash
    chmod +x ./scripts/docker.sh && ./scripts/docker.sh
    ```

2.  **Build the Image:**
    This command reads the `Dockerfile` and builds the application image. You only need to do this once.
    ```bash
    make docker-build
    ```

For detailed instructions on running with different options, managing data, and troubleshooting, please refer to the **[Docker Setup Guide](./Docker.md)**.

### 💻 Option 2: Local Python Installation

Follow these steps to set up a local development environment.

#### 1. System Dependencies

First, ensure you have the required external scanning tools. Our setup script can check for and install them for you.

*   **Required:** `nmap`
*   **Recommended:** `masscan`, `arp-scan`

#### 2. Automated Setup

Our `setup.sh` script automates the entire process:
*   Checks for system dependencies and helps you install them.
*   Creates a Python virtual environment in `./venv/`.
*   Installs all required Python packages from `ops/requirements.txt`.

To run it:
```bash
# Make the script executable
chmod +x ./scripts/setup.sh

# Run the setup process
./scripts/setup.sh
```

#### 3. Install the Command (Final Step)

After running the setup script, run the following command to create a system-wide `mapper` command for easy access:
```bash
make install
```
This will prompt for your `sudo` password to create a symbolic link in `/usr/local/bin`.

---

## Usage

How you run NetworkMapper depends on your installation method.

### 🐳 Running with Docker

The `Makefile` provides the easiest way to interact with the Docker container.

**Start the interactive menu:**
```bash
make docker-run
```

**Run a non-interactive scan:**
Pass arguments directly to the container.
```bash
docker-compose run --rm networkmapper --target 192.168.1.0/24 --scan-type deeper
```
> For more commands, see the **[Docker Setup Guide](./DOCKER_README.md)**.

### 💻 Running Locally

**If you used `make install`:**
You can run the application from any directory in your terminal.

**Start the interactive menu:**
```bash
mapper
```
**Run a non-interactive scan:**
(Note: Some scan types like `deeper` or `fast` require root privileges)
```bash
sudo mapper --target 10.0.0.0/16 --scan-type fast
```

**If you only used `make setup` (developer mode):**
You must run the tool from within the project directory using the `Makefile`.

**Start the interactive menu:**
```bash
make run
```
**Run a non-interactive scan:**
```bash
make scan TARGET=192.168.1.0/24 TYPE=fast
```

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
make mapper
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
