# NetworkMapper v2 - Comprehensive Usage Examples

## Table of Contents
1. [Quick Start](#quick-start)
2. [Basic Scanning](#basic-scanning)
3. [Advanced Scanning](#advanced-scanning)
4. [SNMP Configuration](#snmp-configuration)
5. [Vulnerability Assessment](#vulnerability-assessment)
6. [Report Generation](#report-generation)
7. [Data Export](#data-export)
8. [Change Tracking](#change-tracking)
9. [Device Annotation](#device-annotation)
10. [Automation Examples](#automation-examples)

## Quick Start

### First Run
```bash
# Install dependencies
pip3 install -r requirements.txt

# Run NetworkMapper
python3 mapper.py

# Generate test data for demo
python3 generate_test_data.py
```

### Using Makefile
```bash
# View all available commands
make help

# Run the application
make run

# Generate demo data
make demo

# Run tests
make test
```

## Basic Scanning

### Interactive Mode (Recommended)
```bash
python3 mapper.py
```
Then follow the interactive prompts:
1. Select "Run Network Scan"
2. Enter target (e.g., 192.168.1.0/24)
3. Choose scan type (Discovery/Inventory/Deep)
4. Configure SNMP (optional)
5. Enable vulnerability scanning (recommended)

### Command Line with Options
```bash
# Disable SNMP for quick scan
python3 mapper.py --disable-snmp

# Use specific SNMP community
python3 mapper.py --snmp-community private --snmp-version v2c
```

### Scan Types Explained

**Discovery Scan (Fast)**
- Basic host discovery
- Common ports only
- ~30 seconds for /24 network
- Good for initial network mapping

**Inventory Scan (Detailed)**
- Full port scan
- Service version detection
- OS fingerprinting
- ~5 minutes for /24 network
- Recommended for asset inventory

**Deep Scan (Comprehensive)**
- All ports
- Script scanning
- Detailed service info
- ~15 minutes for /24 network
- Best for security assessments

**ARP Scan (Layer 2)**
- Local network only
- MAC address discovery
- Very fast (~10 seconds)
- No service detection

## Advanced Scanning

### Targeting Options
```bash
# Single host
192.168.1.10

# Network range (CIDR)
192.168.1.0/24

# IP range
192.168.1.1-50

# Hostname
router.local

# Multiple targets (comma-separated)
192.168.1.1,192.168.1.10,192.168.1.20
```

### Using Masscan for Speed
When prompted for scan type, select "Discovery Scan" and then:
- Choose "Yes" for "Use masscan for faster discovery"
- Note: Requires masscan to be installed

## SNMP Configuration

### Interactive Setup
During scan setup, you'll be prompted:
```
Configure SNMP enrichment? [Y/n]: y
Select SNMP version:
  1. SNMPv1
  2. SNMPv2c
  3. SNMPv3
```

### SNMPv2c Example
```
SNMP version [1/2/3]: 2
Community string [public]: private
```

### SNMPv3 Example
```
SNMP version [1/2/3]: 3
Username: admin
Enable authentication? [Y/n]: y
Auth protocol:
  1. MD5
  2. SHA
Selection: 2
Auth password: ********
Enable encryption? [Y/n]: y
Privacy protocol:
  1. DES
  2. AES
Selection: 2
Privacy password: ********
```

### Reusing Configuration
- SNMP settings are saved automatically
- On next scan, you'll be asked to reuse or create new
- Config stored in `output/config/snmp_config.json`

## Vulnerability Assessment

### Automatic Scanning
Vulnerability scanning is enabled by default and will:
1. Query OSV (Google) API for CVEs
2. Fall back to CIRCL API if needed
3. Use local patterns if APIs unavailable
4. Cache results for 24 hours

### Understanding Results

**Risk Levels**:
- **CRITICAL**: CVSS 9.0-10.0 (Immediate action required)
- **HIGH**: CVSS 7.0-8.9 (Address soon)
- **MEDIUM**: CVSS 4.0-6.9 (Plan remediation)
- **LOW**: CVSS 0.0-3.9 (Monitor)

**Example Output**:
```
Device 192.168.1.1: 3 vulnerabilities
  - LOCAL-TELNET-001: HIGH (7.5) - Telnet clear text transmission
  - LOCAL-HTTP-001: MEDIUM (5.3) - Unencrypted HTTP traffic
  - CVE-2023-12345: HIGH (7.8) - Apache vulnerability
```

## Report Generation

### Automatic Reports
After each scan, reports automatically:
1. Save to `output/reports/`
2. Open in your default browser
3. Include both visualization and detailed views

### Manual Report Generation
From main menu:
1. Select "Generate Reports"
2. Choose a recent scan
3. Reports will open automatically

### Report Types

**Network Map** (`network_map_*.html`):
- Interactive D3.js visualization
- Force-directed layout
- Device filtering and search
- Export to PNG

**Detailed Report** (`report_*.html`):
- Comprehensive device tables
- Security assessment tab
- Service analysis tab
- Subnet breakdown

**Comparison Report** (`comparison_*.html`):
- Shows changes between scans
- New/missing/modified devices
- Automatic generation when changes detected

## Data Export

### Export Formats

**PDF Report**:
```python
# From menu: Select "Export Data" > "Export to PDF Report"
# Includes: Executive summary, charts, device inventory
# Location: output/exports/network_report_*.pdf
```

**Excel Workbook**:
```python
# Multiple sheets: Summary, Devices, Vulnerabilities, Services, Changes
# Formatted with colors and filters
# Location: output/exports/network_inventory_*.xlsx
```

**Enhanced JSON**:
```python
# Complete data with metadata
# Suitable for integration with other tools
# Location: output/exports/network_export_*.json
```

**CSV Export**:
```python
# Includes vulnerability columns
# Compatible with spreadsheet apps
# Location: output/exports/devices_*.csv
```

### Export Examples

**Export Critical Devices Only**:
1. Select "Export Data" from menu
2. Choose "Export critical devices only"
3. CSV file created with critical infrastructure

**Export by Device Type**:
1. Select "Export Data" from menu
2. Choose "Export by device type"
3. Enter type (router/switch/server/etc)
4. Filtered CSV created

## Change Tracking

### Quick Change Detection
From main menu:
1. Select "Check Changes"
2. Summary shows:
   - New devices (green)
   - Missing devices (red) 
   - Modified devices (yellow)

### Advanced Scan Comparison
From main menu:
1. Select "Compare Scans" (option 4)
2. System automatically:
   - Groups scans by subnet
   - Detects same-network scans
   - Shows last 20 scans
3. Choose subnet to compare
4. Select two scans for comparison
5. View detailed comparison with color coding
6. Export results (JSON, CSV, HTML)

### Change Report Files
- JSON format: `output/changes/changes_*.json`
- Text summary: `output/changes/changes_*.txt`
- Comparison exports: `output/exports/comparison_*.{json,csv,html}`

### Example Change Detection
```
NEW DEVICES (2)
------------------------------
  • 192.168.1.50 - laptop-john (workstation)
  • 192.168.1.51 - printer-floor2 (printer)

MISSING DEVICES (1)
------------------------------
  • 192.168.1.30 - old-server (server)

CHANGED DEVICES (1)
------------------------------
  • 192.168.1.1 - main-router
    - services: added https:443
```

### Comparison Features
- **Subnet Auto-Detection**: Automatically groups scans by network
- **Visual Diff Display**: Color-coded changes (green=new, red=missing, yellow=modified)
- **Field-Level Changes**: Shows exactly what changed (ports, services, etc.)
- **Multiple Export Formats**: JSON, CSV, HTML reports
- **HTML Report Integration**: "Compare to Last Scan" button in reports

## Device Annotation

### Adding Annotations
From main menu:
1. Select "Annotate Devices"
2. Choose device to annotate
3. Options:
   - Mark as critical infrastructure
   - Add custom notes
   - Apply tags

### Annotation Persistence
- Stored in `output/annotations/`
- Automatically applied to future scans
- Included in all reports and exports

### Example Annotations
```python
# Critical infrastructure
Device: 192.168.1.1 (main-router)
Critical: Yes
Notes: Primary gateway - DO NOT MODIFY

# Custom notes
Device: 192.168.1.100 (web-server)
Critical: No
Notes: Production web server - Apache 2.4.41
Tags: production, web, public-facing
```

## Automation Examples

### Scheduled Scanning
```bash
# Add to crontab for daily scan at 2 AM
0 2 * * * cd /path/to/networkmapper && python3 mapper.py --disable-snmp < scan_input.txt

# scan_input.txt contents:
1
192.168.1.0/24
1
n
y
```

### Scripted Scan
```python
#!/usr/bin/env python3
import subprocess
import json
from pathlib import Path

# Run scan programmatically
scan_input = "1\n192.168.1.0/24\n2\nn\ny\n"
subprocess.run(['python3', 'mapper.py'], input=scan_input, text=True)

# Process results
latest_scan = max(Path('output/scans').glob('scan_*.json'))
with open(latest_scan) as f:
    devices = json.load(f)

# Alert on vulnerabilities
vulnerable = [d for d in devices if d.get('vulnerability_count', 0) > 0]
if vulnerable:
    print(f"ALERT: {len(vulnerable)} vulnerable devices found!")
```

### Integration with Monitoring
```python
# Export to monitoring system
import requests
from pathlib import Path
import json

# Get latest scan
latest = max(Path('output/scans').glob('scan_*.json'))
with open(latest) as f:
    devices = json.load(f)

# Send to monitoring API
for device in devices:
    if device.get('critical_vulns', 0) > 0:
        requests.post('https://monitoring.example.com/api/alert', 
                     json={
                         'host': device['ip'],
                         'severity': 'critical',
                         'message': f"{device['critical_vulns']} critical vulnerabilities"
                     })
```

### Batch Processing
```bash
#!/bin/bash
# Scan multiple networks

networks=("192.168.1.0/24" "192.168.2.0/24" "10.0.0.0/24")

for net in "${networks[@]}"; do
    echo "Scanning $net..."
    echo -e "1\n$net\n1\nn\ny" | python3 mapper.py
    sleep 60  # Wait between scans
done
```

## Tips and Best Practices

### Performance Optimization
1. Use Discovery scan for large networks first
2. Enable masscan for faster discovery
3. Scan during off-peak hours
4. Use CIDR notation for efficiency

### Security Considerations
1. Always scan only networks you own/manage
2. Use SNMPv3 with encryption when possible
3. Store reports securely (contain network details)
4. Review vulnerability findings promptly

### Troubleshooting

**"Permission denied" errors**:
```bash
# Some scans require root
sudo python3 mapper.py
```

**No devices found**:
- Check target format
- Verify network connectivity
- Try ARP scan for local network
- Check firewall rules

**Slow scans**:
- Use Discovery instead of Deep scan
- Enable masscan option
- Reduce network range
- Check network latency

**Missing vulnerabilities**:
- Ensure services are detected
- Check internet connectivity (for APIs)
- Review `output/cache/` for cached data
- Try manual service detection

### Advanced Configuration

**Custom Scan Profiles**:
Edit `core/scanner.py` to add custom nmap options:
```python
self.scan_profiles['custom'] = {
    'nmap': ['-sS', '-sV', '-p-', '--script', 'vuln'],
    'description': 'Custom vulnerability scan'
}
```

**Device Type Signatures**:
Edit `core/classifier.py` to improve detection:
```python
self.port_signatures['iot_device'] = {
    'ports': [8080, 8443],
    'services': ['http', 'https'],
    'keywords': ['esp', 'arduino', 'raspberry']
}
```