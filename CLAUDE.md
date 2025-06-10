# NetworkMapper v2 - Claude Context

## Project Overview
NetworkMapper v2 is a comprehensive Python-based network discovery and asset management tool that combines multiple scanning technologies (nmap, masscan, arp-scan) with advanced visualization capabilities (D3.js, Three.js). It's designed for network administrators to discover, classify, track, and visualize devices on their networks.

## Architecture

### Core Modules
- **mapper.py**: Main CLI interface using Typer and Rich for interactive menus
- **core/scanner.py**: Orchestrates network scans with real-time progress tracking
- **core/classifier.py**: Identifies device types using port signatures, services, and OS fingerprints
- **core/parser.py**: Normalizes scan results from different scanners into unified format
- **core/tracker.py**: Detects changes between scans (new/missing devices, service changes)
- **core/annotator.py**: Manages persistent device annotations and tags
- **utils/visualization.py**: Generates network topology data for visualizations
- **utils/mac_lookup.py**: MAC vendor lookup with local OUI database and API fallback
- **utils/network_utils.py**: IP address manipulation and network calculations
- **utils/vulnerability_scanner.py**: Multi-API vulnerability correlation (OSV, CIRCL, local patterns)
- **utils/snmp_config.py**: Interactive SNMP configuration with persistence
- **utils/export_manager.py**: Advanced export functionality (PDF, Excel, JSON, CSV)

### Key Technologies
- **Scanning**: nmap (primary), masscan (speed), arp-scan (layer 2)
- **CLI**: Typer, Rich (tables, progress bars, formatting)
- **Visualization**: Interactive network map using D3.js and Three.js
- **Data Storage**: JSON files (no database required)
- **Web Framework**: Flask (for serving reports)
- **Vulnerability APIs**: OSV (Google), CIRCL CVE Search (keyless, free APIs)
- **Export Formats**: PDF, Excel, CSV, JSON with full vulnerability data

## Key Features

### 1. Multi-Scanner Support
- Intelligent scanner selection based on network size and scan type
- Real-time progress tracking with hang detection
- Three scan profiles: Discovery (fast), Inventory (detailed), Deep (comprehensive)

### 2. Device Classification
- 16+ device types supported (routers, switches, servers, IoT, printers, etc.)
- Signature-based classification using ports, services, OS, vendor info
- Confidence scoring for classification accuracy

### 3. Change Tracking
- Detects new, missing, and modified devices
- Tracks service/port changes
- Maintains scan history for comparison

### 4. Visualization ✅ ENHANCED
- **2D Network Map**: 
  - Modern dark theme UI with intuitive controls
  - Force-directed layout with hierarchical positioning
  - Real-time device search and filtering
  - Interactive tooltips and device detail panels
  - Change tracking visualization (new/modified/removed devices)
  - Export to PNG functionality
- **3D Network Map**:
  - Layered 3D view with spatial organization by device type
  - Smooth camera controls and optional auto-rotation
  - Glowing effects for critical devices
  - Curved connection lines with type-based styling
- **Auto-opening Reports**: Both detailed report and visualization open after scans
- **Improved Initial View**: Fixed camera positioning for immediate visibility

### 5. Asset Management
- Persistent device annotations
- Critical infrastructure flagging
- Custom tags and notes

## Common Commands

### Testing and Linting
```bash
# Run linting checks
./lint.sh

# Test scan functionality
python generate_test_data.py
python generate_minimal_network_test.py
```

### Development Workflow
```bash
# Activate virtual environment
source venv/bin/activate

# Run the main application
python3 mapper.py

# Monitor scan progress (separate terminal)
./monitor.sh
```

## File Structure
```
output/
├── scans/          # Raw scan results (JSON)
├── reports/        # HTML reports with visualizations
├── changes/        # Change tracking data
└── annotations/    # Device annotations
```

## Implementation Notes

### Progress Tracking
- Parses scanner output line-by-line
- Detects scan phases (discovery, port scan, service detection)
- Calculates percentage based on discovered hosts vs estimated total
- Implements hang detection with configurable thresholds

### Network Topology Generation
- Creates realistic topologies in visualization.py
- Routers form backbone ring
- Switches connect to nearest routers
- Workstations distribute among switches
- Application-layer connections (web servers ↔ databases)

### MAC Address Handling
- Local OUI database with automatic updates
- Cross-platform ARP cache parsing
- Virtual machine detection
- API fallback for unknown vendors

### Security Considerations
- Sudo authentication handling
- Input validation for network targets
- Permission checks for privileged operations
- Responsible scanning practices emphasized

## Common Tasks

### Adding New Device Types
Edit `core/classifier.py`:
```python
self.port_signatures['new_device'] = {
    'ports': [port_list],
    'services': ['service_names'],
    'keywords': ['identifying_keywords']
}
```

### Creating Custom Scan Profiles
Edit `core/scanner.py`:
```python
self.scan_profiles['profile_name'] = {
    'nmap': ['-sS', '-p', 'ports'],
    'description': 'Profile description'
}
```

### Modifying Visualizations
- 2D: Edit D3.js code in templates/report.html
- 3D: Modify Three.js implementation in report.html
- Topology: Update logic in utils/visualization.py

## Testing Considerations
- Test with different network sizes (use generate_test_data.py)
- Verify scanner fallback mechanisms
- Check progress tracking accuracy
- Validate device classification logic
- Test change detection algorithms

## Known Limitations
- 3D visualization currently only works locally (not over network)
- Large networks (>1000 hosts) may slow down visualizations
- Some device classifications depend on open ports being detected
- Scan speed vs accuracy tradeoffs in different profiles

## Future Enhancement Proposals

### 1. Advanced Analytics & Intelligence
- **Behavioral Analysis**: Track device behavior patterns over time to detect anomalies
- **ML-Based Classification**: Use machine learning to improve device type identification accuracy
- **Predictive Maintenance**: Alert on devices showing signs of potential failure
- **Network Health Scoring**: Calculate overall network health metrics and trends

### 2. Integration Capabilities
- **SNMP Integration**: Pull additional device information via SNMP polling
- **API Endpoints**: RESTful API for integration with other tools
- **Webhook Support**: Send alerts on network changes to external systems
- **SIEM Integration**: Export data in formats compatible with popular SIEM tools
- **Asset Management Systems**: Sync with IT asset management databases

### 3. Enhanced Visualization
- **Real-time Updates**: WebSocket-based live network view
- **Custom Dashboards**: Drag-and-drop dashboard builder
- **Geographic Mapping**: Plot devices on physical location maps
- **Network Flow Visualization**: Show traffic patterns between devices
- **VR/AR Support**: Immersive network exploration in virtual reality

### 4. Security Enhancements
- **Vulnerability Correlation**: Integrate with CVE databases to flag vulnerable services
- **Compliance Checking**: Verify devices meet security standards
- **Rogue Device Detection**: Alert on unauthorized devices
- **Network Segmentation Analysis**: Visualize and validate network segments
- **SSL/TLS Certificate Monitoring**: Track certificate expiration and validity

### 5. Performance & Scalability
- **Distributed Scanning**: Coordinate scans from multiple probe points
- **Database Backend Option**: PostgreSQL/MySQL support for large deployments
- **Scan Scheduling**: Cron-like scheduling with conflict resolution
- **Incremental Scanning**: Only scan changed portions of the network
- **Parallel Processing**: Multi-threaded analysis and classification

### 6. User Experience
- **Web-Based UI**: Full-featured web interface as alternative to CLI
- **Mobile App**: Monitor network status from mobile devices
- **Role-Based Access**: Multi-user support with permissions
- **Scan Templates**: Save and share scan configurations
- **Export Improvements**: PDF reports, Excel integration, custom templates

### 7. Advanced Features
- **IPv6 Support**: Full IPv6 scanning and visualization
- **Container/VM Awareness**: Detect and map virtual infrastructure
- **Cloud Integration**: Scan and map cloud resources (AWS, Azure, GCP)
- **IoT Device Profiles**: Expanded signatures for IoT devices
- **Network Simulation**: Test changes in simulated environment

### 8. Operational Intelligence
- **Change Automation**: Auto-approve expected changes
- **Baseline Learning**: Automatically establish normal network state
- **Capacity Planning**: Predict when network segments will need expansion
- **Documentation Generation**: Auto-generate network documentation
- **Troubleshooting Assistant**: AI-powered network issue diagnosis

### 9. Data Management
- **Backup/Restore**: Built-in data backup capabilities
- **Data Retention Policies**: Automatic cleanup of old scan data
- **Compression**: Efficient storage of historical data
- **Data Privacy**: Anonymization options for sensitive environments
- **Multi-Site Management**: Manage multiple networks from single instance

### 10. Developer Experience
- **Plugin System**: Allow custom scanners, classifiers, and visualizations
- **SDK/Libraries**: Python/JS libraries for extending functionality
- **CI/CD Integration**: Automated network testing in pipelines
- **Configuration as Code**: YAML/JSON-based network definitions
- **API Documentation**: Interactive API documentation with examples

## Implementation Priority
1. **High Priority**: API endpoints, SNMP integration, vulnerability correlation
2. **Medium Priority**: Web UI, distributed scanning, plugin system
3. **Low Priority**: VR support, mobile app, advanced ML features

These enhancements would transform NetworkMapper from a scanning tool into a comprehensive network intelligence platform.

## Recent Updates (2025)

### Completed Enhancements
1. **Comprehensive Test Suite** ✅
   - 100+ unit tests covering all core modules
   - Integration tests for full workflow validation
   - Makefile with 40+ test automation targets
   - Fixed logger initialization issues

2. **Modern Network Visualization** ✅
   - Complete redesign of 2D/3D network maps
   - Professional dark theme UI
   - Interactive device filtering and search
   - Change tracking indicators
   - Auto-opening after scan completion
   - Fixed camera positioning issues

3. **Advanced Export Capabilities** ✅
   - PDF reports with executive summaries and charts
   - Excel workbooks with multiple formatted sheets
   - JSON/CSV exports for data integration
   - Rich formatting and device type categorization
   - Automated generation integrated with scan workflow

4. **SNMP Integration** ✅
   - Device enrichment with SNMP data collection
   - System information retrieval (hostname, uptime, description)
   - Device-specific metrics (interfaces, memory, processes)
   - Smart candidate filtering and error handling
   - Interactive setup at the start of every scan
   - Support for SNMP v1, v2c, and v3 with full credential management
   - Configuration persistence with secure storage
   - CLI argument override support (--disable-snmp, --snmp-community, --snmp-version)
   - Input validation and user-friendly error handling
   - Progress tracking during enrichment operations

5. **Enhanced Scan Wizard UX** ✅
   - Completely redesigned scan setup flow with clear, intuitive prompts
   - Smart input validation with helpful error messages and examples
   - Structured option selection (numbered lists vs confusing bracket notation)
   - Contextual help and descriptions for all scan types
   - Target validation with support for IPs, CIDR, ranges, and hostnames
   - Graceful fallback handling for invalid input
   - Consistent visual formatting and progress indicators

6. **Multi-API Vulnerability Correlation** ✅
   - **Primary API**: OSV (Google Open Source Vulnerabilities) - keyless, comprehensive
   - **Fallback API**: CIRCL CVE Search - community-maintained, no authentication
   - **Local Patterns**: Enhanced security assessment for common vulnerabilities
   - Automatic CVE matching for discovered services and versions
   - CVSS scoring and severity classification (Critical/High/Medium/Low)
   - Intelligent cascading: tries APIs in order, falls back gracefully
   - Caching system to minimize API requests and improve performance
   - Vulnerability summary reporting with top risks highlighted
   - Full integration with CSV and HTML reports

7. **Enhanced Report Structure** ✅
   - **Removed**: Broken 2D/3D map tabs that displayed poorly in smaller report view
   - **Added**: Security Report tab with comprehensive vulnerability analysis
   - **Added**: Services tab with network service distribution and details
   - **Improved**: Vulnerability columns in device tables and CSV exports
   - **New**: Risk assessment cards with visual indicators
   - **Better**: Service organization by type and port information

### Current System Capabilities
The NetworkMapper v2 now provides a complete network security assessment platform with:

- **Multi-scanner network discovery** with intelligent fallback
- **Advanced device classification** using port, service, and OS fingerprints
- **Real-time vulnerability assessment** using multiple free APIs
- **Interactive SNMP enrichment** with full v1/v2c/v3 support
- **Comprehensive reporting** in multiple formats (HTML, PDF, Excel, CSV, JSON)
- **Change tracking** between scans with detailed comparison reports
- **Professional visualizations** with the main network map
- **Security-focused reporting** with vulnerability details and risk assessment
- **Service analysis** showing network service distribution
- **Export automation** with vulnerability data included in all formats

### Usage Examples

```bash
# Basic scan with all features
python3 mapper.py

# Scan with SNMP disabled
python3 mapper.py --disable-snmp

# Scan with specific SNMP settings
python3 mapper.py --snmp-community private --snmp-version v2c

# Generate test data
python3 generate_test_data.py

# Run linting
./lint.sh
```

### API Documentation

#### Vulnerability APIs (No Keys Required)

1. **OSV (Open Source Vulnerabilities)**
   - Endpoint: `https://api.osv.dev/v1/query`
   - Method: POST
   - Coverage: Major package ecosystems, CVEs
   - Used as primary source

2. **CIRCL CVE Search**
   - Endpoint: `https://cve.circl.lu/api/search/{keyword}`
   - Method: GET
   - Coverage: Full CVE dataset mirror
   - Used as fallback when OSV has no results

3. **Local Patterns**
   - Built-in vulnerability patterns for common services
   - Used when APIs are unavailable or return no results
   - Covers: telnet, ftp, http, snmp, ssh, rlogin, finger, netbios

### Testing

The project includes comprehensive testing capabilities:

```bash
# Generate test network data
python3 generate_test_data.py

# Generate minimal test network
python3 generate_minimal_network_test.py

# Run all linting checks
./lint.sh
```

### Important Notes

- The system is designed to work completely offline with local patterns
- All vulnerability APIs are free and require no authentication
- SNMP configuration is securely stored and can be reused between scans
- Reports automatically open in the browser after generation
- The main network visualization map provides the best interactive experience