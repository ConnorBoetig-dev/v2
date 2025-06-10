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
- **utils/visualization.py**: Generates network topology data for 2D/3D visualizations
- **utils/mac_lookup.py**: MAC vendor lookup with local OUI database and API fallback
- **utils/network_utils.py**: IP address manipulation and network calculations

### Key Technologies
- **Scanning**: nmap (primary), masscan (speed), arp-scan (layer 2)
- **CLI**: Typer, Rich (tables, progress bars, formatting)
- **Visualization**: D3.js (2D force-directed graphs), Three.js (3D layered view)
- **Data Storage**: JSON files (no database required)
- **Web Framework**: Flask (for serving reports)

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

### 4. Visualization
- 2D network map with force-directed layout
- 3D layered view with device hierarchy
- Auto-generated network topology with intelligent link creation

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