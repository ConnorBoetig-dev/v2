# NetworkMapper Application Architecture

## Overview

NetworkMapper is a comprehensive network discovery and asset management tool built with a modular architecture. It combines multiple network scanning technologies with advanced analysis capabilities to provide deep insights into network infrastructure. The application follows a CLI-first design with rich terminal UI elements and web-based visualizations.

## Architecture & Design

### High-Level Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   CLI Interface │────▶│  Core Modules    │────▶│  Data Storage   │
│   (mapper.py)   │     │  (Scanner, etc)  │     │  (JSON files)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         │                       │                         │
         ▼                       ▼                         ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  User Wizards   │     │  Utility Modules │     │  HTML Reports   │
│  (Interactive)  │     │  (Export, Vuln)  │     │  (D3.js/Three)  │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

### Component Organization

1. **Core Modules** (`core/`)
   - `scanner.py` / `scanner_async.py`: Network scanning orchestration
   - `classifier.py`: AI-powered device type identification
   - `parser.py`: Scan result parsing and normalization
   - `tracker.py`: Change detection between scans
   - `annotator.py`: Device annotation management

2. **Utility Modules** (`utils/`)
   - `vulnerability_scanner.py`: CVE correlation
   - `export_manager.py`: Multi-format data export
   - `visualization.py`: Network map generation
   - `traffic_analyzer.py`: Passive traffic analysis
   - `snmp_config.py`: SNMP credential management

3. **User Interface**
   - `mapper.py`: Main CLI application
   - `modern_interface.py`: Alternative UI (experimental)
   - `templates/`: HTML report templates
   - Rich library integration for terminal UI

### Data Flow

```
Network Scan → Raw Results → Parser → Classifier → Enrichment → Storage → Visualization
     ↓              ↓           ↓          ↓            ↓           ↓            ↓
[nmap/masscan] [XML/JSON]  [Normalize] [AI Type]  [SNMP/Vuln]  [JSON]    [HTML/D3.js]
```

## Key Concepts

### Modular Design Philosophy

Each component has a single, well-defined responsibility:
- **Scanner**: Only handles scan execution
- **Classifier**: Only determines device types
- **Parser**: Only normalizes data formats
- **Tracker**: Only detects changes

This separation enables:
- Easy testing of individual components
- Replacement of implementations
- Addition of new features without disruption

### Wizard-Based User Experience

Complex operations are broken into guided steps:
1. Clear prompts with validation
2. Sensible defaults for all options
3. Help text and examples
4. Progress indication throughout
5. Automatic result display

### Multi-Tool Integration

The system integrates multiple tools seamlessly:
- **nmap**: Detailed scanning (services, OS)
- **masscan**: High-speed discovery
- **arp-scan**: Layer 2 discovery
- **SNMP**: Device enrichment
- Results merged intelligently

## Usage & Integration

### CLI Usage

```bash
# Interactive mode (recommended)
python3 mapper.py

# With CLI arguments
python3 mapper.py --target 192.168.1.0/24 --scan-type fast --disable-snmp

# Export specific
python3 mapper.py export --format csv --output network_inventory.csv
```

### Programmatic Usage

```python
from mapper import NetworkMapper

nm = NetworkMapper()

# Run a scan programmatically
devices = nm.scanner.scan("192.168.1.0/24", scan_type="fast")
classified = nm.classifier.classify_devices(devices)

# Generate reports
nm.generate_html_report(classified, "timestamp")
```

### Integration Points

1. **Data Import/Export**
   - JSON for data interchange
   - CSV for spreadsheet integration
   - PDF for management reports
   - Excel for detailed analysis

2. **Visualization**
   - Standalone HTML files
   - Can be embedded in dashboards
   - REST API potential (future)

3. **Automation**
   - CLI arguments for scripting
   - JSON output for pipelines
   - Exit codes for CI/CD

## Assumptions & Limitations

### Assumptions
- Unix-like operating system (Linux preferred)
- Python 3.8+ available
- Network scanning tools installed (nmap, masscan)
- User has appropriate network permissions
- Target networks are reachable

### Limitations
- No built-in scheduling (use cron)
- Single-threaded UI (async for scanning only)
- File-based storage (no database)
- Limited to IPv4 currently
- No real-time monitoring

### Security Considerations
- Requires sudo for some operations
- SNMP credentials stored locally
- No built-in authentication
- Scan results may contain sensitive data

## Troubleshooting

### Common Issues

1. **"Scanner not found" errors**
   ```bash
   # Install required tools
   sudo apt update
   sudo apt install nmap masscan arp-scan
   ```

2. **Permission denied**
   ```bash
   # Run with sudo for full features
   sudo python3 mapper.py
   ```

3. **Module import errors**
   ```bash
   # Install dependencies
   pip install -r requirements.txt
   ```

4. **Visualization not opening**
   ```bash
   # Check default browser
   xdg-settings get default-web-browser
   ```

### Debug Mode

Enable debug logging:
```python
# In mapper.py
logging.basicConfig(level=logging.DEBUG)
```

### Performance Tuning

1. **Large Networks**
   - Use fast scan mode
   - Enable masscan
   - Increase parallel limits in scanner_async.py

2. **Memory Usage**
   - Process results in chunks
   - Clear cache between scans
   - Limit vulnerability lookups

## Future Considerations

### Planned Enhancements

1. **Web Interface**
   - Flask/FastAPI backend
   - Real-time scan monitoring
   - Multi-user support

2. **Database Backend**
   - PostgreSQL for scale
   - Historical trending
   - Advanced queries

3. **API Development**
   - RESTful endpoints
   - WebSocket for live updates
   - Integration with other tools

4. **Enhanced Analytics**
   - ML-based anomaly detection
   - Predictive maintenance
   - Security scoring

### Extension Points

1. **Custom Scanners**
   - Implement scanner interface
   - Add to scanner registry
   - Integrate results

2. **New Device Types**
   - Add to DeviceType enum
   - Create signature
   - Train classifier

3. **Export Formats**
   - Implement exporter interface
   - Add to export manager
   - Register format

### Contributing

When extending NetworkMapper:
1. Follow existing patterns
2. Add comprehensive tests
3. Document new features
4. Update relevant .claude.md files
5. Consider backward compatibility