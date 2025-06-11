# NetworkMapper v2 - Development Context

## Quick Start
```bash
# Activate virtual environment
source venv/bin/activate

# Run the application
python3 mapper.py

# Run tests
pytest tests/ -v

# Generate demo data
python demo_large_network.py
```

## Project Structure
```
v2/
├── mapper.py              # Main CLI application
├── core/                  # Core scanning and analysis modules
│   ├── scanner.py        # Multi-scanner orchestration
│   ├── classifier.py     # Device type identification
│   ├── parser.py         # Scan result parsing
│   ├── tracker.py        # Change detection
│   └── annotator.py      # Device annotations
├── utils/                 # Utility modules
│   ├── visualization.py  # Network topology generation
│   ├── mac_lookup.py     # MAC vendor lookup
│   ├── network_utils.py  # IP/network helpers
│   ├── vulnerability_scanner.py  # CVE correlation
│   ├── snmp_config.py    # SNMP configuration
│   └── export_manager.py # Export functionality
├── templates/            # HTML templates
│   ├── report.html       # Main report template
│   └── comparison_report.html  # Change report
├── tests/                # Test suite
│   ├── test_scanner.py   # Scanner tests
│   ├── test_classifier.py # Classifier tests
│   └── ...              # Other module tests
└── output/              # Generated files
    ├── scans/           # Scan results
    ├── reports/         # HTML reports
    └── exports/         # PDF/Excel exports
```

## Key Design Decisions

### 1. Scanner Architecture
- **Multi-scanner support**: Falls back gracefully between nmap, masscan, and arp-scan
- **Real-time progress**: Parses scanner output line-by-line for live updates
- **Profile-based**: Discovery (fast), Inventory (detailed), Deep (comprehensive)

### 2. Device Classification
- **Signature-based**: Uses port patterns, services, OS, and vendor info
- **Confidence scoring**: Returns certainty level for each classification
- **Extensible**: Easy to add new device types in classifier.py

### 3. Data Storage
- **JSON-based**: No database required, simple file storage
- **Organized structure**: Separate directories for scans, reports, annotations
- **Timestamped**: All files include timestamps for tracking

### 4. Visualization
- **Auto-generation**: Network topology created algorithmically
- **Interactive**: D3.js for 2D, Three.js for 3D views
- **Export-friendly**: Can save as PNG or include in reports

### 5. Testing
- **Comprehensive coverage**: Unit and integration tests
- **Fixtures**: Shared test data for consistency
- **Mocking**: External dependencies are mocked

## Common Development Tasks

### Adding a New Device Type
1. Edit `core/classifier.py`
2. Add signature to `self.port_signatures`
3. Update tests in `tests/test_classifier.py`

### Adding a New Scanner
1. Add scanner check in `core/scanner.py._check_scanners()`
2. Add parsing logic in `_parse_<scanner>_output()`
3. Add to scan profiles

### Modifying Visualizations
1. 2D map: Edit D3.js in `templates/report.html`
2. 3D map: Modify Three.js in `templates/report.html`
3. Topology logic: Update `utils/visualization.py`

### Running Specific Tests
```bash
# Run single test file
pytest tests/test_scanner.py -v

# Run single test method
pytest tests/test_scanner.py::TestNetworkScanner::test_scan_discovery -v

# Run with coverage
pytest tests/ --cov=core --cov=utils
```

## Performance Considerations
- **Large networks**: Visualizations may slow with >1000 devices
- **Scan speed**: Use 'discovery' profile for quick results
- **Memory usage**: Each scan stores full device details in memory

## Security Notes
- **Sudo handling**: Scanner prompts for sudo when needed
- **Input validation**: All network targets are validated
- **API keys**: No API keys required (uses free services)

## Recent Changes (January 2025)
- Reduced demo network from ~220 to ~55 devices
- Added comprehensive pytest test suite
- Fixed visualization camera positioning
- Enhanced SNMP configuration UI
- Improved scan wizard UX

## Debugging Tips
- Enable debug logging: Set log level in mapper.py
- Monitor scans: Use `./monitor.sh` in separate terminal
- Check output files: Look in `output/scans/` for raw data
- Test with small networks: Use `generate_minimal_network_test.py`

## Contributing Guidelines
1. Run linting before commits: `./lint.sh`
2. Add tests for new features
3. Update CLAUDE.md for significant changes
4. Follow existing code style (PEP 8)
5. Document complex logic with comments