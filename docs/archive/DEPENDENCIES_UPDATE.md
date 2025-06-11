# Dependencies Update Summary

## Consolidated Requirements
All dependencies have been consolidated into a single `requirements.txt` file. The `test-requirements.txt` file has been removed to avoid duplication.

## New Dependencies Added

### For Export Features
- **pandas** (2.0.3) - Data manipulation for Excel exports
- **numpy** - Required by pandas
- **pillow** - Image handling for reportlab
- **flask** (3.0.0) - Web server for serving reports

### Testing Framework (from test-requirements.txt)
- **pytest** suite - Complete testing framework
- **faker** - Test data generation  
- **factory-boy** - Test fixtures
- **responses** - HTTP mocking
- **freezegun** - Time mocking

### Development Tools
- **ipython** - Enhanced Python shell
- **ipdb** - Interactive debugger
- **pdbpp** - Better Python debugger
- **memory-profiler** - Memory usage analysis
- **coverage** - Code coverage reporting

### Code Quality
- **bandit** - Security linting
- **safety** - Dependency vulnerability checking
- **mypy** - Static type checking
- **pre-commit** - Git hooks for code quality

## Installation Instructions

### Minimal Production Install
```bash
pip3 install typer rich python-nmap requests jinja2 pyyaml reportlab openpyxl pandas pysnmp flask
```

### Full Development Install
```bash
pip3 install -r requirements.txt
```

### Optional Dependencies
- **scapy** - Uncomment in requirements.txt if passive traffic analysis is needed
- **mutmut** - Uncomment for mutation testing

## Breaking Changes
None - all existing functionality remains the same. The consolidation only adds new capabilities.