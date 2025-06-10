# NetworkMapper v2 - File Organization

## New Directory Structure

The project has been reorganized for better maintainability and clarity:

### Core Application
- `mapper.py` - Main application with modern interface
- `modern_interface.py` - New sleek UI components

### Organized Folders

#### `/demos/` - Demo and Example Scripts
- `demo_large_network.py` - Generate large network demo data
- `demo_full_simulation.py` - Full network simulation with traffic flows
- `generate_demo_report.py` - Generate demo reports
- `generate_enterprise_test.py` - Enterprise network test data
- `generate_minimal_network_test.py` - Minimal network test
- `generate_test_data.py` - General test data generator
- `view_demo.py` - View demo data

#### `/scripts/` - Utility and Testing Scripts
- `test_core_functionality.py` - Core functionality verification
- `test_full_system.py` - Full system integration tests
- `test_visualization.py` - Visualization testing
- `verify_installation.py` - Installation verification
- `lint.sh` - Code linting script
- `monitor.sh` - Scan monitoring script

#### `/tools/` - External Tools and Binaries
- `masscan_1.3.2+ds1-1_amd64.deb` - Masscan Debian package

### Usage

#### Running Demos
```bash
# Generate demo network data
python demos/demo_large_network.py

# Run full simulation
python demos/demo_full_simulation.py

# Generate enterprise test data
python demos/generate_enterprise_test.py
```

#### Running Scripts
```bash
# Verify installation
python scripts/verify_installation.py

# Test core functionality
python scripts/test_core_functionality.py

# Run linting
./scripts/lint.sh

# Monitor active scans
./scripts/monitor.sh
```

#### Main Application
```bash
# Run NetworkMapper with modern interface
python mapper.py
```

## Modern Interface Features

### ✨ New UI Components
- **Rich Layouts**: Multi-panel dashboard with system status
- **Modern Cards**: Card-based menu system with icons and descriptions
- **Progress Indicators**: Live progress bars with spinners and timers
- **Color-coded Panels**: Status-aware coloring for different states
- **Interactive Wizards**: Step-by-step guided workflows

### 🎯 Enhanced UX
- **Visual Hierarchy**: Clear information structure with proper spacing
- **Intuitive Navigation**: Numbered options with descriptive text
- **Real-time Status**: Live system status and scan information
- **Modern Typography**: Unicode icons and styled text
- **Error Handling**: Elegant error messages with helpful guidance

### 📊 Dashboard Features
- **System Status Tree**: Hierarchical view of system state
- **Recent Activity**: Latest scans and reports overview
- **Tool Availability**: Status of required scanning tools
- **Quick Stats**: Device counts and scan summaries

## Backward Compatibility

All existing functionality remains available through the new interface. The organization changes are purely structural and don't affect the core scanning and analysis capabilities.

## Migration Notes

- All demo scripts are now in `/demos/` folder
- Test and utility scripts moved to `/scripts/` folder
- External tools consolidated in `/tools/` folder
- Original functionality preserved with enhanced UI
- New modern interface is enabled by default