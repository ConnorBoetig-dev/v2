#!/usr/bin/env python3
"""
Verification script to ensure NetworkMapper v2 installation is complete and working
"""

import sys
import subprocess
import importlib
from pathlib import Path

def check_python_version():
    """Check if Python version is adequate"""
    print("Checking Python version...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"❌ Python {version.major}.{version.minor} detected. Require Python 3.8+")
        return False
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} - OK")
    return True

def check_required_modules():
    """Check if all required Python modules are available"""
    print("\nChecking required Python modules...")
    required_modules = [
        'typer', 'rich', 'jinja2', 'requests', 'scapy'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            importlib.import_module(module)
            print(f"✅ {module} - OK")
        except ImportError:
            print(f"❌ {module} - MISSING")
            missing_modules.append(module)
    
    if missing_modules:
        print(f"\n❌ Missing modules: {', '.join(missing_modules)}")
        print("Install with: pip install -r requirements.txt")
        return False
    
    return True

def check_system_tools():
    """Check if required system tools are available"""
    print("\nChecking system tools...")
    tools = {
        'nmap': 'sudo apt install nmap (Ubuntu) or brew install nmap (macOS)',
        'arp-scan': 'sudo apt install arp-scan (Ubuntu) or brew install arp-scan (macOS)'
    }
    
    missing_tools = []
    for tool, install_cmd in tools.items():
        try:
            result = subprocess.run(['which', tool], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ {tool} - OK ({result.stdout.strip()})")
            else:
                print(f"❌ {tool} - NOT FOUND")
                print(f"   Install with: {install_cmd}")
                missing_tools.append(tool)
        except Exception as e:
            print(f"❌ {tool} - ERROR: {e}")
            missing_tools.append(tool)
    
    return len(missing_tools) == 0

def check_project_structure():
    """Check if project structure is complete"""
    print("\nChecking project structure...")
    
    required_files = [
        'mapper.py',
        'core/scanner.py',
        'core/classifier.py', 
        'core/parser.py',
        'core/tracker.py',
        'core/annotator.py',
        'utils/visualization.py',
        'utils/mac_lookup.py',
        'templates/report.html',
        'requirements.txt',
        'CLAUDE.md',
        'README.md',
        'CONTEXT.md'
    ]
    
    required_dirs = [
        'output/scans',
        'output/reports',
        'output/cache',
        'tests'
    ]
    
    missing_files = []
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"✅ {file_path} - OK")
        else:
            print(f"❌ {file_path} - MISSING")
            missing_files.append(file_path)
    
    missing_dirs = []
    for dir_path in required_dirs:
        if Path(dir_path).exists():
            print(f"✅ {dir_path}/ - OK")
        else:
            print(f"❌ {dir_path}/ - MISSING")
            missing_dirs.append(dir_path)
    
    return len(missing_files) == 0 and len(missing_dirs) == 0

def check_core_functionality():
    """Test basic NetworkMapper functionality"""
    print("\nTesting core functionality...")
    
    try:
        # Test imports
        from core.classifier import DeviceClassifier
        from utils.visualization import MapGenerator
        from utils.mac_lookup import MACLookup
        print("✅ Core modules import successfully")
        
        # Test device classification
        classifier = DeviceClassifier()
        test_device = {'ip': '10.0.1.1', 'open_ports': [22, 80], 'services': ['ssh', 'http']}
        result = classifier.classify_devices([test_device])
        print(f"✅ Device classification works (classified as: {result[0].get('type', 'unknown')})")
        
        # Test visualization generation
        map_gen = MapGenerator()
        sample_devices = [
            {'ip': '10.0.1.1', 'hostname': 'test1', 'type': 'router'},
            {'ip': '10.0.1.2', 'hostname': 'test2', 'type': 'switch'}
        ]
        viz_data = map_gen.generate_d3_data(sample_devices)
        print(f"✅ Visualization generation works ({len(viz_data['nodes'])} nodes, {len(viz_data['links'])} links)")
        
        return True
        
    except Exception as e:
        print(f"❌ Core functionality test failed: {e}")
        return False

def check_demo_data():
    """Check if demo data can be generated"""
    print("\nChecking demo data generation...")
    
    try:
        # Try to run demo script
        result = subprocess.run([
            sys.executable, 'demo_large_network.py'
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Demo network generation - OK")
            
            # Check if demo files were created
            demo_files = list(Path("output/demo").glob("*.json"))
            if demo_files:
                print(f"✅ Demo files created ({len(demo_files)} files)")
                return True
            else:
                print("❌ Demo files not found")
                return False
        else:
            print(f"❌ Demo generation failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Demo generation timed out")
        return False
    except Exception as e:
        print(f"❌ Demo generation error: {e}")
        return False

def main():
    """Run all verification checks"""
    print("NetworkMapper v2 Installation Verification")
    print("=" * 50)
    
    checks = [
        ("Python Version", check_python_version),
        ("Required Modules", check_required_modules),
        ("System Tools", check_system_tools),
        ("Project Structure", check_project_structure),
        ("Core Functionality", check_core_functionality),
        ("Demo Data Generation", check_demo_data)
    ]
    
    passed = 0
    total = len(checks)
    
    for check_name, check_func in checks:
        try:
            if check_func():
                passed += 1
            else:
                print(f"\n⚠️  {check_name} check failed")
        except Exception as e:
            print(f"\n❌ {check_name} check error: {e}")
    
    print("\n" + "=" * 50)
    print(f"VERIFICATION SUMMARY: {passed}/{total} checks passed")
    print("=" * 50)
    
    if passed == total:
        print("🎉 ALL CHECKS PASSED!")
        print("\nNetworkMapper v2 is ready to use!")
        print("\nNext steps:")
        print("1. Run: python3 mapper.py")
        print("2. Select 'Run Network Scan'")
        print("3. Choose your target network (e.g., 192.168.1.0/24)")
        print("4. View the generated reports")
        print("\nFor remote access, see the README.md 'Remote Access Setup' section.")
        return True
    else:
        print("❌ Some checks failed. Please fix the issues above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)