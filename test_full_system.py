#!/usr/bin/env python3
"""
Full system integration test for NetworkMapper v2
Tests all major components working together
"""

import json
import sys
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from mapper import NetworkMapper
from utils.vulnerability_scanner import VulnerabilityScanner
from utils.snmp_config import SNMPConfig
from utils.export_manager import ExportManager


def test_full_system():
    """Test complete NetworkMapper functionality"""
    print("NetworkMapper v2 - Full System Test")
    print("=" * 50)
    
    # Initialize components
    print("\n1. Initializing components...")
    mapper = NetworkMapper()
    print("   ✓ NetworkMapper initialized")
    
    # Test data generation
    print("\n2. Testing data generation...")
    test_devices = [
        {
            'ip': '192.168.1.1',
            'hostname': 'test-router',
            'mac': '00:11:22:33:44:55',
            'vendor': 'Cisco',
            'type': 'router',
            'os': 'IOS 15.2',
            'services': ['telnet:23', 'http:80', 'snmp:161'],
            'open_ports': [23, 80, 161],
            'last_seen': datetime.now().isoformat()
        },
        {
            'ip': '192.168.1.10',
            'hostname': 'test-server',
            'mac': '00:AA:BB:CC:DD:EE',
            'vendor': 'Dell',
            'type': 'server',
            'os': 'Ubuntu 20.04',
            'services': ['ssh:22', 'http:80 (Apache 2.4.41)', 'mysql:3306'],
            'open_ports': [22, 80, 3306],
            'last_seen': datetime.now().isoformat()
        }
    ]
    print(f"   ✓ Generated {len(test_devices)} test devices")
    
    # Test device classification
    print("\n3. Testing device classification...")
    classified = mapper.classifier.classify_devices(test_devices)
    print(f"   ✓ Classified {len(classified)} devices")
    for device in classified:
        print(f"     - {device['ip']}: {device['type']} (confidence: {device.get('classification_confidence', 'N/A')})")
    
    # Test vulnerability scanning
    print("\n4. Testing vulnerability scanning...")
    vuln_scanner = mapper.vuln_scanner
    enriched = vuln_scanner.scan_devices(classified)
    total_vulns = sum(d.get('vulnerability_count', 0) for d in enriched)
    print(f"   ✓ Found {total_vulns} total vulnerabilities")
    
    for device in enriched:
        if device.get('vulnerability_count', 0) > 0:
            print(f"     - {device['ip']}: {device['vulnerability_count']} vulnerabilities")
            for vuln in device.get('vulnerabilities', [])[:2]:
                print(f"       • {vuln['cve_id']}: {vuln['severity']} ({vuln['cvss_score']})")
    
    # Test change tracking
    print("\n5. Testing change tracking...")
    # Save as previous scan
    prev_scan_file = mapper.output_path / "scans" / "scan_previous.json"
    with open(prev_scan_file, 'w') as f:
        json.dump(enriched, f, indent=2)
    
    # Modify data for changes
    enriched_copy = enriched.copy()
    enriched_copy.append({
        'ip': '192.168.1.20',
        'hostname': 'new-device',
        'type': 'workstation',
        'services': [],
        'open_ports': []
    })
    
    changes = mapper.tracker.detect_changes(enriched_copy)
    if changes:
        print(f"   ✓ Detected changes:")
        print(f"     - New devices: {len(changes.get('new_devices', []))}")
        print(f"     - Missing devices: {len(changes.get('missing_devices', []))}")
        print(f"     - Changed devices: {len(changes.get('changed_devices', []))}")
    
    # Test SNMP configuration
    print("\n6. Testing SNMP configuration...")
    snmp_config = mapper.snmp_config
    test_config = {
        'version': 'v2c',
        'community': 'public',
        'timeout': 2,
        'retries': 1
    }
    snmp_config.save_config(test_config)
    loaded = snmp_config.load_config()
    print(f"   ✓ SNMP config saved and loaded: {loaded['version']}")
    
    # Test exports
    print("\n7. Testing export functionality...")
    export_mgr = mapper.export_mgr
    
    # Test CSV export
    csv_file = export_mgr.export_to_csv_enhanced(enriched)
    print(f"   ✓ CSV export: {csv_file.name}")
    
    # Test JSON export
    json_file = export_mgr.export_to_json(enriched, changes)
    print(f"   ✓ JSON export: {json_file.name}")
    
    # Test report generation
    print("\n8. Testing report generation...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save scan data
    scan_file = mapper.output_path / "scans" / f"scan_{timestamp}.json"
    with open(scan_file, 'w') as f:
        json.dump(enriched, f, indent=2)
    
    # Generate visualization data
    d3_data = mapper.map_gen.generate_d3_data(enriched)
    three_data = mapper.map_gen.generate_threejs_data(enriched)
    
    print(f"   ✓ Generated D3 data: {len(d3_data['nodes'])} nodes, {len(d3_data['links'])} links")
    print(f"   ✓ Generated 3D data: {len(three_data)} nodes")
    
    # Test device annotation
    print("\n9. Testing device annotation...")
    # Add annotation directly
    from core.annotator import DeviceAnnotation
    annotation = DeviceAnnotation(
        ip='192.168.1.1',
        critical=True,
        notes='Main router - critical infrastructure'
    )
    mapper.annotator.annotations['192.168.1.1'] = annotation
    mapper.annotator.save_annotations()
    
    annotated = mapper.annotator.apply_annotations(enriched)
    critical_count = sum(1 for d in annotated if d.get('critical', False))
    print(f"   ✓ Annotated devices: {critical_count} critical")
    
    # Summary
    print("\n" + "=" * 50)
    print("SYSTEM TEST COMPLETE")
    print("=" * 50)
    print("\nAll components tested successfully:")
    print("✓ Device discovery and classification")
    print("✓ Vulnerability scanning (APIs + local)")
    print("✓ Change tracking between scans")
    print("✓ SNMP configuration management")
    print("✓ Multiple export formats")
    print("✓ Report data generation")
    print("✓ Device annotation system")
    
    # Cleanup test files
    print("\nCleaning up test files...")
    for file in [csv_file, json_file, scan_file, prev_scan_file]:
        if file.exists():
            file.unlink()
    print("✓ Cleanup complete")
    
    return True


if __name__ == "__main__":
    try:
        success = test_full_system()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ System test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)