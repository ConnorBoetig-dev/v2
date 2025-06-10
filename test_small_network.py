#!/usr/bin/env python3
"""
Test script for small networks without routers
Simulates a typical home/small office network
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.classifier import DeviceClassifier
from core.parser import ScanParser
from utils.traffic_analyzer import PassiveTrafficAnalyzer
from utils.visualization import MapGenerator


def create_small_network_data():
    """Create test data for a small network without a router"""
    devices = [
        {
            "ip": "192.168.1.100",
            "hostname": "desktop-main",
            "mac": "00:11:22:33:44:55",
            "vendor": "Dell Inc.",
            "type": "workstation",
            "os": "Windows 10",
            "services": ["http", "rdp", "smb"],
            "open_ports": [80, 3389, 445],
            "last_seen": datetime.now().isoformat(),
        },
        {
            "ip": "192.168.1.101",
            "hostname": "laptop-work",
            "mac": "AA:BB:CC:DD:EE:FF",
            "vendor": "Apple Inc.",
            "type": "workstation",
            "os": "macOS",
            "services": ["ssh", "vnc"],
            "open_ports": [22, 5900],
            "last_seen": datetime.now().isoformat(),
        },
        {
            "ip": "192.168.1.102",
            "hostname": "raspberrypi",
            "mac": "B8:27:EB:11:22:33",
            "vendor": "Raspberry Pi Foundation",
            "type": "linux_server",
            "os": "Linux",
            "services": ["ssh", "http", "mqtt"],
            "open_ports": [22, 80, 1883],
            "last_seen": datetime.now().isoformat(),
        },
        {
            "ip": "192.168.1.103",
            "hostname": "printer-office",
            "mac": "00:1B:44:11:3A:B7",
            "vendor": "HP",
            "type": "printer",
            "services": ["ipp", "http"],
            "open_ports": [631, 80],
            "last_seen": datetime.now().isoformat(),
        },
    ]

    # Add some passive analysis data
    for device in devices:
        if device["type"] == "workstation":
            device["passive_analysis"] = {
                "traffic_flows": 150,
                "services_observed": ["http", "https", "dns"],
                "communication_peers": 12,
                "inbound_flows": 30,
                "outbound_flows": 120,
            }

    return devices


def create_traffic_flow_matrix():
    """Create a traffic flow matrix for the small network"""
    flow_matrix = {
        "192.168.1.100": {
            "192.168.1.102": 250,  # Desktop to Raspberry Pi
            "192.168.1.103": 50,  # Desktop to Printer
            "8.8.8.8": 1000,  # Desktop to Internet (DNS)
            "192.168.1.101": 30,  # Desktop to Laptop
        },
        "192.168.1.101": {
            "192.168.1.102": 180,  # Laptop to Raspberry Pi
            "192.168.1.103": 20,  # Laptop to Printer
            "8.8.8.8": 800,  # Laptop to Internet
            "192.168.1.100": 30,  # Laptop to Desktop
        },
        "192.168.1.102": {
            "192.168.1.100": 100,  # Raspberry Pi to Desktop
            "192.168.1.101": 80,  # Raspberry Pi to Laptop
            "8.8.8.8": 200,  # Raspberry Pi to Internet
        },
        "192.168.1.103": {
            "192.168.1.100": 10,  # Printer responses
            "192.168.1.101": 5,  # Printer responses
        },
    }

    return flow_matrix


def test_visualization():
    """Test visualization with small network data"""
    print("Testing visualization for small network...")

    # Create test data
    devices = create_small_network_data()
    flow_matrix = create_traffic_flow_matrix()

    # Test map generator
    map_gen = MapGenerator()

    # Test basic D3 data generation
    d3_data = map_gen.generate_d3_data(devices)
    print(f"✓ Generated D3 data: {len(d3_data['nodes'])} nodes, {len(d3_data['links'])} links")

    # For small networks without routers, we expect minimal or no inferred connections
    print(f"  Note: Basic topology shows {len(d3_data['links'])} inferred connections")

    # Test traffic flow data generation
    traffic_data = map_gen.generate_traffic_flow_data(devices, flow_matrix)
    print(f"✓ Generated traffic flow data: {len(traffic_data['links'])} traffic links")

    # Test 3D data generation
    three_data = map_gen.generate_threejs_data(devices)
    print(f"✓ Generated 3D data: {len(three_data['positions'])} positions")

    # Save test data for manual inspection
    output_dir = Path("output/test")
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(output_dir / "small_network_d3.json", "w") as f:
        json.dump(d3_data, f, indent=2)

    with open(output_dir / "small_network_traffic.json", "w") as f:
        json.dump(traffic_data, f, indent=2)

    print(f"\n✓ Test data saved to {output_dir}")

    return True


def test_device_classification():
    """Test device classification for small network devices"""
    print("\nTesting device classification...")

    classifier = DeviceClassifier()
    devices = create_small_network_data()

    # Test classification
    classified_devices = classifier.classify_devices(devices)

    for device in classified_devices:
        print(
            f"  {device['hostname']}: Type = '{device['type']}', Confidence = {device.get('classification_confidence', 0)}"
        )

    return True


def test_passive_analysis_integration():
    """Test passive analysis with empty/minimal data"""
    print("\nTesting passive analysis integration...")

    analyzer = PassiveTrafficAnalyzer()
    devices = create_small_network_data()

    # Test merge with empty passive data
    merged = analyzer.merge_with_active_scan(devices)
    print(f"✓ Merged {len(merged)} devices (no passive data)")

    # Test export with no capture data
    try:
        devices_file, flows_file = analyzer.export_results("test_timestamp")
        print(f"✓ Exported empty results: {devices_file.name}, {flows_file.name}")

        # Verify files are valid JSON
        with open(devices_file) as f:
            data = json.load(f)
            assert "devices" in data

        with open(flows_file) as f:
            data = json.load(f)
            assert "flow_matrix" in data

    except Exception as e:
        print(f"✗ Export failed: {e}")
        return False

    return True


def main():
    """Run all tests for small networks"""
    print("Small Network Test Suite")
    print("=" * 50)

    tests = [
        ("Visualization", test_visualization),
        ("Device Classification", test_device_classification),
        ("Passive Analysis Integration", test_passive_analysis_integration),
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"\n✅ {test_name} test passed")
            else:
                failed += 1
                print(f"\n❌ {test_name} test failed")
        except Exception as e:
            failed += 1
            print(f"\n❌ {test_name} test failed with error: {e}")
            import traceback

            traceback.print_exc()

    print("\n" + "=" * 50)
    print(f"Results: {passed} passed, {failed} failed")

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
