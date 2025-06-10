#!/usr/bin/env python3
"""
Test script to demonstrate export functionality
"""

import json
from datetime import datetime
from pathlib import Path

from utils.export_manager import ExportManager


def generate_sample_data():
    """Generate sample network data for testing exports"""
    devices = [
        {
            "ip": "192.168.1.1",
            "hostname": "core-router-01",
            "mac": "00:11:22:33:44:55",
            "vendor": "Cisco Systems",
            "type": "router",
            "open_ports": [22, 80, 443],
            "services": ["ssh:22", "http:80", "https:443"],
            "os": "Cisco IOS 15.2",
            "critical": True,
            "notes": "Main gateway router - DO NOT MODIFY",
            "last_seen": datetime.now().isoformat(),
        },
        {
            "ip": "192.168.1.10",
            "hostname": "web-server-01",
            "mac": "AA:BB:CC:DD:EE:FF",
            "vendor": "Dell Inc.",
            "type": "web_server",
            "open_ports": [22, 80, 443, 3306],
            "services": ["ssh:22", "http:80", "https:443", "mysql:3306"],
            "os": "Ubuntu 20.04 LTS",
            "critical": True,
            "notes": "Production web server",
            "last_seen": datetime.now().isoformat(),
        },
        {
            "ip": "192.168.1.100",
            "hostname": "ws-john-doe",
            "mac": "11:22:33:44:55:66",
            "vendor": "Dell Inc.",
            "type": "workstation",
            "open_ports": [],
            "services": [],
            "os": "Windows 10 Pro",
            "critical": False,
            "notes": "",
            "last_seen": datetime.now().isoformat(),
        },
        {
            "ip": "192.168.1.200",
            "hostname": "printer-floor1",
            "mac": "22:33:44:55:66:77",
            "vendor": "HP",
            "type": "printer",
            "open_ports": [80, 9100],
            "services": ["http:80", "jetdirect:9100"],
            "os": "HP Embedded",
            "critical": False,
            "notes": "Network printer - 2nd floor",
            "last_seen": datetime.now().isoformat(),
        },
        {
            "ip": "192.168.1.250",
            "hostname": "",
            "mac": "FF:EE:DD:CC:BB:AA",
            "vendor": "",
            "type": "unknown",
            "open_ports": [8080, 8443],
            "services": ["http:8080", "https:8443"],
            "os": "",
            "critical": False,
            "notes": "Unidentified device - investigate",
            "last_seen": datetime.now().isoformat(),
        },
    ]

    # Add more devices for better testing
    for i in range(5, 20):
        devices.append(
            {
                "ip": f"192.168.1.{100 + i}",
                "hostname": f"ws-user-{i:02d}",
                "mac": f"AA:BB:CC:{i:02X}:EE:FF",
                "vendor": "Various",
                "type": "workstation",
                "open_ports": [],
                "services": [],
                "os": "Windows 10",
                "critical": False,
                "notes": "",
                "last_seen": datetime.now().isoformat(),
            }
        )

    return devices


def generate_sample_changes():
    """Generate sample change data"""
    changes = {
        "new_devices": [
            {
                "ip": "192.168.1.105",
                "hostname": "new-server",
                "type": "linux_server",
                "vendor": "Dell Inc.",
                "mac": "AA:BB:CC:DD:EE:01",
            },
            {
                "ip": "192.168.1.106",
                "hostname": "new-printer",
                "type": "printer",
                "vendor": "Canon",
                "mac": "AA:BB:CC:DD:EE:02",
            },
        ],
        "missing_devices": [
            {
                "ip": "192.168.1.199",
                "hostname": "old-server",
                "type": "server",
                "last_seen": "2024-01-01T12:00:00",
            }
        ],
        "changed_devices": [
            {
                "ip": "192.168.1.10",
                "hostname": "web-server-01",
                "changes": [
                    {"field": "ports", "action": "Port 8080 opened"},
                    {"field": "services", "action": "New service: tomcat"},
                ],
            }
        ],
        "summary": {
            "total_current": 20,
            "total_previous": 19,
            "new": 2,
            "missing": 1,
            "changed": 1,
        },
    }

    return changes


def main():
    """Test export functionality"""
    print("NetworkMapper Export Test")
    print("=" * 50)

    # Create export manager
    output_path = Path("output")
    export_mgr = ExportManager(output_path)

    # Generate sample data
    devices = generate_sample_data()
    changes = generate_sample_changes()

    print(f"\nGenerated {len(devices)} sample devices")
    print(f"Critical devices: {len([d for d in devices if d.get('critical', False)])}")
    print(f"Device types: {len(set(d.get('type', 'unknown') for d in devices))}")

    # Test each export format
    print("\n1. Testing PDF Export...")
    try:
        pdf_path = export_mgr.export_to_pdf(devices, changes)
        print(f"   ✓ PDF exported to: {pdf_path}")
    except Exception as e:
        print(f"   ✗ PDF export failed: {e}")

    print("\n2. Testing Excel Export...")
    try:
        excel_path = export_mgr.export_to_excel(devices, changes)
        print(f"   ✓ Excel exported to: {excel_path}")
    except Exception as e:
        print(f"   ✗ Excel export failed: {e}")

    print("\n3. Testing JSON Export...")
    try:
        json_path = export_mgr.export_to_json(devices, changes)
        print(f"   ✓ JSON exported to: {json_path}")

        # Verify JSON content
        with open(json_path) as f:
            data = json.load(f)
            print(f"   - Metadata: {data['metadata']}")
            print(f"   - Device count: {len(data['devices'])}")
            print(f"   - Subnet analysis: {len(data['subnet_analysis'])} subnets")
    except Exception as e:
        print(f"   ✗ JSON export failed: {e}")

    print("\n4. Testing CSV Export...")
    try:
        csv_path = export_mgr.export_to_csv_enhanced(devices)
        print(f"   ✓ CSV exported to: {csv_path}")
    except Exception as e:
        print(f"   ✗ CSV export failed: {e}")

    print("\n" + "=" * 50)
    print("Export test complete!")
    print(f"\nAll exports saved to: {output_path / 'exports'}")
    print("\nYou can now:")
    print("1. Open the PDF for a professional report")
    print("2. Open the Excel file for detailed analysis")
    print("3. Use the JSON for integration with other tools")
    print("4. Import the CSV into any spreadsheet application")


if __name__ == "__main__":
    main()
