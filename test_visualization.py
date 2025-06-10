#!/usr/bin/env python3
"""
Test script to demonstrate the new network visualization
"""

import json
from datetime import datetime
from pathlib import Path

from core.classifier import DeviceClassifier
from utils.visualization import MapGenerator


def generate_test_network():
    """Generate a realistic test network"""
    devices = [
        # Core Infrastructure
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
        },
        {
            "ip": "192.168.1.2",
            "hostname": "core-router-02",
            "mac": "00:11:22:33:44:56",
            "vendor": "Cisco Systems",
            "type": "router",
            "open_ports": [22, 80, 443],
            "services": ["ssh:22", "http:80", "https:443"],
            "os": "Cisco IOS 15.2",
            "critical": True,
            "notes": "Backup gateway router",
        },
        # Switches
        {
            "ip": "192.168.1.10",
            "hostname": "switch-floor1",
            "mac": "AA:BB:CC:DD:EE:01",
            "vendor": "HP",
            "type": "switch",
            "open_ports": [22, 80],
            "services": ["ssh:22", "http:80"],
            "os": "HP ProCurve",
            "critical": True,
        },
        {
            "ip": "192.168.1.11",
            "hostname": "switch-floor2",
            "mac": "AA:BB:CC:DD:EE:02",
            "vendor": "HP",
            "type": "switch",
            "open_ports": [22, 80],
            "services": ["ssh:22", "http:80"],
            "os": "HP ProCurve",
            "critical": True,
        },
        {
            "ip": "192.168.1.12",
            "hostname": "switch-datacenter",
            "mac": "AA:BB:CC:DD:EE:03",
            "vendor": "Cisco Systems",
            "type": "switch",
            "open_ports": [22, 80],
            "services": ["ssh:22", "http:80"],
            "os": "Cisco Catalyst",
            "critical": True,
        },
        # Servers
        {
            "ip": "192.168.1.20",
            "hostname": "web-server-01",
            "mac": "11:22:33:44:55:01",
            "vendor": "Dell Inc.",
            "type": "web_server",
            "open_ports": [22, 80, 443],
            "services": ["ssh:22", "http:80", "https:443"],
            "os": "Ubuntu 20.04 LTS",
            "critical": True,
            "notes": "Production web server",
        },
        {
            "ip": "192.168.1.21",
            "hostname": "web-server-02",
            "mac": "11:22:33:44:55:02",
            "vendor": "Dell Inc.",
            "type": "web_server",
            "open_ports": [22, 80, 443],
            "services": ["ssh:22", "http:80", "https:443"],
            "os": "Ubuntu 20.04 LTS",
            "critical": True,
            "notes": "Load balanced web server",
        },
        {
            "ip": "192.168.1.25",
            "hostname": "db-server-01",
            "mac": "11:22:33:44:55:05",
            "vendor": "Dell Inc.",
            "type": "database",
            "open_ports": [22, 3306],
            "services": ["ssh:22", "mysql:3306"],
            "os": "CentOS 8",
            "critical": True,
            "notes": "Primary database server",
        },
        {
            "ip": "192.168.1.26",
            "hostname": "db-server-02",
            "mac": "11:22:33:44:55:06",
            "vendor": "Dell Inc.",
            "type": "database",
            "open_ports": [22, 3306],
            "services": ["ssh:22", "mysql:3306"],
            "os": "CentOS 8",
            "critical": True,
            "notes": "Database replica",
        },
        {
            "ip": "192.168.1.30",
            "hostname": "file-server",
            "mac": "11:22:33:44:55:10",
            "vendor": "HP",
            "type": "windows_server",
            "open_ports": [445, 3389],
            "services": ["smb:445", "rdp:3389"],
            "os": "Windows Server 2019",
            "critical": False,
        },
        # Workstations
        {
            "ip": "192.168.1.100",
            "hostname": "ws-john-doe",
            "mac": "22:33:44:55:66:01",
            "vendor": "Dell Inc.",
            "type": "workstation",
            "open_ports": [],
            "services": [],
            "os": "Windows 10 Pro",
            "critical": False,
        },
        {
            "ip": "192.168.1.101",
            "hostname": "ws-jane-smith",
            "mac": "22:33:44:55:66:02",
            "vendor": "Apple Inc.",
            "type": "workstation",
            "open_ports": [],
            "services": [],
            "os": "macOS Monterey",
            "critical": False,
        },
        {
            "ip": "192.168.1.102",
            "hostname": "ws-dev-01",
            "mac": "22:33:44:55:66:03",
            "vendor": "Lenovo",
            "type": "workstation",
            "open_ports": [22],
            "services": ["ssh:22"],
            "os": "Ubuntu 22.04",
            "critical": False,
        },
        {
            "ip": "192.168.1.103",
            "hostname": "ws-dev-02",
            "mac": "22:33:44:55:66:04",
            "vendor": "Lenovo",
            "type": "workstation",
            "open_ports": [22],
            "services": ["ssh:22"],
            "os": "Ubuntu 22.04",
            "critical": False,
        },
        # Printers and IoT
        {
            "ip": "192.168.1.200",
            "hostname": "printer-floor1",
            "mac": "33:44:55:66:77:01",
            "vendor": "HP",
            "type": "printer",
            "open_ports": [80, 9100],
            "services": ["http:80", "jetdirect:9100"],
            "os": "HP Embedded",
            "critical": False,
        },
        {
            "ip": "192.168.1.201",
            "hostname": "printer-floor2",
            "mac": "33:44:55:66:77:02",
            "vendor": "Canon",
            "type": "printer",
            "open_ports": [80, 9100],
            "services": ["http:80", "jetdirect:9100"],
            "os": "Canon Embedded",
            "critical": False,
        },
        {
            "ip": "192.168.1.210",
            "hostname": "camera-entrance",
            "mac": "44:55:66:77:88:01",
            "vendor": "Hikvision",
            "type": "iot",
            "open_ports": [80, 554],
            "services": ["http:80", "rtsp:554"],
            "os": "Linux Embedded",
            "critical": False,
            "notes": "Security camera",
        },
        {
            "ip": "192.168.1.211",
            "hostname": "thermostat-main",
            "mac": "44:55:66:77:88:02",
            "vendor": "Nest",
            "type": "iot",
            "open_ports": [80],
            "services": ["http:80"],
            "os": "Nest OS",
            "critical": False,
        },
        # Unknown device (for testing)
        {
            "ip": "192.168.1.250",
            "hostname": "",
            "mac": "55:66:77:88:99:00",
            "vendor": "",
            "type": "unknown",
            "open_ports": [8080],
            "services": ["http:8080"],
            "os": "",
            "critical": False,
            "notes": "Unidentified device - investigate",
        },
    ]

    # Add timestamps
    for device in devices:
        device["last_seen"] = datetime.now().isoformat()

    return devices


def generate_changes():
    """Generate sample network changes"""
    changes = {
        "new_devices": [
            {
                "ip": "192.168.1.104",
                "hostname": "ws-new-hire",
                "mac": "22:33:44:55:66:05",
                "type": "workstation",
                "vendor": "Dell Inc.",
            },
            {
                "ip": "192.168.1.212",
                "hostname": "camera-parking",
                "mac": "44:55:66:77:88:03",
                "type": "iot",
                "vendor": "Dahua",
            },
        ],
        "missing_devices": [{"ip": "192.168.1.199", "hostname": "old-printer", "type": "printer"}],
        "changed_devices": [
            {
                "ip": "192.168.1.20",
                "hostname": "web-server-01",
                "changes": [{"field": "ports", "action": "Port 8080 opened"}],
            },
            {
                "ip": "192.168.1.25",
                "hostname": "db-server-01",
                "changes": [{"field": "services", "action": "PostgreSQL service added"}],
            },
        ],
        "summary": {
            "total_current": 20,
            "total_previous": 19,
            "new": 2,
            "missing": 1,
            "changed": 2,
        },
    }

    return changes


def main():
    """Generate test visualization"""
    # Create output directories
    output_path = Path("output")
    (output_path / "reports").mkdir(parents=True, exist_ok=True)
    (output_path / "scans").mkdir(parents=True, exist_ok=True)

    # Generate test data
    print("Generating test network data...")
    devices = generate_test_network()
    changes = generate_changes()

    # Classify devices
    classifier = DeviceClassifier()
    devices = classifier.classify_devices(devices)

    # Generate visualization data
    print("Generating visualization data...")
    map_gen = MapGenerator()
    d3_data = map_gen.generate_d3_data(devices)
    three_data = map_gen.generate_threejs_data(devices)

    # Save scan data
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_file = output_path / "scans" / f"scan_{timestamp}.json"
    with open(scan_file, "w") as f:
        json.dump(devices, f, indent=2)

    # Generate HTML reports
    print("Generating HTML reports...")
    import time

    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader("templates"))

    report_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_timestamp": timestamp,
        "scan_date": datetime.now().strftime("%B %d, %Y"),
        "total_devices": len(devices),
        "devices": devices,
        "device_types": {
            device_type: len([d for d in devices if d.get("type") == device_type])
            for device_type in set(d.get("type", "unknown") for d in devices)
        },
        "critical_devices": [d for d in devices if d.get("critical", False)],
        "d3_data": json.dumps(d3_data),
        "three_data": json.dumps(three_data),
        "subnet_summary": map_gen.generate_subnet_topology(devices)["subnets"],
        "changes": changes,
    }

    # Generate network visualization
    viz_template = env.get_template("network_visualization.html")
    viz_file = output_path / "reports" / f"network_map_{timestamp}.html"
    viz_content = viz_template.render(**report_data)

    with open(viz_file, "w") as f:
        f.write(viz_content)

    # Generate detailed report
    report_template = env.get_template("report.html")
    report_file = output_path / "reports" / f"report_{timestamp}.html"
    report_content = report_template.render(**report_data)

    with open(report_file, "w") as f:
        f.write(report_content)

    # Open both in browser
    import webbrowser

    viz_url = f"file://{viz_file.absolute()}"
    report_url = f"file://{report_file.absolute()}"

    webbrowser.open(viz_url)
    time.sleep(0.5)
    webbrowser.open(report_url)

    print(f"\n✓ Test reports generated!")
    print(f"\nGenerated files:")
    print(f"Network Map: {viz_url}")
    print(f"Detailed Report: {report_url}")
    print(f"\nTest network contains:")
    print(f"  - {len(devices)} total devices")
    print(f"  - {len([d for d in devices if d.get('critical')])} critical devices")
    print(f"  - {len(d3_data['links'])} network connections")
    print(f"  - {len(changes['new_devices'])} new devices")
    print(f"  - {len(changes['changed_devices'])} changed devices")


if __name__ == "__main__":
    main()
