#!/usr/bin/env python3
"""
Generate test network data for NetworkMapper visualization testing
"""

import json
import random
from datetime import datetime
from pathlib import Path


def generate_test_devices():
    """Generate realistic test network devices"""
    devices = []

    # Test network: 192.168.1.0/24
    base_ip = "192.168.1"

    # 1. Router (Gateway)
    devices.append(
        {
            "ip": f"{base_ip}.1",
            "hostname": "gateway.local",
            "mac": "00:11:22:33:44:55",
            "vendor": "Cisco Systems",
            "type": "router",
            "os": "Cisco IOS 15.2",
            "services": ["ssh:22", "telnet:23", "http:80", "https:443"],
            "open_ports": [22, 23, 80, 443],
            "critical": True,
            "confidence": 95,
            "last_seen": datetime.now().isoformat(),
            "first_seen": "2024-01-01T08:00:00Z",
            "notes": "Main gateway router",
            "tags": ["infrastructure", "critical"],
        }
    )

    # 2. Network Switch
    devices.append(
        {
            "ip": f"{base_ip}.2",
            "hostname": "switch-01.local",
            "mac": "00:24:E8:11:22:33",
            "vendor": "HP Inc.",
            "type": "switch",
            "os": "ProCurve",
            "services": ["ssh:22", "telnet:23", "snmp:161"],
            "open_ports": [22, 23, 161],
            "critical": True,
            "confidence": 90,
            "last_seen": datetime.now().isoformat(),
            "first_seen": "2024-01-01T08:00:00Z",
            "notes": "Core network switch",
            "tags": ["infrastructure", "critical"],
        }
    )

    # 3. Linux Server
    devices.append(
        {
            "ip": f"{base_ip}.10",
            "hostname": "web-server-01",
            "mac": "00:50:56:12:34:56",
            "vendor": "VMware",
            "type": "linux_server",
            "os": "Ubuntu 22.04.3 LTS",
            "services": ["ssh:22", "http:80", "https:443", "mysql:3306"],
            "open_ports": [22, 80, 443, 3306],
            "critical": True,
            "confidence": 98,
            "last_seen": datetime.now().isoformat(),
            "first_seen": "2024-01-01T08:00:00Z",
            "notes": "Primary web server",
            "tags": ["production", "web", "critical"],
        }
    )

    # 4. Windows Server
    devices.append(
        {
            "ip": f"{base_ip}.11",
            "hostname": "DC-01",
            "mac": "00:15:5D:A1:B2:C3",
            "vendor": "Microsoft Corp",
            "type": "windows_server",
            "os": "Windows Server 2022",
            "services": ["microsoft-ds:445", "ldap:389", "kerberos:88", "dns:53"],
            "open_ports": [53, 88, 135, 389, 445, 3389],
            "critical": True,
            "confidence": 96,
            "last_seen": datetime.now().isoformat(),
            "first_seen": "2024-01-01T08:00:00Z",
            "notes": "Active Directory Domain Controller",
            "tags": ["infrastructure", "AD", "critical"],
        }
    )

    # 5. Database Server
    devices.append(
        {
            "ip": f"{base_ip}.12",
            "hostname": "db-server-01",
            "mac": "00:50:56:78:9A:BC",
            "vendor": "VMware",
            "type": "database",
            "os": "Ubuntu 22.04.3 LTS",
            "services": ["ssh:22", "postgresql:5432"],
            "open_ports": [22, 5432],
            "critical": True,
            "confidence": 94,
            "last_seen": datetime.now().isoformat(),
            "first_seen": "2024-01-01T08:00:00Z",
            "notes": "PostgreSQL database server",
            "tags": ["database", "production", "critical"],
        }
    )

    # 6-10. Workstations
    workstation_names = ["JOHN-PC", "MARY-LAPTOP", "DEV-WORKSTATION", "SALES-01", "ADMIN-PC"]
    for i, name in enumerate(workstation_names, 20):
        devices.append(
            {
                "ip": f"{base_ip}.{i}",
                "hostname": name,
                "mac": f"00:1C:23:{random.randint(10,99):02X}:{random.randint(10,99):02X}:{random.randint(10,99):02X}",
                "vendor": random.choice(["Dell Inc.", "HP Inc.", "Lenovo", "Apple"]),
                "type": "workstation",
                "os": random.choice(["Windows 11 Pro", "Windows 10 Pro", "macOS Sonoma"]),
                "services": ["microsoft-ds:445"]
                if "Windows" in random.choice(["Windows 11 Pro", "Windows 10 Pro", "macOS Sonoma"])
                else [],
                "open_ports": [445]
                if "Windows" in random.choice(["Windows 11 Pro", "Windows 10 Pro", "macOS Sonoma"])
                else [],
                "critical": False,
                "confidence": random.randint(75, 85),
                "last_seen": datetime.now().isoformat(),
                "first_seen": "2024-01-01T08:00:00Z",
                "notes": f"User workstation - {name.split('-')[0].title()}",
                "tags": ["workstation", "user"],
            }
        )

    # 11. Network Printer
    devices.append(
        {
            "ip": f"{base_ip}.100",
            "hostname": "printer-office-01",
            "mac": "00:26:B9:12:34:56",
            "vendor": "HP Inc.",
            "type": "printer",
            "os": "HP LaserJet",
            "services": ["ipp:631", "jetdirect:9100", "http:80"],
            "open_ports": [80, 515, 631, 9100],
            "critical": False,
            "confidence": 88,
            "last_seen": datetime.now().isoformat(),
            "first_seen": "2024-01-01T08:00:00Z",
            "notes": "Office laser printer",
            "tags": ["printer", "office"],
        }
    )

    # 12-14. IoT Devices
    iot_devices = [
        {"name": "security-cam-01", "ip": 150, "type": "iot", "desc": "Security camera"},
        {"name": "smart-thermostat", "ip": 151, "type": "iot", "desc": "Smart thermostat"},
        {"name": "wifi-ap-office", "ip": 152, "type": "iot", "desc": "WiFi access point"},
    ]

    for iot in iot_devices:
        devices.append(
            {
                "ip": f"{base_ip}.{iot['ip']}",
                "hostname": iot["name"],
                "mac": f"B8:27:EB:{random.randint(10,99):02X}:{random.randint(10,99):02X}:{random.randint(10,99):02X}",
                "vendor": random.choice(["Raspberry Pi Foundation", "Espressif Inc.", "TP-Link"]),
                "type": iot["type"],
                "os": "Embedded Linux",
                "services": ["http:80", "https:443"],
                "open_ports": [80, 443],
                "critical": False,
                "confidence": random.randint(70, 80),
                "last_seen": datetime.now().isoformat(),
                "first_seen": "2024-01-01T08:00:00Z",
                "notes": iot["desc"],
                "tags": ["iot", "smart-device"],
            }
        )

    # 15. Unknown device
    devices.append(
        {
            "ip": f"{base_ip}.200",
            "hostname": "",
            "mac": "00:00:00:00:00:00",
            "vendor": "",
            "type": "unknown",
            "os": "",
            "services": [],
            "open_ports": [],
            "critical": False,
            "confidence": 30,
            "last_seen": datetime.now().isoformat(),
            "first_seen": "2024-01-01T08:00:00Z",
            "notes": "Unidentified device",
            "tags": ["unknown"],
        }
    )

    return devices


def main():
    """Generate and save test data"""
    print("🧪 NetworkMapper Test Data Generator")
    print("=" * 40)

    # Create output directory
    output_dir = Path("output/scans")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate test devices
    devices = generate_test_devices()
    print(f"Generated {len(devices)} test devices")

    # Save as scan file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_file = output_dir / f"scan_{timestamp}.json"

    with open(scan_file, "w") as f:
        json.dump(devices, f, indent=2)

    print(f"✅ Saved test data to: {scan_file}")
    print(f"📊 Device breakdown:")

    # Count by type
    type_counts = {}
    for device in devices:
        dtype = device["type"]
        type_counts[dtype] = type_counts.get(dtype, 0) + 1

    for dtype, count in sorted(type_counts.items()):
        print(f"   {dtype}: {count}")

    print(f"\n🎯 Next steps:")
    print(f"   1. Run: python3 mapper.py")
    print(f"   2. Select: '📈 Generate Reports'")
    print(f"   3. Choose the scan you just created")
    print(f"   4. View the enhanced 2D/3D visualizations!")


if __name__ == "__main__":
    main()
