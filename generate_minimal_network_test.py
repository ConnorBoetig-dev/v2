#!/usr/bin/env python3
"""
Generate minimal realistic network data for testing visualization
"""

import json
from datetime import datetime
from pathlib import Path

def generate_minimal_network():
    """Generate minimal network with switch, server, and workstation"""
    devices = []

    # 1. Network Switch (acts as central infrastructure)
    devices.append({
        "ip": "192.168.1.1",
        "hostname": "main-switch",
        "mac": "00:24:E8:11:22:33",
        "vendor": "HP Inc.",
        "type": "switch",
        "os": "ProCurve",
        "services": ["ssh:22", "telnet:23"],
        "open_ports": [22, 23],
        "critical": True,
        "confidence": 90,
        "last_seen": datetime.now().isoformat(),
        "first_seen": "2024-01-01T08:00:00Z",
        "notes": "Main network switch",
        "tags": ["infrastructure"]
    })

    # 2. Linux Server
    devices.append({
        "ip": "192.168.1.10",
        "hostname": "app-server",
        "mac": "00:50:56:12:34:56",
        "vendor": "VMware",
        "type": "linux_server",
        "os": "Ubuntu 22.04 LTS",
        "services": ["ssh:22", "http:80", "https:443"],
        "open_ports": [22, 80, 443],
        "critical": True,
        "confidence": 95,
        "last_seen": datetime.now().isoformat(),
        "first_seen": "2024-01-01T08:00:00Z",
        "notes": "Application server",
        "tags": ["production", "server"]
    })

    # 3. Workstation
    devices.append({
        "ip": "192.168.1.20",
        "hostname": "DESKTOP-01",
        "mac": "00:1C:23:45:67:89",
        "vendor": "Dell Inc.",
        "type": "workstation",
        "os": "Windows 11 Pro",
        "services": ["microsoft-ds:445"],
        "open_ports": [445],
        "critical": False,
        "confidence": 85,
        "last_seen": datetime.now().isoformat(),
        "first_seen": "2024-01-01T08:00:00Z",
        "notes": "User workstation",
        "tags": ["workstation", "user"]
    })

    return devices

def main():
    """Generate and save minimal test data"""
    print("🧪 Minimal Network Test Generator")
    print("=" * 40)

    # Create output directory
    output_dir = Path("output/scans")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate test devices
    devices = generate_minimal_network()
    print(f"Generated {len(devices)} devices:")
    for device in devices:
        print(f"  - {device['hostname']} ({device['ip']}) - Type: {device['type']}")

    # Save as scan file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_file = output_dir / f"scan_{timestamp}.json"

    with open(scan_file, 'w') as f:
        json.dump(devices, f, indent=2)

    print(f"\n✅ Saved test data to: {scan_file}")

    print(f"\n🎯 Expected connections:")
    print(f"   - Server → Switch (server_link)")
    print(f"   - Workstation → Switch (access)")
    print(f"\nThis should create a star topology with the switch at the center.")

if __name__ == "__main__":
    main()
