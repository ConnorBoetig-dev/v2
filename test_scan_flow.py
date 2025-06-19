#!/usr/bin/env python3
"""Test script to trace scan data flow and identify where vendor/OS/services are lost"""

import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from utils.mac_lookup import MACLookup
from core.scanner_async import AsyncNetworkScanner
import asyncio
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Test data that mimics what masscan would find
mock_masscan_devices = [
    {
        "ip": "10.1.100.31",
        "mac": "84:A9:38:8F:5C:30",
        "hostname": "",
        "vendor": "",
        "type": "unknown",
        "os": "",
        "services": ["tcp:3389"],
        "open_ports": [3389],
        "scan_time": "2025-06-19T10:00:00",
        "discovery_method": "masscan",
    },
    {
        "ip": "10.1.104.6",
        "mac": "E8:40:F2:E1:FE:63",
        "hostname": "",
        "vendor": "",
        "type": "unknown",
        "os": "",
        "services": ["tcp:3389", "tcp:22"],
        "open_ports": [3389, 22],
        "scan_time": "2025-06-19T10:00:00",
        "discovery_method": "masscan",
    },
]


def test_vendor_lookup():
    """Test MAC vendor lookup"""
    print("\n=== Testing MAC Vendor Lookup ===")
    mac_lookup = MACLookup()

    test_macs = ["84:A9:38:8F:5C:30", "E8:40:F2:E1:FE:63", "A0:CE:C8:6C:CD:4B"]

    for mac in test_macs:
        vendor = mac_lookup.lookup(mac)
        print(f"MAC: {mac} -> Vendor: {vendor or 'Not found'}")

    # Check OUI database stats
    stats = mac_lookup.get_stats()
    print(f"\nOUI Database stats:")
    print(f"  Entries: {stats['vendor_count']}")
    print(f"  File exists: {stats['database_exists']}")
    print(f"  File size: {stats['database_size']} bytes")


def test_enrichment_merge():
    """Test how enrichment data is merged"""
    print("\n=== Testing Enrichment Data Merge ===")

    # Simulate what nmap enrichment would return
    enriched_data = {
        "ip": "10.1.100.31",
        "mac": "84:A9:38:8F:5C:30",
        "hostname": "DESKTOP-ABC123",
        "vendor": "Lite-On Technology Corporation",  # From nmap
        "type": "workstation",
        "os": "Microsoft Windows 10",
        "os_accuracy": 95,
        "services": ["ms-wbt-server:3389 (Microsoft Terminal Services)"],
        "open_ports": [3389],
    }

    # Original device from masscan
    original = mock_masscan_devices[0].copy()
    print(f"Original: {json.dumps(original, indent=2)}")

    # Simulate merge
    original.update(
        {
            "hostname": enriched_data.get("hostname", ""),
            "os": enriched_data.get("os", ""),
            "os_accuracy": enriched_data.get("os_accuracy", 0),
            "services": enriched_data.get("services", [])
            if enriched_data.get("services")
            else original.get("services", []),
            "vendor": enriched_data.get("vendor") or original.get("vendor", ""),
            "mac": enriched_data.get("mac") or original.get("mac", ""),
        }
    )

    print(f"\nAfter merge: {json.dumps(original, indent=2)}")


def test_nmap_xml_parsing():
    """Test parsing of nmap XML output"""
    print("\n=== Testing Nmap XML Parsing ===")

    # Create a sample nmap XML that would come from enrichment
    sample_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.1.100.31" addrtype="ipv4"/>
    <address addr="84:A9:38:8F:5C:30" addrtype="mac" vendor="Lite-On Technology Corporation"/>
    <hostnames>
      <hostname name="DESKTOP-ABC123" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server" product="Microsoft Terminal Services" version="10.0" />
      </port>
    </ports>
    <os>
      <osmatch name="Microsoft Windows 10 1809" accuracy="95" line="69514">
        <osclass type="general purpose" vendor="Microsoft" osfamily="Windows" osgen="10" accuracy="95"/>
      </osmatch>
    </os>
  </host>
</nmaprun>"""

    # Save to temp file
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(sample_xml)
        temp_file = f.name

    # Parse with scanner's parser
    scanner = AsyncNetworkScanner()
    parsed = scanner._parse_nmap_xml(temp_file)

    print(f"Parsed device: {json.dumps(parsed[0], indent=2)}")

    # Cleanup
    import os

    os.unlink(temp_file)


async def test_full_enrichment():
    """Test the full enrichment process"""
    print("\n=== Testing Full Enrichment Process ===")

    scanner = AsyncNetworkScanner()

    # Test enrichment of mock devices
    print("Starting with masscan devices:")
    for d in mock_masscan_devices:
        print(f"  {d['ip']}: services={d['services']}, vendor={d['vendor']}, os={d['os']}")

    # This would normally be called internally
    enriched = await scanner._enrich_devices_async(mock_masscan_devices.copy())

    print("\nAfter enrichment:")
    for d in enriched:
        print(
            f"  {d['ip']}: services={d.get('services', [])}, vendor={d.get('vendor', '')}, os={d.get('os', '')}"
        )


def check_report_template():
    """Check how the report template processes data"""
    print("\n=== Checking Report Template Processing ===")

    # Simulate what the report would receive
    test_device = {
        "ip": "10.1.100.31",
        "mac": "84:A9:38:8F:5C:30",
        "vendor": "Lite-On Technology Corporation",
        "os": "Microsoft Windows 10",
        "services": ["ms-wbt-server:3389", "tcp:445", "http:80"],
    }

    print(f"Device data: {json.dumps(test_device, indent=2)}")
    print("\nHow it would appear in report:")
    print(f"  Vendor column: {test_device.get('vendor', '-')}")
    print(f"  OS column: ", end="")

    # Simulate OS display logic
    os_val = test_device.get("os", "")
    if os_val:
        if "windows" in os_val.lower():
            print("Windows")
        elif "darwin" in os_val.lower() or "macos" in os_val.lower():
            print("macOS")
        elif "linux" in os_val.lower():
            print("Linux")
        else:
            print(os_val)
    else:
        print("-")

    print(f"  Services: {', '.join(test_device.get('services', []))}")


if __name__ == "__main__":
    # Run all tests
    test_vendor_lookup()
    test_enrichment_merge()
    test_nmap_xml_parsing()

    # Run async test
    print("\n" + "=" * 50)
    asyncio.run(test_full_enrichment())

    check_report_template()

    print("\n=== Summary ===")
    print("Check the output above to identify where data is being lost.")
