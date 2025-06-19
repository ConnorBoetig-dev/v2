#!/usr/bin/env python3
"""Test the actual deeper scan enrichment process"""

import json
import asyncio
import logging
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

sys.path.append(str(Path(__file__).parent))

from core.scanner_async import AsyncNetworkScanner

# Enable detailed logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


async def test_deeper_scan():
    """Test a deeper scan on a small target"""
    scanner = AsyncNetworkScanner()

    # Test on localhost to ensure we get results
    print("=== Testing Deeper Scan ===")
    print("Scanning localhost to test enrichment...")

    devices = await scanner.scan(target="127.0.0.1", scan_type="deeper")

    print(f"\nFound {len(devices)} devices")
    for device in devices:
        print(f"\nDevice: {device['ip']}")
        print(f"  MAC: {device.get('mac', 'N/A')}")
        print(f"  Vendor: {device.get('vendor', 'N/A')}")
        print(f"  OS: {device.get('os', 'N/A')}")
        print(f"  Services: {device.get('services', [])}")
        print(f"  Open Ports: {device.get('open_ports', [])}")


def check_xml_parsing():
    """Check if we can parse actual nmap output"""
    print("\n=== Testing Nmap Command and Parsing ===")

    import subprocess
    import tempfile

    # Run a simple nmap scan
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        temp_file = f.name

    cmd = [
        "sudo",
        "-n",
        "nmap",
        "-sS",
        "-sV",
        "-O",
        "--osscan-guess",
        "--top-ports",
        "10",
        "-oX",
        temp_file,
        "127.0.0.1",
    ]

    print(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print(f"Return code: {result.returncode}")

        if result.returncode != 0:
            print(f"STDERR: {result.stderr}")
            return

        # Parse the XML
        tree = ET.parse(temp_file)
        root = tree.getroot()

        print(f"\nXML root tag: {root.tag}")
        print(f"Hosts found: {len(root.findall('.//host'))}")

        for host in root.findall(".//host"):
            status = host.find(".//status")
            if status is not None:
                print(f"Host status: {status.get('state')}")

            # Check what we got
            ip_elem = host.find('.//address[@addrtype="ipv4"]')
            if ip_elem is not None:
                print(f"IP: {ip_elem.get('addr')}")

            mac_elem = host.find('.//address[@addrtype="mac"]')
            if mac_elem is not None:
                print(f"MAC: {mac_elem.get('addr')}, Vendor: {mac_elem.get('vendor', 'N/A')}")

            # Check OS detection
            os_matches = host.findall(".//osmatch")
            print(f"OS matches found: {len(os_matches)}")
            for os_match in os_matches[:1]:  # First match
                print(f"  OS: {os_match.get('name')} (accuracy: {os_match.get('accuracy')}%)")

            # Check services
            ports = host.findall(".//port")
            print(f"Ports found: {len(ports)}")
            for port in ports:
                port_id = port.get("portid")
                service = port.find(".//service")
                if service is not None:
                    print(f"  Port {port_id}: {service.get('name', 'unknown')}")

    except subprocess.TimeoutExpired:
        print("Command timed out!")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        import os

        if os.path.exists(temp_file):
            os.unlink(temp_file)


def test_masscan_to_nmap_flow():
    """Test the flow from masscan discovery to nmap enrichment"""
    print("\n=== Testing Masscan -> Nmap Flow ===")

    # This is what masscan typically returns
    masscan_output = [
        {
            "ip": "10.1.100.31",
            "mac": "",  # Masscan doesn't get MAC
            "hostname": "",
            "vendor": "",
            "type": "unknown",
            "os": "",
            "services": ["tcp:3389"],  # Just protocol:port
            "open_ports": [3389],
            "discovery_method": "masscan",
        }
    ]

    print("Masscan output:")
    print(json.dumps(masscan_output[0], indent=2))

    print("\nWhat nmap enrichment should add:")
    print("- MAC address (if on same network)")
    print("- Vendor (from MAC)")
    print("- OS detection")
    print("- Service names (ms-wbt-server instead of tcp)")
    print("- Hostname")


if __name__ == "__main__":
    # Check sudo access first
    import subprocess

    result = subprocess.run(["sudo", "-n", "true"], capture_output=True)
    if result.returncode != 0:
        print("This test needs sudo access. Run: sudo -v")
        sys.exit(1)

    # Run tests
    check_xml_parsing()
    test_masscan_to_nmap_flow()

    # Run async test
    asyncio.run(test_deeper_scan())
