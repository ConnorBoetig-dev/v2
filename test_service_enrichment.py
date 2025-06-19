#!/usr/bin/env python3
"""Test service enrichment in deeper scan"""

import asyncio
import json
import logging
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

# Enable debug logging
logging.basicConfig(level=logging.DEBUG, format="%(message)s")

# Silence some noisy loggers
logging.getLogger("asyncio").setLevel(logging.WARNING)

from core.scanner_async import AsyncNetworkScanner


async def trace_deeper_scan():
    """Trace the deeper scan process step by step"""

    scanner = AsyncNetworkScanner()

    # Override some methods to add tracing
    original_run_masscan = scanner._run_masscan_deeper
    original_enrich = scanner._enrich_deeper_scan_async
    original_parse_xml = scanner._parse_nmap_xml

    async def traced_run_masscan(target):
        print("\n=== STEP 1: Masscan Discovery ===")
        devices = await original_run_masscan(target)
        print(f"Masscan found {len(devices)} devices:")
        for d in devices[:3]:  # Show first 3
            print(f"  {d['ip']}: services={d.get('services', [])}, vendor={d.get('vendor', 'N/A')}")
        return devices

    async def traced_enrich(devices):
        print("\n=== STEP 2: Nmap Enrichment ===")
        print(f"Enriching {len(devices)} devices...")
        enriched = await original_enrich(devices)
        print(f"After enrichment:")
        for d in enriched[:3]:  # Show first 3
            print(
                f"  {d['ip']}: services={d.get('services', [])}, vendor={d.get('vendor', 'N/A')}, os={d.get('os', 'N/A')}"
            )
        return enriched

    def traced_parse_xml(xml_file):
        print(f"\n=== Parsing Nmap XML: {xml_file} ===")
        devices = original_parse_xml(xml_file)
        print(f"Parsed {len(devices)} devices from XML")
        if devices:
            print(f"Sample device from XML:")
            print(json.dumps(devices[0], indent=2))
        return devices

    # Monkey patch for tracing
    scanner._run_masscan_deeper = traced_run_masscan
    scanner._enrich_deeper_scan_async = traced_enrich
    scanner._parse_nmap_xml = traced_parse_xml

    # Run a deeper scan on a small range
    print("Starting deeper scan on localhost range...")
    devices = await scanner.scan(target="127.0.0.1/32", scan_type="deeper")  # Just localhost

    print(f"\n=== FINAL RESULT ===")
    print(f"Total devices: {len(devices)}")
    for device in devices:
        print(f"\nDevice: {device['ip']}")
        print(f"  MAC: {device.get('mac', 'N/A')}")
        print(f"  Vendor: {device.get('vendor', 'N/A')}")
        print(f"  OS: {device.get('os', 'N/A')}")
        print(f"  Services: {device.get('services', [])}")


if __name__ == "__main__":
    asyncio.run(trace_deeper_scan())
