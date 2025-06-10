#!/usr/bin/env python3
"""
Quick script to view the demo network visualization with traffic flows
"""

import json
import shutil
from pathlib import Path
from datetime import datetime

# Copy demo data to proper locations
demo_dir = Path("output/demo")
scan_files = list(demo_dir.glob("scan_*.json"))
flow_files = list(demo_dir.glob("flows_*.json"))

if not scan_files or not flow_files:
    print("No demo data found. Run ./demo_large_network.py first.")
    exit(1)

# Get latest files
latest_scan = sorted(scan_files)[-1]
latest_flow = sorted(flow_files)[-1]

# Copy to scans directory
scan_dest = Path("output/scans") / latest_scan.name
shutil.copy(latest_scan, scan_dest)
print(f"Copied scan data to: {scan_dest}")

# Update the mapper to use the flow data
# We'll create a modified version of the scan that includes passive analysis results
with open(latest_scan) as f:
    devices = json.load(f)

with open(latest_flow) as f:
    flow_matrix = json.load(f)

# Mark some devices as discovered via passive analysis
stealth_count = 0
for device in devices:
    if device.get("stealth_device"):
        device["discovery_method"] = "passive"
        stealth_count += 1

# Save the enhanced scan data
enhanced_scan = Path("output/scans") / f"enhanced_{latest_scan.name}"
with open(enhanced_scan, 'w') as f:
    json.dump(devices, f, indent=2)

# Create a passive analysis results file
timestamp = latest_scan.stem.replace("scan_", "")
passive_results = {
    "devices_file": str(enhanced_scan),
    "flows_file": str(latest_flow),
    "flow_matrix": flow_matrix,
    "duration": 60,
    "service_usage": {}
}

# Calculate service usage from devices
for device in devices:
    for service in device.get("services", []):
        service_name = service.split(":")[0]
        if service_name not in passive_results["service_usage"]:
            passive_results["service_usage"][service_name] = []
        passive_results["service_usage"][service_name].append(device["ip"])

# Save passive results
passive_file = Path("output") / "passive_analysis" / f"passive_{timestamp}.json"
passive_file.parent.mkdir(exist_ok=True)
with open(passive_file, 'w') as f:
    json.dump(passive_results, f, indent=2)

print(f"\nDemo data prepared!")
print(f"Devices: {len(devices)} (including {stealth_count} stealth devices)")
print(f"Traffic flows: {sum(len(dests) for dests in flow_matrix.values())}")
print(f"\nNow run: python3 mapper.py")
print(f"Select option 6 (Generate Reports) and choose the latest scan")
print(f"\nThe visualization will include:")
print("- Network topology with 220+ devices")
print("- Traffic Flow Analysis with live connections") 
print("- Risk Propagation Modeling")
print("- Critical Assets dashboard")