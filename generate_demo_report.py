#!/usr/bin/env python3
"""
Generate reports directly from demo data with traffic flows
"""

import json
import webbrowser
from pathlib import Path
from datetime import datetime
from mapper import NetworkMapper

# Initialize mapper
mapper = NetworkMapper()

# Find latest demo data
demo_dir = Path("output/demo")
scan_files = sorted(demo_dir.glob("scan_*.json"))
flow_files = sorted(demo_dir.glob("flows_*.json"))

if not scan_files or not flow_files:
    print("No demo data found. Run ./demo_large_network.py first.")
    exit(1)

latest_scan = scan_files[-1]
latest_flow = flow_files[-1]

print(f"Loading demo data from: {latest_scan}")

# Load devices and flow matrix
with open(latest_scan) as f:
    devices = json.load(f)

with open(latest_flow) as f:
    flow_matrix = json.load(f)

# Apply annotations
devices = mapper.annotator.apply_annotations(devices)

# Simulate passive analysis results
mapper.passive_analysis_results = {
    "flow_matrix": flow_matrix,
    "service_usage": {},
    "duration": 60
}

# Calculate service usage
for device in devices:
    for service in device.get("services", []):
        service_name = service.split(":")[0]
        if service_name not in mapper.passive_analysis_results["service_usage"]:
            mapper.passive_analysis_results["service_usage"][service_name] = []
        mapper.passive_analysis_results["service_usage"][service_name].append(device["ip"])

# Get timestamp
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

print(f"Generating reports for {len(devices)} devices with {sum(len(dests) for dests in flow_matrix.values())} traffic flows...")

# Generate reports
try:
    report_file, comparison_file = mapper.generate_html_report(devices, timestamp)
    print(f"\n✓ Reports generated successfully!")
    print(f"\nOpening in browser...")
    
    # The reports should auto-open, but print the paths too
    print(f"\nGenerated files:")
    print(f"- Network Map: {report_file}")
    if mapper.passive_analysis_results:
        traffic_report = Path("output/reports") / f"traffic_flow_{timestamp}.html"
        if traffic_report.exists():
            print(f"- Traffic Flow Analysis: {traffic_report}")
    
except Exception as e:
    print(f"Error generating reports: {e}")
    import traceback
    traceback.print_exc()