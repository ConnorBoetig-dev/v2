#!/usr/bin/env python3
"""Test fixed visualization by generating a quick report"""

import json
from pathlib import Path
from datetime import datetime
from mapper import NetworkMapper

def test_fixed_visualization():
    """Generate a quick report to test the visualization fix"""
    
    # Load the latest demo data
    scan_files = sorted(Path("output/scans").glob("scan_*.json"), reverse=True)
    if not scan_files:
        print("No scan files found")
        return
        
    # Find a scan with a lot of devices (demo scan)
    demo_scan = None
    for scan_file in scan_files:
        with open(scan_file) as f:
            devices = json.load(f)
            if len(devices) > 100:  # Likely a demo scan
                demo_scan = scan_file
                print(f"Found demo scan: {scan_file.name} with {len(devices)} devices")
                break
    
    if not demo_scan:
        print("No demo scan found")
        return
    
    # Load demo flow matrix if available
    flow_matrix_file = Path("output/scans/demo_flow_matrix_20250610_034734.json")
    if flow_matrix_file.exists():
        with open(flow_matrix_file) as f:
            flow_matrix = json.load(f)
        print(f"Loaded flow matrix with {len(flow_matrix)} sources")
    else:
        print("No flow matrix found, will use topology-based connections")
        flow_matrix = None
    
    # Load devices
    with open(demo_scan) as f:
        devices = json.load(f)
    
    # Create mapper instance and set passive analysis results if we have flow matrix
    mapper = NetworkMapper()
    
    if flow_matrix:
        # Simulate having passive analysis results
        mapper.passive_analysis_results = {
            "flow_matrix": flow_matrix,
            "service_usage": {},
            "duration": 60
        }
    
    # Generate report with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"\nGenerating report with timestamp: {timestamp}")
    
    report_file, _ = mapper.generate_html_report(devices, timestamp)
    
    print(f"\nReport generated: {report_file}")
    print("\nTo view the fixed visualization:")
    print(f"1. Open: file://{report_file.absolute()}")
    print("2. Click on the 'Network Map' tab")
    print("3. You should now see connection lines between devices!")
    
    # Check the generated data
    report_file_str = str(report_file)
    network_map_file = Path(report_file_str.replace("report_", "network_map_"))
    
    if network_map_file.exists():
        print(f"\nAlso generated: {network_map_file}")

if __name__ == "__main__":
    test_fixed_visualization()