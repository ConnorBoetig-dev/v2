#!/usr/bin/env python3
"""
Generate all three report types from the latest scan
This includes the traffic flow report even without passive analysis
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import random
import webbrowser
import time

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from mapper import NetworkMapper

def generate_simulated_traffic_flow_DISABLED(devices):
    """Generate realistic traffic flow data for visualization"""
    flow_matrix = {}
    
    # Create device groups
    routers = [d for d in devices if d.get('type') == 'router']
    servers = [d for d in devices if d.get('type') in ['server', 'web_server', 'database']]
    workstations = [d for d in devices if d.get('type') == 'workstation']
    
    # Ensure we have some devices to work with
    if not servers:
        # If no servers identified, use some unknown devices as servers
        servers = [d for d in devices if d.get('type') == 'unknown'][:5]
    
    if not workstations:
        # If no workstations, use remaining devices
        workstations = [d for d in devices if d not in servers and d not in routers][:10]
    
    # Generate traffic patterns
    # 1. Workstations to servers
    for ws in workstations[:20]:  # Limit to prevent too many connections
        if ws['ip'] not in flow_matrix:
            flow_matrix[ws['ip']] = {}
        
        # Each workstation connects to 1-3 servers
        if servers:
            num_servers = min(len(servers), random.randint(1, 3))
            for server in random.sample(servers, num_servers):
                flow_matrix[ws['ip']][server['ip']] = random.randint(100, 1000)
    
    # 2. Server to server communication
    if len(servers) > 1:
        for i, server1 in enumerate(servers[:10]):
            if server1['ip'] not in flow_matrix:
                flow_matrix[server1['ip']] = {}
            
            # Each server talks to 1-2 other servers
            other_servers = [s for s in servers if s != server1]
            if other_servers:
                for server2 in random.sample(other_servers, min(2, len(other_servers))):
                    flow_matrix[server1['ip']][server2['ip']] = random.randint(500, 2000)
    
    # 3. All devices to routers (gateway traffic)
    all_devices = (workstations[:20] + servers[:10]) if (workstations or servers) else devices[:20]
    for device in all_devices:
        if device['ip'] not in flow_matrix:
            flow_matrix[device['ip']] = {}
        
        if routers:
            router = random.choice(routers)
            flow_matrix[device['ip']][router['ip']] = random.randint(50, 500)
        else:
            # Create some random flows if no routers
            if len(devices) > 1:
                target = random.choice([d for d in devices if d['ip'] != device['ip']])
                flow_matrix[device['ip']][target['ip']] = random.randint(50, 500)
    
    return flow_matrix

def main():
    print("NetworkMapper v2 - Generate All Reports")
    print("=" * 40)
    
    # Find the latest scan
    scan_files = sorted(Path("output/scans").glob("scan_*.json"), reverse=True)
    if not scan_files:
        print("Error: No scan files found. Run a scan first.")
        return
    
    latest_scan = scan_files[0]
    print(f"Using scan: {latest_scan.name}")
    
    # Load devices
    with open(latest_scan) as f:
        devices = json.load(f)
    
    print(f"Found {len(devices)} devices")
    
    # Generate simulated traffic flow
    print("\nGenerating simulated traffic flow data...")
    flow_matrix = generate_simulated_traffic_flow(devices)
    total_flows = sum(len(flows) for flows in flow_matrix.values())
    print(f"Created {total_flows} traffic flows")
    
    # Get timestamp first
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create mapper instance
    mapper = NetworkMapper()
    
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
    
    # Create dummy scan metadata for the report template
    scan_metadata = {
        "scan_parameters": {
            "snmp_enabled": False,
            "vulnerability_scan": True,
            "passive_analysis": True
        },
        "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration": "2 minutes",
        "device_count": len(devices),
        "services_scanned": len(mapper.passive_analysis_results["service_usage"]),
        "vulnerabilities_detected": sum(1 for d in devices if d.get("vulnerability_count", 0) > 0),
        "target": "192.168.1.0/24",
        "subnets_discovered": ["192.168.1.0/24"]
    }
    
    # Save scan metadata
    metadata_file = mapper.output_path / "scans" / f"summary_{timestamp}.json"
    with open(metadata_file, 'w') as f:
        json.dump(scan_metadata, f, indent=2)
    
    print(f"\nGenerating all reports with timestamp: {timestamp}")
    
    # Generate all reports
    try:
        # First generate the standard reports
        report_file, comparison_file = mapper.generate_html_report(devices, timestamp)
        
        # Force open all reports including traffic flow
        reports = [
            (mapper.output_path / "reports" / f"network_map_{timestamp}.html", "Network Visualization"),
            (mapper.output_path / "reports" / f"report_{timestamp}.html", "Detailed Report"),
            (mapper.output_path / "reports" / f"traffic_flow_{timestamp}.html", "Traffic Flow Analysis")
        ]
        
        print("\n✓ Successfully generated:")
        for i, (path, name) in enumerate(reports, 1):
            if path.exists():
                print(f"  {i}. {name}")
                url = f"file://{path.absolute()}"
                webbrowser.open(url)
                time.sleep(0.5)  # Small delay between opening tabs
        
        print("\nAll reports should have opened in your browser.")
        print("\nTroubleshooting tips:")
        print("  - For 3D visualization: Check the 2D/3D toggle buttons in the Network Map")
        print("  - The 3D view uses WebGL - ensure your browser supports it")
        print("  - Traffic Flow report shows animated flow between devices")
        print("  - Try refreshing the page if visualization doesn't load immediately")
        
    except Exception as e:
        print(f"Error generating reports: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()