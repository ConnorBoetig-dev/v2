#!/usr/bin/env python3
"""
Full simulation demo showing all NetworkMapper features with realistic traffic data
This represents what you would see when scanning a real large network
"""

import json
from pathlib import Path
from datetime import datetime
from mapper import NetworkMapper
import random

def generate_realistic_flow_matrix(devices):
    """Generate realistic traffic flow patterns between devices"""
    flow_matrix = {}
    
    # Extract devices by type
    dns_servers = [d for d in devices if d.get('type') == 'dns_server']
    domain_controllers = [d for d in devices if d.get('type') == 'domain_controller']
    web_servers = [d for d in devices if d.get('type') == 'web_server']
    databases = [d for d in devices if d.get('type') == 'database']
    workstations = [d for d in devices if d.get('type') == 'workstation']
    
    # 1. All workstations query DNS servers
    for ws in workstations:
        if ws['ip'] not in flow_matrix:
            flow_matrix[ws['ip']] = {}
        
        # Distribute DNS queries across DNS servers
        for dns in dns_servers:
            packets = random.randint(50, 500)
            flow_matrix[ws['ip']][dns['ip']] = packets
    
    # 2. Workstations authenticate with domain controllers
    for ws in workstations:
        for dc in domain_controllers:
            if random.random() > 0.3:  # 70% of workstations
                packets = random.randint(50, 300)
                flow_matrix[ws['ip']][dc['ip']] = packets
    
    # 3. Workstations access web servers
    for ws in workstations:
        # Each workstation accesses 1-3 web servers
        accessed_servers = random.sample(web_servers, min(random.randint(1, 3), len(web_servers)))
        for web in accessed_servers:
            packets = random.randint(100, 1000)
            flow_matrix[ws['ip']][web['ip']] = packets
    
    # 4. Web servers query databases
    for web in web_servers:
        if web['ip'] not in flow_matrix:
            flow_matrix[web['ip']] = {}
        
        # Each web server connects to 1-3 databases
        connected_dbs = random.sample(databases, min(random.randint(1, 3), len(databases)))
        for db in connected_dbs:
            packets = random.randint(500, 5000)
            flow_matrix[web['ip']][db['ip']] = packets
    
    # 5. Add some inter-server communication
    all_servers = web_servers + databases
    for i, server1 in enumerate(all_servers):
        if server1['ip'] not in flow_matrix:
            flow_matrix[server1['ip']] = {}
        
        # Each server talks to 1-2 other servers
        for _ in range(random.randint(1, 2)):
            if len(all_servers) > 1:
                server2 = random.choice([s for s in all_servers if s != server1])
                packets = random.randint(50, 500)
                flow_matrix[server1['ip']][server2['ip']] = packets
    
    # 6. Add some stealth device traffic (devices not in active scan)
    stealth_ips = [
        "10.0.2.200",  # Rogue device
        "10.0.3.200",  # Unauthorized AP
    ]
    
    for stealth_ip in stealth_ips:
        flow_matrix[stealth_ip] = {}
        # Stealth devices communicate with a few workstations
        targets = random.sample(workstations, min(3, len(workstations)))
        for target in targets:
            flow_matrix[stealth_ip][target['ip']] = random.randint(10, 100)
    
    return flow_matrix

def generate_service_usage(devices, flow_matrix):
    """Generate service usage statistics from flow matrix"""
    service_usage = {
        'dns': [],
        'http': [],
        'https': [],
        'ldap': [],
        'ssh': [],
        'rdp': [],
        'smb': [],
        'database': []
    }
    
    # Analyze flow matrix to determine service usage
    for device in devices:
        ip = device['ip']
        services = device.get('services', [])
        
        # Check if device receives traffic for its services
        total_inbound = sum(
            flow_matrix.get(src, {}).get(ip, 0) 
            for src in flow_matrix
        )
        
        if total_inbound > 0:
            for service in services:
                if 'dns' in service.lower():
                    service_usage['dns'].append(ip)
                elif 'http:80' in service or 'http:8080' in service:
                    service_usage['http'].append(ip)
                elif 'https' in service:
                    service_usage['https'].append(ip)
                elif 'ldap' in service:
                    service_usage['ldap'].append(ip)
                elif 'ssh' in service:
                    service_usage['ssh'].append(ip)
                elif 'rdp' in service:
                    service_usage['rdp'].append(ip)
                elif 'smb' in service:
                    service_usage['smb'].append(ip)
                elif any(db in service for db in ['mysql', 'postgresql', 'mssql', 'oracle']):
                    service_usage['database'].append(ip)
    
    # Remove empty services
    service_usage = {k: v for k, v in service_usage.items() if v}
    
    return service_usage

def main():
    """Run full simulation demo"""
    print("NetworkMapper v2 - Full Simulation Demo")
    print("=" * 50)
    print("\nThis demo simulates what you would see when scanning a real enterprise network")
    print("with passive traffic analysis enabled.\n")
    
    # Load the latest demo scan
    scan_files = sorted(Path("output/scans").glob("scan_*.json"), reverse=True)
    demo_scan = None
    
    for scan_file in scan_files:
        with open(scan_file) as f:
            devices = json.load(f)
            if len(devices) > 30:  # Find a demo scan
                demo_scan = scan_file
                print(f"Found demo network: {scan_file.name}")
                print(f"Total devices: {len(devices)}")
                break
    
    if not demo_scan:
        print("Error: No demo scan found. Please run demo_large_network.py first.")
        return
    
    # Load devices
    with open(demo_scan) as f:
        devices = json.load(f)
    
    # Generate realistic traffic flow matrix
    print("\nGenerating realistic traffic patterns...")
    flow_matrix = generate_realistic_flow_matrix(devices)
    total_flows = sum(len(dests) for dests in flow_matrix.values())
    print(f"Generated {total_flows} traffic flows")
    
    # Add stealth devices to the device list (discovered via passive analysis)
    stealth_devices = [
        {
            "ip": "10.0.2.200",
            "hostname": "ROGUE-DEVICE",
            "mac": "AA:BB:CC:DD:EE:FF",
            "vendor": "Unknown",
            "type": "unknown",
            "services": [],
            "open_ports": [],
            "stealth_device": True,
            "discovery_method": "passive",
            "critical": False,
            "last_seen": datetime.now().isoformat()
        },
        {
            "ip": "10.0.3.200",
            "hostname": "UNAUTHORIZED-AP",
            "mac": "11:22:33:44:55:66",
            "vendor": "TP-Link",
            "type": "wireless_ap",
            "services": ["http:80"],
            "open_ports": [80],
            "stealth_device": True,
            "discovery_method": "passive",
            "critical": False,
            "last_seen": datetime.now().isoformat()
        }
    ]
    
    # Add stealth devices
    all_devices = devices + stealth_devices
    print(f"Added {len(stealth_devices)} stealth devices discovered via passive analysis")
    
    # Generate service usage
    service_usage = generate_service_usage(all_devices, flow_matrix)
    
    # Create mapper instance and simulate passive analysis results
    mapper = NetworkMapper()
    mapper.passive_analysis_results = {
        "flow_matrix": flow_matrix,
        "service_usage": service_usage,
        "duration": 60,
        "devices_file": "simulated_passive_devices.json",
        "flows_file": "simulated_traffic_flows.json"
    }
    
    # Simulate traffic analyzer stats
    mapper.traffic_analyzer.stats = {
        "packets_captured": sum(sum(dests.values()) for dests in flow_matrix.values()),
        "packets_processed": sum(sum(dests.values()) for dests in flow_matrix.values()),
        "flows_tracked": total_flows,
        "devices_discovered": len(stealth_devices),
        "duration": 60
    }
    
    # Generate all reports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"\nGenerating comprehensive reports with timestamp: {timestamp}")
    
    # Save the enhanced device list for report generation
    enhanced_scan_file = Path(f"output/scans/demo_enhanced_{timestamp}.json")
    with open(enhanced_scan_file, 'w') as f:
        json.dump(all_devices, f, indent=2)
    
    # Generate reports
    report_files = mapper.generate_html_report(all_devices, timestamp)
    
    print("\n" + "=" * 50)
    print("SIMULATION COMPLETE!")
    print("=" * 50)
    
    print("\nGenerated Reports:")
    print("1. Main Network Report (tables/statistics only)")
    print("2. Network Visualization (2D/3D interactive maps)")  
    print("3. Live Traffic Flow Analysis (with risk propagation)")
    
    print("\nKey Features Demonstrated:")
    print("✓ Device discovery and classification")
    print("✓ Stealth device detection via passive analysis")
    print("✓ Real-time traffic flow visualization")
    print("✓ Service usage statistics")
    print("✓ Interactive network topology")
    print("✓ Risk propagation modeling")
    print("✓ Critical asset identification")
    
    print("\nThis simulation shows what NetworkMapper would display when:")
    print("- Scanning a ~55 device enterprise network")
    print("- Running passive traffic analysis for 60 seconds")
    print("- Detecting rogue/unauthorized devices")
    print("- Mapping actual traffic patterns between systems")

if __name__ == "__main__":
    main()