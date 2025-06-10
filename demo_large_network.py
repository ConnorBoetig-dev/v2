#!/usr/bin/env python3
"""
Demo script to showcase NetworkMapper v2 features on a large enterprise network
Generates realistic scan data with traffic flows for visualization testing
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

def _get_db_services(db_type):
    """Get services for database type"""
    services_map = {
        "mysql": ["mysql:3306", "ssh:22"],
        "postgresql": ["postgresql:5432", "ssh:22"],
        "mssql": ["mssql:1433", "rdp:3389"],
        "oracle": ["oracle:1521", "ssh:22"]
    }
    return services_map.get(db_type, ["ssh:22"])

def _generate_mac():
    """Generate random MAC address"""
    mac = [random.randint(0x00, 0xff) for _ in range(6)]
    mac[0] = mac[0] & 0xfc  # Clear multicast and local bits
    return ':'.join(f'{byte:02x}' for byte in mac)

def generate_large_network_demo():
    """Generate a large enterprise network with realistic traffic patterns"""
    
    # Network configuration - reduced to 3 subnets for better visualization
    SUBNETS = {
        "10.0.1.0/24": "Core Infrastructure & Servers",
        "10.0.2.0/24": "Workstations",
        "10.0.3.0/24": "DMZ & IoT"
    }
    
    devices = []
    device_map = {}  # For quick lookup
    
    # Core Infrastructure and Servers (10.0.1.0/24)
    core_devices = [
        # Core router
        {"ip": "10.0.1.1", "hostname": "CORE-RTR01", "type": "router", "critical": True,
         "services": ["ssh:22", "https:443", "snmp:161", "bgp:179"],
         "os": "Cisco IOS", "vendor": "Cisco", "is_gateway": True},
        
        # Core switches
        {"ip": "10.0.1.2", "hostname": "CORE-SW01", "type": "switch", "critical": True,
         "services": ["ssh:22", "https:443", "snmp:161"],
         "os": "Cisco NX-OS", "vendor": "Cisco"},
        {"ip": "10.0.1.3", "hostname": "CORE-SW02", "type": "switch", "critical": True,
         "services": ["ssh:22", "https:443", "snmp:161"],
         "os": "Cisco NX-OS", "vendor": "Cisco"},
        
        # DNS server
        {"ip": "10.0.1.10", "hostname": "DNS01", "type": "dns_server", "critical": True,
         "services": ["dns:53", "ssh:22", "snmp:161"],
         "os": "Windows Server 2019", "vendor": "Microsoft"},
        
        # Domain controller
        {"ip": "10.0.1.20", "hostname": "DC01", "type": "domain_controller", "critical": True,
         "services": ["ldap:389", "ldaps:636", "kerberos:88", "dns:53", "smb:445"],
         "os": "Windows Server 2019", "vendor": "Microsoft"},
    ]
    
    # Web servers (on same subnet as core)
    web_servers = []
    for i in range(1, 6):  # 5 web servers
        web_servers.append({
            "ip": f"10.0.1.{30+i}",
            "hostname": f"WEB{i:02d}",
            "type": "web_server",
            "services": ["http:80", "https:443", "ssh:22"],
            "os": "Ubuntu 20.04" if i % 2 == 0 else "CentOS 8",
            "vendor": "Various",
            "dependencies": ["DC01", "DNS01"]
        })
    
    # Database servers (on same subnet as core)
    db_servers = []
    for i in range(1, 4):  # 3 database servers
        db_type = ["mysql", "postgresql", "mssql"][i % 3]
        db_servers.append({
            "ip": f"10.0.1.{40+i}",
            "hostname": f"DB{i:02d}",
            "type": "database",
            "services": _get_db_services(db_type),
            "os": "Windows Server 2019" if "mssql" in db_type else "Red Hat Enterprise Linux 8",
            "vendor": "Various",
            "critical": True,
            "dependencies": ["DC01", "DNS01"]
        })
    
    # Workstations (10.0.2.0/24)
    workstations = []
    for i in range(1, 21):  # 20 workstations
        workstations.append({
            "ip": f"10.0.2.{10+i}",
            "hostname": f"WS{i:04d}",
            "type": "workstation",
            "services": ["rdp:3389", "smb:445"] if i % 5 == 0 else [],
            "os": "Windows 10" if i % 10 != 0 else "Windows 11",
            "vendor": "Dell" if i % 2 == 0 else "HP",
            "dependencies": ["DC01", "DNS01"]
        })
    
    # IoT & Building Systems (10.0.3.0/24)
    iot_devices = []
    # Security cameras
    for i in range(1, 6):
        iot_devices.append({
            "ip": f"10.0.3.{20+i}",
            "hostname": f"CAM{i:02d}",
            "type": "iot",
            "services": ["rtsp:554", "http:80"],
            "os": "Embedded Linux",
            "vendor": "Hikvision"
        })
    
    # HVAC controllers
    for i in range(1, 3):
        iot_devices.append({
            "ip": f"10.0.3.{30+i}",
            "hostname": f"HVAC{i:02d}",
            "type": "plc",
            "services": ["modbus:502", "http:80"],
            "os": "Proprietary",
            "vendor": "Siemens",
            "critical": True
        })
    
    # DMZ (10.0.3.0/24)
    dmz_devices = [
        {"ip": "10.0.3.10", "hostname": "FW-DMZ01", "type": "firewall", "critical": True,
         "services": ["https:443", "ssh:22", "snmp:161"],
         "os": "pfSense", "vendor": "Netgate"},
        {"ip": "10.0.3.11", "hostname": "PROXY01", "type": "proxy", 
         "services": ["http:3128", "https:8443", "ssh:22"],
         "os": "Ubuntu 20.04", "vendor": "Canonical"},
        {"ip": "10.0.3.12", "hostname": "MAIL01", "type": "mail_server",
         "services": ["smtp:25", "smtp:587", "imap:143", "imaps:993", "https:443"],
         "os": "Exchange 2019", "vendor": "Microsoft", "critical": True},
    ]
    
    # Combine all devices
    devices.extend(core_devices)
    devices.extend(web_servers)
    devices.extend(db_servers)
    devices.extend(workstations)
    devices.extend(iot_devices)
    devices.extend(dmz_devices)
    
    # Add common fields to all devices
    for device in devices:
        # MAC addresses
        device["mac"] = _generate_mac()
        
        # Open ports (from services)
        device["open_ports"] = [int(s.split(":")[1]) for s in device.get("services", [])]
        
        # Last seen
        device["last_seen"] = datetime.now().isoformat()
        
        # Uptime
        if device.get("critical") or device.get("type") in ["router", "switch", "firewall"]:
            device["uptime_days"] = random.randint(180, 500)
        else:
            device["uptime_days"] = random.randint(1, 180)
        
        # Notes
        if device.get("critical"):
            device["notes"] = "Critical infrastructure - requires change approval"
        
        # Build device map
        device_map[device["ip"]] = device
    
    # Generate realistic traffic flows
    flow_matrix = {}
    
    # All workstations talk to domain controllers
    for ws in workstations:
        if ws["ip"] not in flow_matrix:
            flow_matrix[ws["ip"]] = {}
        
        # Authentication traffic
        flow_matrix[ws["ip"]]["10.0.1.20"] = random.randint(100, 500)  # DC01
        flow_matrix[ws["ip"]]["10.0.1.21"] = random.randint(50, 200)   # DC02
        
        # DNS queries
        flow_matrix[ws["ip"]]["10.0.1.10"] = random.randint(200, 1000) # DNS01
        
        # Web traffic to servers
        for web in random.sample(web_servers, min(5, len(web_servers))):
            flow_matrix[ws["ip"]][web["ip"]] = random.randint(50, 500)
    
    # Web servers talk to databases
    for web in web_servers:
        if web["ip"] not in flow_matrix:
            flow_matrix[web["ip"]] = {}
        
        # Connect to 1-3 database servers
        for db in random.sample(db_servers, random.randint(1, 3)):
            flow_matrix[web["ip"]][db["ip"]] = random.randint(500, 5000)
    
    # IoT devices generate traffic
    for iot in iot_devices:
        if iot["ip"] not in flow_matrix:
            flow_matrix[iot["ip"]] = {}
        
        # IoT devices send data to proxy server
        flow_matrix[iot["ip"]]["10.0.3.11"] = random.randint(100, 1000)
    
    # Add backup server
    backup_server = "10.0.1.50"
    devices.append({
        "ip": backup_server,
        "hostname": "BACKUP01",
        "type": "server",
        "services": ["ssh:22", "https:443", "nfs:2049"],
        "os": "Ubuntu 20.04",
        "vendor": "Dell",
        "critical": True,
        "mac": _generate_mac(),
        "open_ports": [22, 443, 2049],
        "last_seen": datetime.now().isoformat(),
        "uptime_days": 365
    })
    
    # All servers backup to backup server
    for server in web_servers + db_servers:
        if server["ip"] not in flow_matrix:
            flow_matrix[server["ip"]] = {}
        flow_matrix[server["ip"]][backup_server] = random.randint(1000, 10000)
    
    # Add stealth devices (devices only seen in traffic, not in active scan)
    stealth_devices = [
        {"ip": "10.0.2.100", "hostname": "UNKNOWN-01", "type": "unknown",
         "mac": _generate_mac(), "stealth_device": True,
         "discovery_method": "passive", "last_seen": datetime.now().isoformat()},
        {"ip": "10.0.2.101", "hostname": "UNKNOWN-02", "type": "unknown", 
         "mac": _generate_mac(), "stealth_device": True,
         "discovery_method": "passive", "last_seen": datetime.now().isoformat()},
    ]
    
    # Stealth devices generate suspicious traffic
    for stealth in stealth_devices:
        flow_matrix[stealth["ip"]] = {}
        # Scanning behavior - touches many hosts
        for target in random.sample(devices, min(10, len(devices))):
            flow_matrix[stealth["ip"]][target["ip"]] = random.randint(1, 50)
    
    devices.extend(stealth_devices)
    
    # Calculate dependent counts
    dependent_counts = {}
    for src, destinations in flow_matrix.items():
        for dst, packets in destinations.items():
            if packets > 100:  # Significant traffic
                dependent_counts[dst] = dependent_counts.get(dst, 0) + 1
    
    # Update devices with dependent counts
    for device in devices:
        device["dependent_count"] = dependent_counts.get(device["ip"], 0)
    
    # Add some vulnerabilities for demo
    vuln_devices = random.sample([d for d in devices if d.get("type") != "unknown"], min(10, len([d for d in devices if d.get("type") != "unknown"])))
    for device in vuln_devices:
        device["vulnerability_count"] = random.randint(1, 10)
        device["critical_vulns"] = random.randint(0, 2)
        device["high_vulns"] = random.randint(0, 3)
        device["vulnerabilities"] = []
        
        if device["critical_vulns"] > 0:
            device["vulnerabilities"].append({
                "cve_id": "CVE-2024-0001",
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "description": "Remote code execution vulnerability"
            })
        
        if device["high_vulns"] > 0:
            device["vulnerabilities"].append({
                "cve_id": "CVE-2024-0002", 
                "cvss_score": 7.5,
                "severity": "HIGH",
                "description": "Authentication bypass vulnerability"
            })
    
    return devices, flow_matrix

def save_demo_data():
    """Generate and save demo data"""
    print("Generating large enterprise network demo data...")
    
    devices, flow_matrix = generate_large_network_demo()
    
    # Create output directory
    output_dir = Path("output/demo")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save scan data
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_file = output_dir / f"scan_{timestamp}.json"
    
    with open(scan_file, 'w') as f:
        json.dump(devices, f, indent=2)
    
    # Save flow matrix
    flow_file = output_dir / f"flows_{timestamp}.json"
    with open(flow_file, 'w') as f:
        json.dump(flow_matrix, f, indent=2)
    
    # Generate summary
    summary = {
        "total_devices": len(devices),
        "device_types": {},
        "critical_devices": len([d for d in devices if d.get("critical")]),
        "vulnerable_devices": len([d for d in devices if d.get("vulnerability_count", 0) > 0]),
        "stealth_devices": len([d for d in devices if d.get("stealth_device")]),
        "total_flows": sum(len(dests) for dests in flow_matrix.values()),
        "high_dependency_devices": len([d for d in devices if d.get("dependent_count", 0) > 20])
    }
    
    # Count device types
    for device in devices:
        device_type = device.get("type", "unknown")
        summary["device_types"][device_type] = summary["device_types"].get(device_type, 0) + 1
    
    print(f"\nDemo data generated successfully!")
    print(f"Total devices: {summary['total_devices']}")
    print(f"Critical devices: {summary['critical_devices']}")
    print(f"Stealth devices: {summary['stealth_devices']}")
    print(f"Total traffic flows: {summary['total_flows']}")
    print(f"\nFiles saved to: {output_dir}")
    print(f"- Scan data: {scan_file}")
    print(f"- Flow matrix: {flow_file}")
    
    # Save summary
    summary_file = output_dir / "summary.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    return str(scan_file), str(flow_file)

if __name__ == "__main__":
    scan_file, flow_file = save_demo_data()
    
    print("\n" + "="*60)
    print("INSTRUCTIONS TO VIEW THE DEMO:")
    print("="*60)
    print("\n1. Copy the scan file to the scans directory:")
    print(f"   cp {scan_file} output/scans/")
    print("\n2. Run NetworkMapper and select 'Generate Reports'")
    print("   python3 mapper.py")
    print("\n3. The visualization will show:")
    print("   - ~55 devices across 3 subnets")
    print("   - Live traffic flows between systems")
    print("   - Critical infrastructure highlighted")
    print("   - Stealth devices detected via passive analysis")
    print("   - Risk propagation modeling on traffic flow map")
    print("\n4. In the Traffic Flow report, click 'Risk Analysis Mode' to:")
    print("   - Simulate device failures")
    print("   - See cascading impacts")
    print("   - Get mitigation suggestions")