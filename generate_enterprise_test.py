#!/usr/bin/env python3
"""
Generate a comprehensive enterprise network test dataset with critical assets
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

# Enterprise device templates with realistic configurations
ENTERPRISE_DEVICES = {
    "domain_controllers": [
        {
            "type": "windows_server",
            "subtype": "domain_controller",
            "services": ["ldap:389", "ldaps:636", "kerberos:88", "dns:53", "smb:445", "rpc:135"],
            "os": "Windows Server 2019",
            "critical": True,
            "always_on": True,
            "uptime_days": 180,
            "dependencies": ["dns_servers", "ntp_servers"],
            "dependent_count": 50,  # Many devices depend on AD
        }
    ],
    "dns_servers": [
        {
            "type": "linux_server",
            "subtype": "dns_server",
            "services": ["dns:53", "ssh:22", "snmp:161"],
            "os": "Ubuntu 20.04 LTS",
            "critical": True,
            "always_on": True,
            "uptime_days": 365,
            "dependencies": [],
            "dependent_count": 100,  # Everything depends on DNS
        }
    ],
    "database_servers": [
        {
            "type": "database",
            "subtype": "postgresql",
            "services": ["postgresql:5432", "ssh:22", "snmp:161"],
            "os": "Ubuntu 20.04 LTS",
            "critical": True,
            "always_on": True,
            "uptime_days": 90,
            "dependencies": ["dns_servers"],
            "dependent_count": 15,
        },
        {
            "type": "database",
            "subtype": "mysql",
            "services": ["mysql:3306", "ssh:22", "snmp:161"],
            "os": "CentOS 7",
            "critical": True,
            "always_on": True,
            "uptime_days": 120,
            "dependencies": ["dns_servers"],
            "dependent_count": 20,
        },
        {
            "type": "database",
            "subtype": "oracle",
            "services": ["oracle:1521", "ssh:22", "snmp:161"],
            "os": "Oracle Linux 8",
            "critical": True,
            "always_on": True,
            "uptime_days": 200,
            "dependencies": ["dns_servers", "ntp_servers"],
            "dependent_count": 25,
        }
    ],
    "web_servers": [
        {
            "type": "web_server",
            "subtype": "nginx",
            "services": ["https:443", "http:80", "ssh:22", "snmp:161"],
            "os": "Ubuntu 20.04 LTS",
            "critical": False,
            "always_on": True,
            "uptime_days": 30,
            "dependencies": ["dns_servers", "database_servers"],
            "dependent_count": 0,
        }
    ],
    "gateway_routers": [
        {
            "type": "router",
            "subtype": "gateway",
            "services": ["ssh:22", "https:443", "snmp:161", "bgp:179"],
            "os": "Cisco IOS 15.6",
            "critical": True,
            "always_on": True,
            "uptime_days": 400,
            "is_gateway": True,
            "dependencies": [],
            "dependent_count": 150,  # Everything routes through gateway
        }
    ],
    "core_switches": [
        {
            "type": "switch",
            "subtype": "core_switch",
            "services": ["ssh:22", "https:443", "snmp:161"],
            "os": "Cisco NX-OS",
            "critical": True,
            "always_on": True,
            "uptime_days": 300,
            "dependencies": ["gateway_routers"],
            "dependent_count": 40,
        }
    ],
    "ups_systems": [
        {
            "type": "iot",
            "subtype": "ups",
            "services": ["snmp:161", "http:80"],
            "os": "APC UPS OS",
            "critical": True,
            "always_on": True,
            "uptime_days": 500,
            "snmp_enabled": True,
            "dependencies": [],
            "dependent_count": 30,  # Powers critical infrastructure
        }
    ],
    "plc_systems": [
        {
            "type": "iot",
            "subtype": "plc",
            "services": ["modbus:502", "http:80", "snmp:161"],
            "os": "Siemens SIMATIC",
            "critical": True,
            "always_on": True,
            "uptime_days": 600,
            "snmp_enabled": True,
            "dependencies": ["gateway_routers"],
            "dependent_count": 5,
        }
    ],
    "scada_systems": [
        {
            "type": "iot",
            "subtype": "scada",
            "services": ["dnp3:20000", "iec104:2404", "https:443", "snmp:161"],
            "os": "Wonderware InTouch",
            "critical": True,
            "always_on": True,
            "uptime_days": 365,
            "snmp_enabled": True,
            "dependencies": ["plc_systems", "database_servers"],
            "dependent_count": 10,
        }
    ],
    "ntp_servers": [
        {
            "type": "linux_server",
            "subtype": "ntp_server",
            "services": ["ntp:123", "ssh:22", "snmp:161"],
            "os": "Ubuntu 20.04 LTS",
            "critical": True,
            "always_on": True,
            "uptime_days": 400,
            "dependencies": ["dns_servers"],
            "dependent_count": 80,  # Time sync is critical
        }
    ],
    "backup_servers": [
        {
            "type": "windows_server",
            "subtype": "backup_server",
            "services": ["veeam:9392", "smb:445", "https:443", "snmp:161"],
            "os": "Windows Server 2019",
            "critical": True,
            "always_on": True,
            "uptime_days": 150,
            "dependencies": ["domain_controllers", "dns_servers"],
            "dependent_count": 40,
        }
    ],
    "monitoring_servers": [
        {
            "type": "linux_server",
            "subtype": "monitoring",
            "services": ["nagios:443", "ssh:22", "snmp:161", "nrpe:5666"],
            "os": "CentOS 8",
            "critical": True,
            "always_on": True,
            "uptime_days": 200,
            "dependencies": ["dns_servers", "database_servers"],
            "dependent_count": 0,  # Monitoring doesn't have dependents
        }
    ],
    "virtualization_hosts": [
        {
            "type": "linux_server",
            "subtype": "vmware_esxi",
            "services": ["vmware:443", "ssh:22", "snmp:161"],
            "os": "VMware ESXi 7.0",
            "critical": True,
            "always_on": True,
            "uptime_days": 250,
            "dependencies": ["dns_servers", "ntp_servers"],
            "dependent_count": 30,  # Hosts many VMs
        }
    ],
    "storage_systems": [
        {
            "type": "linux_server",
            "subtype": "nas",
            "services": ["nfs:2049", "smb:445", "https:443", "snmp:161"],
            "os": "TrueNAS",
            "critical": True,
            "always_on": True,
            "uptime_days": 300,
            "dependencies": ["domain_controllers", "dns_servers"],
            "dependent_count": 25,
        }
    ],
    "voip_servers": [
        {
            "type": "linux_server",
            "subtype": "voip",
            "services": ["sip:5060", "rtp:10000-20000", "https:443", "snmp:161"],
            "os": "Asterisk PBX",
            "critical": False,
            "always_on": True,
            "uptime_days": 60,
            "dependencies": ["dns_servers"],
            "dependent_count": 50,  # All phones depend on it
        }
    ],
    "security_appliances": [
        {
            "type": "router",
            "subtype": "firewall",
            "services": ["https:443", "ssh:22", "snmp:161"],
            "os": "pfSense",
            "critical": True,
            "always_on": True,
            "uptime_days": 180,
            "dependencies": ["gateway_routers"],
            "dependent_count": 100,
        }
    ],
    "workstations": [
        {
            "type": "workstation",
            "subtype": "windows_workstation",
            "services": ["rdp:3389", "smb:445"],
            "os": "Windows 10 Pro",
            "critical": False,
            "always_on": False,
            "uptime_days": 7,
            "dependencies": ["domain_controllers", "dns_servers"],
            "dependent_count": 0,
        },
        {
            "type": "workstation",
            "subtype": "linux_workstation",
            "services": ["ssh:22", "vnc:5900"],
            "os": "Ubuntu 22.04",
            "critical": False,
            "always_on": False,
            "uptime_days": 14,
            "dependencies": ["dns_servers"],
            "dependent_count": 0,
        }
    ],
    "printers": [
        {
            "type": "printer",
            "subtype": "network_printer",
            "services": ["ipp:631", "http:80", "snmp:161"],
            "os": "HP Embedded",
            "critical": False,
            "always_on": True,
            "uptime_days": 90,
            "snmp_enabled": True,
            "dependencies": ["dns_servers"],
            "dependent_count": 0,
        }
    ],
    "iot_devices": [
        {
            "type": "iot",
            "subtype": "hvac_controller",
            "services": ["http:80", "modbus:502", "snmp:161"],
            "os": "Embedded Linux",
            "critical": False,
            "always_on": True,
            "uptime_days": 365,
            "snmp_enabled": True,
            "dependencies": ["gateway_routers"],
            "dependent_count": 0,
        },
        {
            "type": "iot",
            "subtype": "security_camera",
            "services": ["rtsp:554", "http:80"],
            "os": "Camera OS",
            "critical": False,
            "always_on": True,
            "uptime_days": 180,
            "dependencies": ["gateway_routers"],
            "dependent_count": 0,
        }
    ]
}

# Asset criticality rules
CRITICALITY_RULES = {
    "always_critical": ["domain_controller", "dns_server", "gateway", "ups", "plc", "scada", "firewall"],
    "dependency_threshold": 10,  # Devices with > 10 dependents are critical
    "uptime_threshold": 180,     # Devices with > 180 days uptime are likely critical
    "service_critical": ["ldap", "dns", "ntp", "postgresql", "mysql", "oracle"]
}

class EnterpriseNetworkGenerator:
    def __init__(self):
        self.devices = []
        self.device_map = {}
        self.dependency_graph = {}
        self.subnet_assignments = {
            "10.0.1.0/24": "management",     # Critical infrastructure
            "10.0.2.0/24": "servers",        # Application servers
            "10.0.3.0/24": "databases",      # Database servers
            "10.0.4.0/24": "dmz",            # Web servers
            "10.0.5.0/24": "industrial",     # SCADA/PLC
            "10.0.6.0/24": "users",          # Workstations
            "10.0.7.0/24": "voip",           # VoIP systems
            "10.0.8.0/24": "iot",            # IoT devices
        }
        self.ip_counter = {subnet: 10 for subnet in self.subnet_assignments}
        
    def get_next_ip(self, device_type: str) -> str:
        """Assign IP based on device type"""
        subnet_mapping = {
            "domain_controller": "10.0.1.0/24",
            "dns_server": "10.0.1.0/24",
            "gateway": "10.0.1.0/24",
            "firewall": "10.0.1.0/24",
            "core_switch": "10.0.1.0/24",
            "ntp_server": "10.0.1.0/24",
            "monitoring": "10.0.1.0/24",
            "backup_server": "10.0.1.0/24",
            "vmware_esxi": "10.0.2.0/24",
            "nas": "10.0.2.0/24",
            "nginx": "10.0.4.0/24",
            "postgresql": "10.0.3.0/24",
            "mysql": "10.0.3.0/24",
            "oracle": "10.0.3.0/24",
            "plc": "10.0.5.0/24",
            "scada": "10.0.5.0/24",
            "ups": "10.0.5.0/24",
            "windows_workstation": "10.0.6.0/24",
            "linux_workstation": "10.0.6.0/24",
            "voip": "10.0.7.0/24",
            "hvac_controller": "10.0.8.0/24",
            "security_camera": "10.0.8.0/24",
            "network_printer": "10.0.8.0/24",
        }
        
        subnet = subnet_mapping.get(device_type, "10.0.8.0/24")
        base = subnet.split('/')[0].rsplit('.', 1)[0]
        ip = f"{base}.{self.ip_counter[subnet]}"
        self.ip_counter[subnet] += 1
        return ip
    
    def generate_hostname(self, device_type: str, index: int) -> str:
        """Generate realistic hostname"""
        prefix_map = {
            "domain_controller": "DC",
            "dns_server": "DNS",
            "gateway": "GW",
            "firewall": "FW",
            "core_switch": "CORE-SW",
            "ntp_server": "NTP",
            "monitoring": "MON",
            "backup_server": "BACKUP",
            "vmware_esxi": "ESX",
            "nas": "NAS",
            "nginx": "WEB",
            "postgresql": "PGDB",
            "mysql": "MYDB",
            "oracle": "ORCL",
            "plc": "PLC",
            "scada": "SCADA",
            "ups": "UPS",
            "windows_workstation": "WIN",
            "linux_workstation": "LNX",
            "voip": "VOIP",
            "hvac_controller": "HVAC",
            "security_camera": "CAM",
            "network_printer": "PRN",
        }
        
        prefix = prefix_map.get(device_type, "DEV")
        return f"{prefix}{index:02d}"
    
    def calculate_criticality(self, device_template: Dict) -> bool:
        """Determine if device should be marked as critical"""
        # Already marked critical in template
        if device_template.get("critical", False):
            return True
            
        # Check subtype
        if device_template.get("subtype") in CRITICALITY_RULES["always_critical"]:
            return True
            
        # Check dependency count
        if device_template.get("dependent_count", 0) > CRITICALITY_RULES["dependency_threshold"]:
            return True
            
        # Check uptime
        if device_template.get("uptime_days", 0) > CRITICALITY_RULES["uptime_threshold"]:
            return True
            
        # Check critical services
        services = device_template.get("services", [])
        for service in services:
            service_name = service.split(':')[0]
            if service_name in CRITICALITY_RULES["service_critical"]:
                return True
                
        return False
    
    def add_tags(self, device: Dict) -> List[str]:
        """Add automatic tags based on device characteristics"""
        tags = []
        
        # Asset type tags
        if device.get("subtype"):
            tags.append(f"asset:{device['subtype']}")
            
        # Criticality tags
        if device.get("critical"):
            tags.append("critical")
            
        # Dependency tags
        dep_count = device.get("dependent_count", 0)
        if dep_count > 50:
            tags.append("high_dependency")
        elif dep_count > 20:
            tags.append("medium_dependency")
        elif dep_count > 0:
            tags.append("has_dependents")
            
        # Always-on tags
        if device.get("always_on"):
            tags.append("always_on")
            
        # Long uptime tags
        uptime = device.get("uptime_days", 0)
        if uptime > 365:
            tags.append("long_uptime")
        elif uptime > 180:
            tags.append("stable_uptime")
            
        # SNMP tags
        if device.get("snmp_enabled"):
            tags.append("snmp_managed")
            
        # Service-specific tags
        services = device.get("services", [])
        service_names = [s.split(':')[0] for s in services]
        
        if "ldap" in service_names or "ldaps" in service_names:
            tags.append("authentication")
        if "dns" in service_names:
            tags.append("name_resolution")
        if "ntp" in service_names:
            tags.append("time_sync")
        if any(db in service_names for db in ["postgresql", "mysql", "oracle"]):
            tags.append("database")
        if "modbus" in service_names or "dnp3" in service_names:
            tags.append("industrial_protocol")
            
        # Gateway tags
        if device.get("is_gateway"):
            tags.append("default_gateway")
            
        # Subnet-based tags
        ip = device.get("ip", "")
        for subnet, zone in self.subnet_assignments.items():
            if ip.startswith(subnet.split('/')[0].rsplit('.', 1)[0]):
                tags.append(f"zone:{zone}")
                break
                
        return tags
    
    def generate_devices(self) -> List[Dict]:
        """Generate comprehensive device list"""
        device_id = 1
        
        # Generate devices by category
        for category, templates in ENTERPRISE_DEVICES.items():
            # Determine count based on category
            count_map = {
                "domain_controllers": 2,
                "dns_servers": 2,
                "database_servers": len(templates),  # One of each type
                "web_servers": 5,
                "gateway_routers": 2,
                "core_switches": 4,
                "ups_systems": 3,
                "plc_systems": 5,
                "scada_systems": 2,
                "ntp_servers": 2,
                "backup_servers": 2,
                "monitoring_servers": 2,
                "virtualization_hosts": 4,
                "storage_systems": 3,
                "voip_servers": 1,
                "security_appliances": 2,
                "workstations": 50,
                "printers": 10,
                "iot_devices": 20,
            }
            
            count = count_map.get(category, 1)
            
            for i in range(count):
                # Select template (cycle through if multiple)
                template = templates[i % len(templates)]
                
                # Create device
                subtype = template.get("subtype", "generic")
                ip = self.get_next_ip(subtype)
                hostname = self.generate_hostname(subtype, i + 1)
                
                # Calculate uptime with variation
                base_uptime = template.get("uptime_days", 30)
                uptime_variation = random.randint(-5, 5)
                uptime = max(1, base_uptime + uptime_variation)
                last_seen = datetime.now() - timedelta(days=random.uniform(0, 0.5))
                
                # Parse ports, handling ranges
                open_ports = []
                for service in template.get("services", []):
                    if ':' in service:
                        port_str = service.split(':')[1]
                        if '-' in port_str:  # Handle port ranges
                            # Just use the first port of the range
                            port = int(port_str.split('-')[0])
                        else:
                            try:
                                port = int(port_str)
                            except ValueError:
                                continue
                        open_ports.append(port)
                
                device = {
                    "id": device_id,
                    "ip": ip,
                    "hostname": hostname,
                    "mac": self.generate_mac(),
                    "type": template["type"],
                    "subtype": subtype,
                    "vendor": self.get_vendor(template),
                    "os": template.get("os", "Unknown"),
                    "services": template.get("services", []),
                    "open_ports": open_ports,
                    "uptime_days": uptime,
                    "last_seen": last_seen.isoformat(),
                    "always_on": template.get("always_on", False),
                    "dependent_count": template.get("dependent_count", 0),
                    "is_gateway": template.get("is_gateway", False),
                    "snmp_enabled": template.get("snmp_enabled", False),
                }
                
                # Calculate criticality
                device["critical"] = self.calculate_criticality(template)
                
                # Add tags
                device["tags"] = self.add_tags(device)
                
                # Add to collections
                self.devices.append(device)
                self.device_map[hostname] = device
                device_id += 1
                
        # Build dependency relationships
        self.build_dependencies()
        
        return self.devices
    
    def generate_mac(self) -> str:
        """Generate realistic MAC address"""
        # Common vendor OUIs
        vendor_ouis = [
            "00:50:56",  # VMware
            "00:0C:29",  # VMware
            "00:1B:21",  # Intel
            "00:15:5D",  # Hyper-V
            "B8:27:EB",  # Raspberry Pi
            "00:19:99",  # Fujitsu
            "00:1C:C0",  # Intel
            "00:24:E8",  # Dell
            "00:26:55",  # HP
        ]
        
        oui = random.choice(vendor_ouis)
        nic = ":".join([f"{random.randint(0, 255):02x}" for _ in range(3)])
        return f"{oui}:{nic}".upper()
    
    def get_vendor(self, template: Dict) -> str:
        """Get vendor based on device type"""
        vendor_map = {
            "gateway": "Cisco Systems",
            "core_switch": "Cisco Systems",
            "firewall": "Netgate",
            "domain_controller": "Microsoft",
            "windows_server": "Microsoft",
            "vmware_esxi": "VMware",
            "linux_server": "Dell Inc.",
            "plc": "Siemens",
            "scada": "Wonderware",
            "ups": "APC",
            "network_printer": "HP",
            "security_camera": "Hikvision",
        }
        
        return vendor_map.get(template.get("subtype", ""), "Generic Vendor")
    
    def build_dependencies(self):
        """Build dependency graph based on device relationships"""
        # Clear existing
        self.dependency_graph = {}
        
        # Build graph
        for device in self.devices:
            device_id = device["hostname"]
            self.dependency_graph[device_id] = {
                "depends_on": [],
                "dependents": []
            }
        
        # Establish dependencies based on rules
        for device in self.devices:
            hostname = device["hostname"]
            
            # DNS dependencies
            if "dns_server" not in device.get("subtype", ""):
                dns_servers = [d for d in self.devices if d.get("subtype") == "dns_server"]
                for dns in dns_servers[:2]:  # Depend on up to 2 DNS servers
                    self.add_dependency(hostname, dns["hostname"])
            
            # Domain controller dependencies
            if device.get("os", "").startswith("Windows") and "domain_controller" not in device.get("subtype", ""):
                dcs = [d for d in self.devices if d.get("subtype") == "domain_controller"]
                for dc in dcs[:1]:  # Depend on primary DC
                    self.add_dependency(hostname, dc["hostname"])
            
            # Gateway dependencies
            if device.get("subtype") not in ["gateway", "dns_server"]:
                gateways = [d for d in self.devices if d.get("is_gateway", False)]
                for gw in gateways[:1]:  # Depend on primary gateway
                    self.add_dependency(hostname, gw["hostname"])
            
            # Database dependencies for web servers
            if device.get("subtype") == "nginx":
                databases = [d for d in self.devices if "database" in d.get("type", "")]
                if databases:
                    db = random.choice(databases)
                    self.add_dependency(hostname, db["hostname"])
            
            # SCADA depends on PLCs
            if device.get("subtype") == "scada":
                plcs = [d for d in self.devices if d.get("subtype") == "plc"]
                for plc in plcs[:3]:  # SCADA monitors multiple PLCs
                    self.add_dependency(hostname, plc["hostname"])
            
            # Everything in critical zones depends on UPS
            if device.get("tags") and "zone:management" in device["tags"]:
                ups_systems = [d for d in self.devices if d.get("subtype") == "ups"]
                for ups in ups_systems[:1]:
                    self.add_dependency(hostname, ups["hostname"])
        
        # Update dependent counts
        for device in self.devices:
            hostname = device["hostname"]
            device["dependent_count"] = len(self.dependency_graph[hostname]["dependents"])
            device["dependencies"] = self.dependency_graph[hostname]["depends_on"]
    
    def add_dependency(self, dependent: str, dependency: str):
        """Add dependency relationship"""
        if dependent != dependency:  # No self-dependencies
            if dependency not in self.dependency_graph[dependent]["depends_on"]:
                self.dependency_graph[dependent]["depends_on"].append(dependency)
            if dependent not in self.dependency_graph[dependency]["dependents"]:
                self.dependency_graph[dependency]["dependents"].append(dependent)
    
    def generate_traffic_flows(self) -> Dict:
        """Generate realistic traffic flow matrix"""
        flow_matrix = {}
        
        for device in self.devices:
            src_ip = device["ip"]
            flow_matrix[src_ip] = {}
            
            # Generate flows based on dependencies
            for dep_hostname in device.get("dependencies", []):
                dep_device = self.device_map.get(dep_hostname)
                if dep_device:
                    dst_ip = dep_device["ip"]
                    # Higher traffic for critical dependencies
                    base_packets = 1000 if dep_device.get("critical") else 100
                    flow_matrix[src_ip][dst_ip] = random.randint(base_packets, base_packets * 10)
            
            # Add some random flows for realism
            num_random_flows = random.randint(0, 5)
            for _ in range(num_random_flows):
                target = random.choice(self.devices)
                if target["ip"] != src_ip:
                    flow_matrix[src_ip][target["ip"]] = random.randint(10, 500)
        
        return flow_matrix
    
    def generate_test_data(self):
        """Generate complete test dataset"""
        print("Generating enterprise network test data...")
        
        # Generate devices
        devices = self.generate_devices()
        print(f"Generated {len(devices)} devices")
        
        # Generate traffic flows
        flow_matrix = self.generate_traffic_flows()
        
        # Calculate statistics
        critical_count = len([d for d in devices if d.get("critical")])
        high_dep_count = len([d for d in devices if d.get("dependent_count", 0) > 20])
        always_on_count = len([d for d in devices if d.get("always_on")])
        
        print(f"Critical assets: {critical_count}")
        print(f"High dependency devices: {high_dep_count}")
        print(f"Always-on devices: {always_on_count}")
        
        # Create output directory
        output_dir = Path("output/test/enterprise")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save scan data
        scan_data = {
            "timestamp": datetime.now().isoformat(),
            "devices": devices,
            "total_devices": len(devices),
            "scan_duration": 300,
            "scanner": "enterprise_test",
        }
        
        with open(output_dir / "scan_data.json", "w") as f:
            json.dump(scan_data, f, indent=2)
        
        # Save traffic data
        traffic_data = {
            "timestamp": datetime.now().isoformat(),
            "flow_matrix": flow_matrix,
            "total_flows": sum(len(flows) for flows in flow_matrix.values()),
        }
        
        with open(output_dir / "traffic_data.json", "w") as f:
            json.dump(traffic_data, f, indent=2)
        
        # Generate summary report
        self.generate_summary_report(devices, output_dir)
        
        print(f"\nTest data saved to: {output_dir}")
        print("\nDevice distribution by type:")
        type_counts = {}
        for device in devices:
            subtype = device.get("subtype", device["type"])
            type_counts[subtype] = type_counts.get(subtype, 0) + 1
        
        for dtype, count in sorted(type_counts.items()):
            print(f"  {dtype}: {count}")
        
        return devices, flow_matrix
    
    def generate_summary_report(self, devices: List[Dict], output_dir: Path):
        """Generate HTML summary report"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Enterprise Network Test Data Summary</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }}
        h1 {{ color: #333; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #f8f9fa; padding: 15px; border-radius: 8px; border: 1px solid #dee2e6; }}
        .stat-card h3 {{ margin: 0 0 10px 0; color: #495057; font-size: 14px; }}
        .stat-card .value {{ font-size: 28px; font-weight: bold; color: #007bff; }}
        .critical {{ color: #dc3545 !important; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        th {{ background: #f8f9fa; font-weight: bold; }}
        .tag {{ display: inline-block; padding: 2px 8px; margin: 2px; background: #e9ecef; border-radius: 4px; font-size: 12px; }}
        .critical-tag {{ background: #f8d7da; color: #721c24; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Enterprise Network Test Data Summary</h1>
        
        <div class="stats">
            <div class="stat-card">
                <h3>Total Devices</h3>
                <div class="value">{total_devices}</div>
            </div>
            <div class="stat-card">
                <h3>Critical Assets</h3>
                <div class="value critical">{critical_count}</div>
            </div>
            <div class="stat-card">
                <h3>High Dependencies (>20)</h3>
                <div class="value">{high_dep}</div>
            </div>
            <div class="stat-card">
                <h3>Always-On Systems</h3>
                <div class="value">{always_on}</div>
            </div>
            <div class="stat-card">
                <h3>SNMP Enabled</h3>
                <div class="value">{snmp_count}</div>
            </div>
            <div class="stat-card">
                <h3>Long Uptime (>180d)</h3>
                <div class="value">{long_uptime}</div>
            </div>
        </div>
        
        <h2>Critical Assets</h2>
        <table>
            <tr>
                <th>Hostname</th>
                <th>IP Address</th>
                <th>Type</th>
                <th>Dependents</th>
                <th>Uptime</th>
                <th>Tags</th>
            </tr>
            {critical_rows}
        </table>
        
        <h2>High Dependency Devices</h2>
        <table>
            <tr>
                <th>Hostname</th>
                <th>IP Address</th>
                <th>Type</th>
                <th>Dependent Count</th>
                <th>Services</th>
            </tr>
            {dependency_rows}
        </table>
    </div>
</body>
</html>"""
        
        # Calculate statistics
        critical_devices = [d for d in devices if d.get("critical")]
        high_dep_devices = [d for d in devices if d.get("dependent_count", 0) > 20]
        
        stats = {
            "total_devices": len(devices),
            "critical_count": len(critical_devices),
            "high_dep": len(high_dep_devices),
            "always_on": len([d for d in devices if d.get("always_on")]),
            "snmp_count": len([d for d in devices if d.get("snmp_enabled")]),
            "long_uptime": len([d for d in devices if d.get("uptime_days", 0) > 180]),
        }
        
        # Generate critical asset rows
        critical_rows = ""
        for device in sorted(critical_devices, key=lambda x: x.get("dependent_count", 0), reverse=True)[:15]:
            tags_html = " ".join([
                f'<span class="tag {"critical-tag" if tag == "critical" else ""}">{tag}</span>'
                for tag in device.get("tags", [])[:5]
            ])
            critical_rows += f"""
            <tr>
                <td>{device['hostname']}</td>
                <td>{device['ip']}</td>
                <td>{device.get('subtype', device['type'])}</td>
                <td>{device.get('dependent_count', 0)}</td>
                <td>{device.get('uptime_days', 0)} days</td>
                <td>{tags_html}</td>
            </tr>"""
        
        # Generate dependency rows
        dependency_rows = ""
        for device in sorted(high_dep_devices, key=lambda x: x.get("dependent_count", 0), reverse=True)[:10]:
            services = ", ".join([s.split(':')[0] for s in device.get("services", [])][:5])
            dependency_rows += f"""
            <tr>
                <td>{device['hostname']}</td>
                <td>{device['ip']}</td>
                <td>{device.get('subtype', device['type'])}</td>
                <td>{device.get('dependent_count', 0)}</td>
                <td>{services}</td>
            </tr>"""
        
        # Format HTML
        html = html.format(
            **stats,
            critical_rows=critical_rows,
            dependency_rows=dependency_rows
        )
        
        with open(output_dir / "summary.html", "w") as f:
            f.write(html)


if __name__ == "__main__":
    generator = EnterpriseNetworkGenerator()
    devices, flow_matrix = generator.generate_test_data()