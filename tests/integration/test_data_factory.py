#!/usr/bin/env python3
"""
Test Data Factory - Generate standardized test data for consistent testing
"""

import pytest
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any
from faker import Faker


class NetworkDataFactory:
    """Factory for generating consistent network test data"""

    def __init__(self, seed: int = 42):
        """Initialize with deterministic seed for reproducible tests"""
        self.fake = Faker()
        Faker.seed(seed)
        random.seed(seed)

        # Common device vendors and their typical products
        self.vendors = {
            "Cisco": ["router", "switch", "firewall"],
            "HP": ["printer", "server", "workstation"],
            "Dell": ["server", "workstation"],
            "VMware": ["server"],
            "Apple": ["workstation"],
            "Microsoft": ["server"],
            "Fortinet": ["firewall"],
            "Palo Alto Networks": ["firewall"],
            "Juniper": ["router", "switch"],
            "Aruba": ["switch", "access_point"],
            "Ubiquiti": ["access_point", "switch"],
            "Axis": ["security_camera"],
            "Hikvision": ["security_camera"],
            "Honeywell": ["iot_device"],
            "Philips": ["iot_device"],
            "Samsung": ["printer", "workstation"],
        }

        # Port mappings for different device types
        self.port_profiles = {
            "router": {"common": [22, 23, 80, 161, 443], "optional": [8080, 8443, 179, 520]},
            "switch": {"common": [22, 23, 80, 161], "optional": [443, 8080]},
            "firewall": {"common": [22, 80, 443, 8080], "optional": [4443, 10443]},
            "web_server": {"common": [22, 80, 443], "optional": [8080, 8443, 9080, 9443]},
            "database": {"common": [22, 3306, 5432], "optional": [1433, 5984, 6379, 27017]},
            "mail_server": {"common": [22, 25, 110, 143, 993, 995], "optional": [587, 465]},
            "file_server": {"common": [22, 139, 445], "optional": [21, 2049]},
            "workstation": {"common": [135, 139, 445], "optional": [22, 3389, 5900]},
            "printer": {"common": [80, 443, 631, 9100], "optional": [515, 721]},
            "security_camera": {"common": [80, 554], "optional": [443, 8080, 8554]},
            "iot_device": {"common": [80, 443], "optional": [1883, 8883, 5683]},
            "access_point": {"common": [22, 80, 443], "optional": [161, 8080]},
        }

        # Service mappings for ports
        self.port_services = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            135: "msrpc",
            139: "netbios-ssn",
            143: "imap",
            161: "snmp",
            443: "https",
            445: "microsoft-ds",
            465: "smtps",
            515: "printer",
            554: "rtsp",
            587: "submission",
            631: "ipp",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            1883: "mqtt",
            2049: "nfs",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8080: "http-alt",
            8443: "https-alt",
            9100: "jetdirect",
            27017: "mongodb",
        }

    def generate_device(self, device_type: str = None, subnet: str = "192.168.1") -> Dict[str, Any]:
        """Generate a single device with realistic characteristics"""
        if device_type is None:
            device_type = random.choice(list(self.port_profiles.keys()))

        # Select vendor based on device type
        suitable_vendors = [v for v, types in self.vendors.items() if device_type in types]
        vendor = (
            random.choice(suitable_vendors)
            if suitable_vendors
            else random.choice(list(self.vendors.keys()))
        )

        # Generate basic info
        ip_suffix = random.randint(1, 254)
        device = {
            "ip": f"{subnet}.{ip_suffix}",
            "mac": self._generate_mac(vendor),
            "hostname": self._generate_hostname(device_type, ip_suffix),
            "vendor": vendor,
            "type": device_type,
        }

        # Generate ports and services
        port_profile = self.port_profiles.get(device_type, {"common": [80], "optional": []})
        common_ports = port_profile["common"][:]
        optional_ports = random.sample(
            port_profile["optional"], random.randint(0, min(3, len(port_profile["optional"])))
        )

        device["open_ports"] = sorted(common_ports + optional_ports)
        device["services"] = [
            self.port_services.get(port, f"unknown-{port}") for port in device["open_ports"]
        ]

        # Generate OS
        device["os"] = self._generate_os(device_type, vendor)

        # Add optional fields
        if random.random() < 0.3:  # 30% chance of having additional info
            device["uptime"] = random.randint(1, 365)  # days

        if random.random() < 0.2:  # 20% chance of having version info
            device["service_versions"] = self._generate_service_versions(device["services"])

        return device

    def generate_network(
        self,
        size: int = 20,
        subnets: List[str] = None,
        device_distribution: Dict[str, float] = None,
    ) -> List[Dict[str, Any]]:
        """Generate a complete network with realistic device distribution"""
        if subnets is None:
            subnets = ["192.168.1"]

        if device_distribution is None:
            device_distribution = {
                "workstation": 0.4,
                "server": 0.2,
                "router": 0.05,
                "switch": 0.1,
                "printer": 0.1,
                "iot_device": 0.1,
                "security_camera": 0.05,
            }

        devices = []
        devices_per_subnet = size // len(subnets)

        for subnet in subnets:
            subnet_devices = []

            # Ensure at least one router per subnet
            if "router" in device_distribution:
                router = self.generate_device("router", subnet)
                router["ip"] = f"{subnet}.1"  # Router typically gets .1
                subnet_devices.append(router)

            # Generate remaining devices based on distribution
            remaining_devices = devices_per_subnet - len(subnet_devices)

            for _ in range(remaining_devices):
                device_type = self._weighted_choice(device_distribution)
                device = self.generate_device(device_type, subnet)

                # Ensure unique IPs within subnet
                while any(d["ip"] == device["ip"] for d in subnet_devices):
                    ip_suffix = random.randint(2, 254)
                    device["ip"] = f"{subnet}.{ip_suffix}"

                subnet_devices.append(device)

            devices.extend(subnet_devices)

        return devices

    def generate_enterprise_network(self) -> List[Dict[str, Any]]:
        """Generate a realistic enterprise network topology"""
        subnets = {
            "10.0.1": "infrastructure",  # Core network equipment
            "10.0.2": "servers",  # Server farm
            "10.0.3": "workstations",  # User workstations
            "10.0.4": "iot",  # IoT and specialty devices
            "10.0.5": "dmz",  # DMZ servers
        }

        devices = []

        # Infrastructure subnet (10.0.1.x)
        infra_devices = [
            self.generate_device("router", "10.0.1"),
            self.generate_device("switch", "10.0.1"),
            self.generate_device("firewall", "10.0.1"),
        ]
        # Set specific IPs for infrastructure
        infra_devices[0]["ip"] = "10.0.1.1"
        infra_devices[1]["ip"] = "10.0.1.2"
        infra_devices[2]["ip"] = "10.0.1.3"
        devices.extend(infra_devices)

        # Server subnet (10.0.2.x)
        server_types = ["web_server", "database", "mail_server", "file_server"]
        for i, server_type in enumerate(server_types, 10):
            server = self.generate_device(server_type, "10.0.2")
            server["ip"] = f"10.0.2.{i}"
            devices.append(server)

        # Workstation subnet (10.0.3.x)
        for i in range(100, 120):  # 20 workstations
            workstation = self.generate_device("workstation", "10.0.3")
            workstation["ip"] = f"10.0.3.{i}"
            devices.append(workstation)

        # IoT subnet (10.0.4.x)
        iot_types = ["printer", "security_camera", "iot_device", "access_point"]
        for i, iot_type in enumerate(iot_types * 3, 50):  # 12 IoT devices
            iot_device = self.generate_device(iot_type, "10.0.4")
            iot_device["ip"] = f"10.0.4.{i}"
            devices.append(iot_device)

        # DMZ subnet (10.0.5.x)
        dmz_devices = [
            self.generate_device("web_server", "10.0.5"),
            self.generate_device("mail_server", "10.0.5"),
        ]
        dmz_devices[0]["ip"] = "10.0.5.10"
        dmz_devices[1]["ip"] = "10.0.5.11"
        devices.extend(dmz_devices)

        return devices

    def generate_scan_timeline(
        self, network: List[Dict[str, Any]], num_scans: int = 5, days_apart: int = 1
    ) -> List[Dict[str, Any]]:
        """Generate a timeline of network scans showing changes over time"""
        timeline = []
        current_network = network[:]

        for i in range(num_scans):
            scan_time = datetime.now() - timedelta(days=(num_scans - i - 1) * days_apart)

            # Apply some changes to the network
            if i > 0:
                current_network = self._apply_network_changes(current_network)

            scan_data = {
                "timestamp": scan_time.isoformat(),
                "scan_id": f'scan_{scan_time.strftime("%Y%m%d_%H%M%S")}',
                "target": self._get_network_range(current_network),
                "devices": current_network[:],
            }
            timeline.append(scan_data)

        return timeline

    def generate_vulnerability_data(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate realistic vulnerability data for a device"""
        vulnerabilities = []

        # Common vulnerabilities based on services
        vuln_templates = {
            "ssh": ["CVE-2020-15778", "CVE-2021-28041"],
            "http": ["CVE-2021-34527", "CVE-2022-22965"],
            "https": ["CVE-2021-44228", "CVE-2022-0778"],
            "telnet": ["CVE-1999-0618"],  # Telnet is inherently insecure
            "snmp": ["CVE-2017-6736", "CVE-2020-8664"],
            "rdp": ["CVE-2019-0708", "CVE-2021-34527"],
        }

        for service in device.get("services", []):
            if service in vuln_templates and random.random() < 0.3:  # 30% chance
                cve = random.choice(vuln_templates[service])
                vuln = {
                    "cve_id": cve,
                    "service": service,
                    "severity": random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
                    "score": round(random.uniform(2.0, 9.9), 1),
                    "description": f"Vulnerability in {service} service",
                }
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _generate_mac(self, vendor: str) -> str:
        """Generate MAC address with vendor-specific OUI"""
        # Simplified vendor OUI mapping
        oui_map = {
            "Cisco": "00:1a:a0",
            "HP": "00:23:ae",
            "Dell": "00:14:22",
            "VMware": "00:50:56",
            "Apple": "00:17:f2",
            "Microsoft": "00:03:ff",
        }

        oui = oui_map.get(vendor, "00:11:22")
        suffix = ":".join([f"{random.randint(0, 255):02x}" for _ in range(3)])
        return f"{oui}:{suffix}"

    def _generate_hostname(self, device_type: str, ip_suffix: int) -> str:
        """Generate realistic hostname based on device type"""
        prefixes = {
            "router": "rtr",
            "switch": "sw",
            "firewall": "fw",
            "web_server": "web",
            "database": "db",
            "mail_server": "mail",
            "file_server": "file",
            "workstation": "ws",
            "printer": "printer",
            "security_camera": "cam",
            "iot_device": "iot",
            "access_point": "ap",
        }

        prefix = prefixes.get(device_type, "device")
        return f"{prefix}-{ip_suffix:03d}"

    def _generate_os(self, device_type: str, vendor: str) -> str:
        """Generate realistic OS based on device type and vendor"""
        os_map = {
            ("router", "Cisco"): "Cisco IOS 15.1",
            ("switch", "Cisco"): "Cisco IOS",
            ("firewall", "Cisco"): "Cisco ASA",
            ("firewall", "Fortinet"): "FortiOS",
            ("firewall", "Palo Alto Networks"): "PAN-OS",
            ("web_server", "VMware"): random.choice(
                ["Ubuntu 20.04", "CentOS 7", "Windows Server 2019"]
            ),
            ("database", "VMware"): random.choice(
                ["Ubuntu 20.04", "CentOS 8", "Windows Server 2019"]
            ),
            ("workstation", "Dell"): "Windows 10",
            ("workstation", "HP"): "Windows 10",
            ("workstation", "Apple"): "macOS 12.0",
            ("printer", "HP"): "HP JetReady",
            ("security_camera", "Axis"): "Linux",
            ("iot_device", "*"): "",
        }

        key = (device_type, vendor)
        if key in os_map:
            return os_map[key]

        # Fallback OS selection
        if device_type in ["workstation"]:
            return random.choice(["Windows 10", "Windows 11", "macOS 12.0", "Ubuntu 20.04"])
        elif device_type in ["web_server", "database", "mail_server", "file_server"]:
            return random.choice(
                ["Ubuntu 20.04", "CentOS 8", "Windows Server 2019", "Windows Server 2022"]
            )
        else:
            return "Linux"

    def _generate_service_versions(self, services: List[str]) -> Dict[str, str]:
        """Generate version information for services"""
        versions = {}
        version_map = {
            "ssh": ["OpenSSH 8.0", "OpenSSH 7.4", "OpenSSH 8.2"],
            "http": ["Apache 2.4.41", "nginx 1.18.0", "IIS 10.0"],
            "https": ["Apache 2.4.41", "nginx 1.18.0", "IIS 10.0"],
            "mysql": ["MySQL 8.0.25", "MySQL 5.7.34", "MySQL 8.0.23"],
            "postgresql": ["PostgreSQL 13.3", "PostgreSQL 12.7", "PostgreSQL 14.1"],
        }

        for service in services:
            if service in version_map:
                versions[service] = random.choice(version_map[service])

        return versions

    def _weighted_choice(self, weights: Dict[str, float]) -> str:
        """Choose an item based on weighted probabilities"""
        items = list(weights.keys())
        probabilities = list(weights.values())
        return random.choices(items, weights=probabilities, k=1)[0]

    def _apply_network_changes(self, network: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply realistic changes to network over time"""
        changed_network = network[:]

        # 10% chance of new device
        if random.random() < 0.1:
            new_device = self.generate_device()
            # Ensure unique IP
            existing_ips = {d["ip"] for d in changed_network}
            attempts = 0
            while new_device["ip"] in existing_ips and attempts < 50:
                new_device = self.generate_device()
                attempts += 1
            if new_device["ip"] not in existing_ips:
                changed_network.append(new_device)

        # 5% chance of device removal
        if random.random() < 0.05 and len(changed_network) > 5:
            removed_device = random.choice(changed_network)
            changed_network.remove(removed_device)

        # 20% chance of service changes
        if random.random() < 0.2 and changed_network:
            device = random.choice(changed_network)
            if random.random() < 0.5:  # Add service
                new_port = random.choice([8080, 8443, 9080, 3000, 5000])
                if new_port not in device["open_ports"]:
                    device["open_ports"].append(new_port)
                    device["services"].append(
                        self.port_services.get(new_port, f"unknown-{new_port}")
                    )
            else:  # Remove service
                if len(device["open_ports"]) > 1:
                    removed_port = random.choice(device["open_ports"])
                    device["open_ports"].remove(removed_port)
                    service_to_remove = self.port_services.get(
                        removed_port, f"unknown-{removed_port}"
                    )
                    if service_to_remove in device["services"]:
                        device["services"].remove(service_to_remove)

        return changed_network

    def _get_network_range(self, devices: List[Dict[str, Any]]) -> str:
        """Determine network range from device list"""
        if not devices:
            return "192.168.1.0/24"

        # Get most common network prefix
        prefixes = {}
        for device in devices:
            ip_parts = device["ip"].split(".")
            prefix = ".".join(ip_parts[:3])
            prefixes[prefix] = prefixes.get(prefix, 0) + 1

        most_common_prefix = max(prefixes.items(), key=lambda x: x[1])[0]
        return f"{most_common_prefix}.0/24"


# Test data fixtures for pytest
@pytest.fixture
def network_factory():
    """Network data factory fixture"""
    return NetworkDataFactory()


@pytest.fixture
def small_network(network_factory):
    """Small test network (5 devices)"""
    return network_factory.generate_network(size=5)


@pytest.fixture
def medium_network(network_factory):
    """Medium test network (20 devices)"""
    return network_factory.generate_network(size=20)


@pytest.fixture
def enterprise_network(network_factory):
    """Enterprise test network"""
    return network_factory.generate_enterprise_network()


@pytest.fixture
def scan_timeline(network_factory, medium_network):
    """Timeline of network scans"""
    return network_factory.generate_scan_timeline(medium_network, num_scans=3)


if __name__ == "__main__":
    # Example usage
    factory = NetworkDataFactory()

    # Generate a small network
    network = factory.generate_network(size=10)
    print(f"Generated {len(network)} devices")

    # Generate enterprise network
    enterprise = factory.generate_enterprise_network()
    print(f"Generated enterprise network with {len(enterprise)} devices")

    # Save to file for manual inspection
    with open("test_network_data.json", "w") as f:
        json.dump({"small_network": network, "enterprise_network": enterprise}, f, indent=2)

    print("Test data saved to test_network_data.json")
