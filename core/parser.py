from datetime import datetime
from typing import Any, Dict, List

from utils.mac_lookup import MACLookup


class ScanParser:
    def __init__(self):
        self.parsers = {"nmap": self._parse_nmap_results, "masscan": self._parse_masscan_results}
        self.mac_lookup = MACLookup()

    def parse_results(self, raw_results: Any) -> List[Dict]:
        """Parse scan results into standardized format"""
        if isinstance(raw_results, list):
            # Already parsed by scanner
            if raw_results and "ip" in raw_results[0]:
                # Nmap results
                devices = self._standardize_devices(raw_results)
                # Enrich with MAC data from ARP cache (macOS)
                devices = self.mac_lookup.enrich_with_arp_cache(devices)
                return devices
            else:
                # Masscan results
                devices = self._parse_masscan_results(raw_results)
                # Enrich with MAC data from ARP cache (macOS)
                devices = self.mac_lookup.enrich_with_arp_cache(devices)
                return devices

        return []

    def _standardize_devices(self, devices: List[Dict]) -> List[Dict]:
        """Ensure all devices have required fields"""
        standardized = []

        for device in devices:
            std_device = {
                "ip": device.get("ip", ""),
                "mac": device.get("mac", ""),
                "hostname": device.get("hostname", ""),
                "vendor": device.get("vendor", ""),
                "type": device.get("type", "unknown"),
                "os": device.get("os", ""),
                "services": device.get("services", []),
                "open_ports": device.get("open_ports", []),
                "critical": device.get("critical", False),
                "confidence": device.get("confidence", 0),
                "last_seen": datetime.now().isoformat(),
                "first_seen": device.get("first_seen", datetime.now().isoformat()),
            }

            # Ensure services are properly formatted
            if std_device["services"] and isinstance(std_device["services"][0], int):
                # Convert port numbers to service strings
                std_device["services"] = [f"unknown:{port}" for port in std_device["services"]]

            # Enrich with vendor info if MAC exists
            if std_device["mac"] and not std_device["vendor"]:
                vendor = self.mac_lookup.lookup(std_device["mac"])
                if vendor:
                    std_device["vendor"] = vendor

            standardized.append(std_device)

        return standardized

    def _parse_nmap_results(self, results: List[Dict]) -> List[Dict]:
        """Parse nmap-specific results"""
        # Already handled by scanner
        return self._standardize_devices(results)

    def _parse_masscan_results(self, results: List[Dict]) -> List[Dict]:
        """Parse masscan JSON results"""
        devices = {}

        for entry in results:
            if "ip" in entry:
                ip = entry["ip"]
                if ip not in devices:
                    devices[ip] = {
                        "ip": ip,
                        "mac": "",
                        "hostname": "",
                        "vendor": "",
                        "type": "unknown",
                        "os": "",
                        "services": [],
                        "open_ports": [],
                    }

                # Add port information if available
                if "ports" in entry:
                    for port_info in entry["ports"]:
                        port = port_info.get("port", 0)
                        if port and port not in devices[ip]["open_ports"]:
                            devices[ip]["open_ports"].append(port)
                            devices[ip]["services"].append(f"unknown:{port}")

        return self._standardize_devices(list(devices.values()))
