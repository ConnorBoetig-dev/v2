import re
from typing import Dict, List


class DeviceClassifier:
    def __init__(self):
        # Port signatures for device types
        self.port_signatures = {
            "router": {
                "ports": [22, 23, 80, 443],
                "services": ["ssh", "telnet", "http", "https"],
                "keywords": ["router", "gateway", "cisco", "juniper", "mikrotik"],
            },
            "switch": {
                "ports": [22, 23, 161],
                "services": ["ssh", "telnet", "snmp"],
                "keywords": ["switch", "catalyst", "procurve"],
            },
            "printer": {
                "ports": [515, 631, 9100],
                "services": ["lpd", "ipp", "jetdirect"],
                "keywords": ["printer", "hp", "canon", "epson"],
            },
            "windows_server": {
                "ports": [135, 139, 445, 3389],
                "services": ["msrpc", "netbios", "microsoft-ds", "ms-wbt-server"],
                "keywords": ["windows", "microsoft"],
            },
            "linux_server": {
                "ports": [22],
                "services": ["ssh"],
                "keywords": ["linux", "ubuntu", "centos", "debian"],
                "exclude_ports": [139, 445],  # No SMB
            },
            "web_server": {
                "ports": [80, 443, 8080, 8443],
                "services": ["http", "https"],
                "keywords": ["apache", "nginx", "iis"],
            },
            "database": {
                "ports": [1433, 3306, 5432, 1521, 27017],
                "services": ["ms-sql", "mysql", "postgresql", "oracle", "mongodb"],
            },
            "iot": {
                "ports": [80, 443, 8080, 1883, 8883],
                "keywords": ["camera", "sensor", "iot", "smart"],
                "vendor_patterns": ["Espressif", "Raspberry", "Arduino"],
            },
            "workstation": {
                "ports": [135, 139, 445],
                "services": ["netbios", "microsoft-ds"],
                "keywords": ["workstation", "desktop"],
                "max_ports": 10,  # Workstations have fewer open ports
            },
        }

        # MAC vendor patterns
        self.vendor_patterns = {
            "Cisco": "router",
            "Juniper": "router",
            "HP|Hewlett": "switch",
            "Dell": "server",
            "VMware": "virtual",
            "Microsoft": "windows",
            "Apple": "workstation",
            "Intel Corporate": "workstation",
            "Raspberry": "iot",
        }

    def classify_devices(self, devices: List[Dict]) -> List[Dict]:
        """Classify devices based on signatures"""
        for device in devices:
            device["type"] = self._classify_single_device(device)
            device["confidence"] = self._calculate_confidence(device)
        return devices

    def _classify_single_device(self, device: Dict) -> str:
        """Classify a single device"""
        scores = {}

        # Check port signatures
        device_ports = set(device.get("open_ports", []))
        device_services = [s.split(":")[0] for s in device.get("services", [])]

        for device_type, signature in self.port_signatures.items():
            score = 0

            # Port matches
            if "ports" in signature:
                matching_ports = device_ports.intersection(signature["ports"])
                score += len(matching_ports) * 2

            # Service matches
            if "services" in signature:
                for service in device_services:
                    if any(sig_svc in service.lower() for sig_svc in signature["services"]):
                        score += 3

            # Keyword matches in OS/hostname
            if "keywords" in signature:
                text = f"{device.get('os', '')} {device.get('hostname', '')}".lower()
                for keyword in signature["keywords"]:
                    if keyword in text:
                        score += 5

            # Exclude ports (negative match)
            if "exclude_ports" in signature:
                if device_ports.intersection(signature["exclude_ports"]):
                    score -= 10

            # Max ports check
            if "max_ports" in signature:
                if len(device_ports) > signature["max_ports"]:
                    score -= 5

            scores[device_type] = score

        # Check vendor patterns
        vendor = device.get("vendor", "")
        for pattern, device_type in self.vendor_patterns.items():
            if re.search(pattern, vendor, re.I):
                scores[device_type] = scores.get(device_type, 0) + 10

        # Return highest scoring type
        if scores:
            best_type = max(scores, key=scores.get)
            if scores[best_type] > 0:
                return best_type

        return "unknown"

    def _calculate_confidence(self, device: Dict) -> float:
        """Calculate classification confidence (0-100)"""
        confidence = 0

        # Has vendor info: +20
        if device.get("vendor"):
            confidence += 20

        # Has OS detection: +30
        if device.get("os"):
            confidence += 30

        # Has services detected: +20
        if len(device.get("services", [])) > 0:
            confidence += 20

        # Has hostname: +10
        if device.get("hostname"):
            confidence += 10

        # Multiple matching signatures: +20
        if device.get("type") != "unknown":
            confidence += 20

        return min(confidence, 100)
