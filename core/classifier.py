import re
from typing import Dict, List, Tuple, Set


class DeviceClassifier:
    def __init__(self):
        # Enhanced port signatures for device types
        self.port_signatures = {
            "router": {
                "ports": [22, 23, 53, 80, 443, 161, 179],  # Added DNS(53), BGP(179)
                "services": ["ssh", "telnet", "dns", "domain", "http", "https", "snmp", "bgp"],
                "keywords": ["router", "gateway", "cisco", "juniper", "mikrotik", "fortinet", "pfsense"],
                "priority": 90
            },
            "switch": {
                "ports": [22, 23, 161, 80, 443],
                "services": ["ssh", "telnet", "snmp", "http", "https"],
                "keywords": ["switch", "catalyst", "procurve", "powerconnect", "managed"],
                "priority": 85
            },
            "firewall": {
                "ports": [22, 443, 500, 4500, 1701],  # VPN ports
                "services": ["ssh", "https", "isakmp", "ipsec", "l2tp"],
                "keywords": ["firewall", "fortigate", "palo alto", "checkpoint", "sonicwall", "asa"],
                "priority": 88
            },
            "database": {
                "ports": [3306, 5432, 1433, 1521, 27017, 6379, 5984],
                "services": ["mysql", "postgresql", "ms-sql", "oracle", "mongodb", "redis", "couchdb"],
                "keywords": ["mysql", "mariadb", "postgres", "oracle", "mongodb", "database"],
                "priority": 80
            },
            "web_server": {
                "ports": [80, 443, 8080, 8443, 8000, 8888, 3000, 5000],
                "services": ["http", "https", "http-proxy", "http-alt", "webmin"],
                "keywords": ["apache", "nginx", "iis", "tomcat", "webserver", "httpd"],
                "priority": 75
            },
            "mail_server": {
                "ports": [25, 110, 143, 465, 587, 993, 995],
                "services": ["smtp", "pop3", "imap", "smtps", "submission", "imaps", "pop3s"],
                "keywords": ["mail", "exchange", "postfix", "sendmail", "zimbra"],
                "priority": 70
            },
            "dns_server": {
                "ports": [53],
                "services": ["dns", "domain"],
                "keywords": ["bind", "named", "dns", "resolver"],
                "priority": 85
            },
            "windows_server": {
                "ports": [135, 139, 445, 3389, 88, 389, 636],  # Added Kerberos, LDAP
                "services": ["msrpc", "netbios", "microsoft-ds", "ms-wbt-server", "kerberos", "ldap"],
                "keywords": ["windows", "microsoft", "active directory", "domain controller"],
                "priority": 65
            },
            "linux_server": {
                "ports": [22, 111, 2049],  # SSH, RPC, NFS
                "services": ["ssh", "rpcbind", "nfs"],
                "keywords": ["linux", "ubuntu", "centos", "debian", "redhat", "suse"],
                "exclude_ports": [139, 445, 3389],  # No Windows services
                "priority": 60
            },
            "printer": {
                "ports": [515, 631, 9100, 80, 443],
                "services": ["lpd", "ipp", "jetdirect", "http", "https"],
                "keywords": ["printer", "print", "cups", "hp", "canon", "epson", "brother", "xerox"],
                "priority": 50
            },
            "nas": {
                "ports": [139, 445, 548, 2049, 873, 5000, 5001],  # SMB, AFP, NFS, rsync, Synology
                "services": ["netbios", "microsoft-ds", "afp", "nfs", "rsync", "http", "https"],
                "keywords": ["nas", "synology", "qnap", "freenas", "truenas", "storage"],
                "priority": 70
            },
            "hypervisor": {
                "ports": [443, 902, 5900, 8006],  # vSphere, Proxmox VNC
                "services": ["https", "vmware", "vnc", "proxmox"],
                "keywords": ["vmware", "esxi", "vsphere", "proxmox", "hyper-v", "xenserver"],
                "priority": 85
            },
            "workstation": {
                "ports": [135, 139, 445, 3389, 5900],  # Windows/VNC
                "services": ["netbios", "microsoft-ds", "ms-wbt-server", "vnc"],
                "keywords": ["workstation", "desktop", "windows 10", "windows 11"],
                "max_ports": 15,
                "priority": 40
            },
            "iot": {
                "ports": [80, 443, 8080, 1883, 8883, 5683, 1900],  # HTTP, MQTT, CoAP, UPnP
                "services": ["http", "https", "mqtt", "coap", "upnp"],
                "keywords": ["camera", "sensor", "iot", "smart", "esp", "arduino", "tasmota"],
                "vendor_patterns": ["Espressif", "Raspberry", "Arduino", "Tuya"],
                "priority": 30
            },
            "voip": {
                "ports": [5060, 5061, 5004, 5005, 2000, 4569],  # SIP, RTP, Asterisk
                "services": ["sip", "sips", "rtp", "asterisk", "iax"],
                "keywords": ["voip", "asterisk", "3cx", "phone", "pbx", "sip"],
                "priority": 55
            },
            "media_server": {
                "ports": [8096, 32400, 8200, 554],  # Jellyfin, Plex, RTSP
                "services": ["http", "plex", "jellyfin", "rtsp"],
                "keywords": ["plex", "jellyfin", "emby", "kodi", "media"],
                "priority": 45
            }
        }

        # Enhanced vendor patterns - don't classify as "virtual"
        self.vendor_patterns = {
            "Cisco": ["router", "switch"],
            "Juniper": ["router", "firewall"],
            "Fortinet|FortiGate": ["firewall"],
            "Dell|PowerEdge": ["server"],
            "HP|Hewlett|ProCurve": ["switch", "server", "printer"],
            "Synology": ["nas"],
            "QNAP": ["nas"],
            "Apple": ["workstation"],
            "Intel Corporate": ["workstation"],
            "Raspberry": ["iot"],
            "Ubiquiti": ["router", "switch"],
            "MikroTik": ["router"],
            "Netgear": ["router", "switch"],
            "TP-Link": ["router", "switch", "iot"],
        }

        # Common service to device type mappings
        self.service_hints = {
            "mysql": "database",
            "postgres": "database",
            "mongodb": "database",
            "redis": "database",
            "apache": "web_server",
            "nginx": "web_server",
            "smtp": "mail_server",
            "dns": "dns_server",
            "domain": "dns_server",
            "ssh": "linux_server",
            "rdp": "windows_server",
            "vnc": "workstation",
            "plex": "media_server"
        }

    def classify_devices(self, devices: List[Dict]) -> List[Dict]:
        """Classify devices based on signatures"""
        for device in devices:
            device["type"] = self._classify_single_device(device)
            device["confidence"] = self._calculate_confidence(device)
        return devices

    def _classify_single_device(self, device: Dict) -> str:
        """Classify a single device with improved logic"""
        scores = {}

        # Get device info
        device_ports = set(device.get("open_ports", []))
        device_services = [s.split(":")[0].lower() for s in device.get("services", [])]
        os_info = device.get("os", "").lower()
        hostname = device.get("hostname", "").lower()
        vendor = device.get("vendor", "").lower()

        # Quick service hint check for obvious cases
        for service in device_services:
            for hint_service, hint_type in self.service_hints.items():
                if hint_service in service:
                    scores[hint_type] = scores.get(hint_type, 0) + 15

        # Detailed signature matching
        for device_type, signature in self.port_signatures.items():
            score = 0
            matches = []

            # Port matches (weighted by priority)
            if "ports" in signature and device_ports:
                matching_ports = device_ports.intersection(signature["ports"])
                if matching_ports:
                    port_weight = 3 * (signature.get("priority", 50) / 100)
                    score += len(matching_ports) * port_weight
                    matches.append(f"ports: {matching_ports}")

            # Service matches (most reliable indicator)
            if "services" in signature:
                for service in device_services:
                    for sig_svc in signature["services"]:
                        if sig_svc in service:
                            service_weight = 5 * (signature.get("priority", 50) / 100)
                            score += service_weight
                            matches.append(f"service: {service}")

            # Keyword matches in OS/hostname
            if "keywords" in signature:
                text = f"{os_info} {hostname} {vendor}"
                for keyword in signature["keywords"]:
                    if keyword in text:
                        score += 8
                        matches.append(f"keyword: {keyword}")

            # Exclude ports (negative match)
            if "exclude_ports" in signature:
                if device_ports.intersection(signature["exclude_ports"]):
                    score -= 20
                    matches.append("excluded ports found")

            # Max ports check
            if "max_ports" in signature:
                if len(device_ports) > signature["max_ports"]:
                    score -= 10
                    matches.append("too many ports")

            # Store score with debug info
            if score > 0:
                scores[device_type] = score
                # Debug: print(f"{device['ip']} - {device_type}: {score} ({matches})")

        # Special handling for virtual machines
        if "vmware" in vendor or "virtual" in os_info:
            # Don't classify as "virtual" - determine actual function
            # Boost scores for server types on virtual platforms
            for server_type in ["database", "web_server", "linux_server", "windows_server"]:
                if server_type in scores:
                    scores[server_type] += 5

        # Vendor pattern matching (but not deterministic)
        if vendor and "vmware" not in vendor:  # Skip VMware vendor matching
            for pattern, device_types in self.vendor_patterns.items():
                if re.search(pattern, vendor, re.I):
                    for device_type in device_types:
                        scores[device_type] = scores.get(device_type, 0) + 10

        # Special cases and heuristics
        if self._is_infrastructure_device(device_ports, device_services):
            for infra_type in ["router", "switch", "firewall"]:
                if infra_type in scores:
                    scores[infra_type] += 5

        # Return highest scoring type
        if scores:
            # Sort by score and return best match
            sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
            best_type, best_score = sorted_scores[0]

            # Require minimum score threshold
            if best_score >= 5:
                return best_type

        return "unknown"

    def _is_infrastructure_device(self, ports: Set[int], services: List[str]) -> bool:
        """Check if device appears to be network infrastructure"""
        infra_indicators = {
            "ports": {22, 23, 161, 443},  # SSH, Telnet, SNMP, HTTPS
            "services": ["ssh", "telnet", "snmp", "https"]
        }

        # Many infrastructure services and few others
        infra_count = len(ports.intersection(infra_indicators["ports"]))
        return infra_count >= 2 and len(ports) < 20

    def _calculate_confidence(self, device: Dict) -> float:
        """Calculate classification confidence (0-100)"""
        confidence = 0

        # Base confidence from data availability
        if device.get("vendor"):
            confidence += 15

        if device.get("os"):
            confidence += 25
            # Specific OS detection adds more confidence
            if any(known in device["os"].lower() for known in ["windows", "linux", "cisco", "ubuntu"]):
                confidence += 10

        if len(device.get("services", [])) > 0:
            confidence += 20
            # Known services add confidence
            if len(device.get("services", [])) > 3:
                confidence += 10

        if device.get("hostname"):
            confidence += 10
            # Meaningful hostname adds confidence
            if not device["hostname"].startswith("192.") and not device["hostname"].startswith("10."):
                confidence += 5

        # Strong type detection
        if device.get("type") not in ["unknown", "virtual"]:
            confidence += 15

        # Multiple open ports suggest active device
        if len(device.get("open_ports", [])) > 1:
            confidence += 5

        return min(confidence, 100)
