"""Device classification module for identifying network device types.

This module analyzes device characteristics (ports, services, OS, vendor)
to determine the most likely device type.
"""

import re
import logging
from typing import Dict, List, Tuple, Set, Optional
from dataclasses import dataclass, field
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)


class DeviceType(Enum):
    """Enumeration of supported device types."""
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    DATABASE = "database"
    WEB_SERVER = "web_server"
    MAIL_SERVER = "mail_server"
    DNS_SERVER = "dns_server"
    WINDOWS_SERVER = "windows_server"
    LINUX_SERVER = "linux_server"
    PRINTER = "printer"
    NAS = "nas"
    HYPERVISOR = "hypervisor"
    WORKSTATION = "workstation"
    IOT = "iot"
    VOIP = "voip"
    MEDIA_SERVER = "media_server"
    UNKNOWN = "unknown"


@dataclass
class DeviceSignature:
    """Device type signature definition."""
    device_type: DeviceType
    ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    exclude_ports: List[int] = field(default_factory=list)
    vendor_patterns: List[str] = field(default_factory=list)
    priority: int = 50
    max_ports: Optional[int] = None
    min_confidence: float = 0.3


class DeviceClassifier:
    """Classifies network devices based on their characteristics."""
    
    def __init__(self):
        """Initialize classifier with device signatures."""
        self.signatures = self._build_signatures()
        self.vendor_patterns = self._build_vendor_patterns()
        self.service_hints = self._build_service_hints()
        
    def _build_signatures(self) -> Dict[DeviceType, DeviceSignature]:
        """Build device signature database."""
        return {
            DeviceType.ROUTER: DeviceSignature(
                device_type=DeviceType.ROUTER,
                ports=[22, 23, 53, 80, 443, 161, 179],  # SSH, Telnet, DNS, HTTP(S), SNMP, BGP
                services=["ssh", "telnet", "dns", "domain", "http", "https", "snmp", "bgp"],
                keywords=["router", "gateway", "cisco", "juniper", "mikrotik", "fortinet", "pfsense", "edgerouter"],
                vendor_patterns=["Cisco", "Juniper", "MikroTik", "Ubiquiti", "Netgear"],
                priority=90
            ),
            DeviceType.SWITCH: DeviceSignature(
                device_type=DeviceType.SWITCH,
                ports=[22, 23, 161, 80, 443],
                services=["ssh", "telnet", "snmp", "http", "https"],
                keywords=["switch", "catalyst", "procurve", "powerconnect", "managed", "vlan"],
                vendor_patterns=["Cisco", "HP", "Dell", "Aruba"],
                priority=85
            ),
            DeviceType.FIREWALL: DeviceSignature(
                device_type=DeviceType.FIREWALL,
                ports=[22, 443, 500, 4500, 1701],  # SSH, HTTPS, VPN ports
                services=["ssh", "https", "isakmp", "ipsec", "l2tp"],
                keywords=["firewall", "fortigate", "palo alto", "checkpoint", "sonicwall", "asa", "pfsense"],
                vendor_patterns=["Fortinet", "Palo Alto", "Check Point", "SonicWall"],
                priority=88
            ),
            DeviceType.DATABASE: DeviceSignature(
                device_type=DeviceType.DATABASE,
                ports=[3306, 5432, 1433, 1521, 27017, 6379, 5984, 9200],  # Added Elasticsearch
                services=["mysql", "postgresql", "ms-sql", "oracle", "mongodb", "redis", "couchdb", "elasticsearch"],
                keywords=["mysql", "mariadb", "postgres", "oracle", "mongodb", "database", "redis", "nosql"],
                priority=80
            ),
            DeviceType.WEB_SERVER: DeviceSignature(
                device_type=DeviceType.WEB_SERVER,
                ports=[80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000],
                services=["http", "https", "http-proxy", "http-alt", "webmin", "nginx", "apache"],
                keywords=["apache", "nginx", "iis", "tomcat", "webserver", "httpd", "node", "express"],
                priority=75
            ),
            DeviceType.MAIL_SERVER: DeviceSignature(
                device_type=DeviceType.MAIL_SERVER,
                ports=[25, 110, 143, 465, 587, 993, 995],
                services=["smtp", "pop3", "imap", "smtps", "submission", "imaps", "pop3s"],
                keywords=["mail", "exchange", "postfix", "sendmail", "zimbra", "dovecot", "exim"],
                priority=70
            ),
            DeviceType.DNS_SERVER: DeviceSignature(
                device_type=DeviceType.DNS_SERVER,
                ports=[53],
                services=["dns", "domain"],
                keywords=["bind", "named", "dns", "resolver", "unbound", "powerdns"],
                priority=85
            ),
            DeviceType.WINDOWS_SERVER: DeviceSignature(
                device_type=DeviceType.WINDOWS_SERVER,
                ports=[135, 139, 445, 3389, 88, 389, 636],  # RPC, SMB, RDP, Kerberos, LDAP
                services=["msrpc", "netbios", "microsoft-ds", "ms-wbt-server", "kerberos", "ldap", "ldaps"],
                keywords=["windows", "microsoft", "active directory", "domain controller", "server"],
                vendor_patterns=["Microsoft"],
                priority=65
            ),
            DeviceType.LINUX_SERVER: DeviceSignature(
                device_type=DeviceType.LINUX_SERVER,
                ports=[22, 111, 2049],  # SSH, RPC, NFS
                services=["ssh", "rpcbind", "nfs"],
                keywords=["linux", "ubuntu", "centos", "debian", "redhat", "suse", "fedora"],
                exclude_ports=[139, 445, 3389],  # No Windows services
                priority=60
            ),
            DeviceType.PRINTER: DeviceSignature(
                device_type=DeviceType.PRINTER,
                ports=[515, 631, 9100, 80, 443],
                services=["lpd", "ipp", "jetdirect", "http", "https"],
                keywords=["printer", "print", "cups", "hp", "canon", "epson", "brother", "xerox", "laserjet"],
                vendor_patterns=["HP", "Canon", "Epson", "Brother", "Xerox"],
                priority=50
            ),
            DeviceType.NAS: DeviceSignature(
                device_type=DeviceType.NAS,
                ports=[139, 445, 548, 2049, 873, 5000, 5001],  # SMB, AFP, NFS, rsync, Synology
                services=["netbios", "microsoft-ds", "afp", "nfs", "rsync", "http", "https"],
                keywords=["nas", "synology", "qnap", "freenas", "truenas", "storage", "openmediavault"],
                vendor_patterns=["Synology", "QNAP", "Western Digital", "Netgear"],
                priority=70
            ),
            DeviceType.HYPERVISOR: DeviceSignature(
                device_type=DeviceType.HYPERVISOR,
                ports=[443, 902, 5900, 8006],  # vSphere, Proxmox VNC
                services=["https", "vmware", "vnc", "proxmox"],
                keywords=["vmware", "esxi", "vsphere", "proxmox", "hyper-v", "xenserver", "kvm", "virtualbox"],
                vendor_patterns=["VMware", "Proxmox", "Citrix"],
                priority=85
            ),
            DeviceType.WORKSTATION: DeviceSignature(
                device_type=DeviceType.WORKSTATION,
                ports=[135, 139, 445, 3389, 5900],  # Windows/VNC
                services=["netbios", "microsoft-ds", "ms-wbt-server", "vnc"],
                keywords=["workstation", "desktop", "windows 10", "windows 11", "macbook", "imac"],
                vendor_patterns=["Apple", "Dell", "HP", "Lenovo"],
                max_ports=15,
                priority=40
            ),
            DeviceType.IOT: DeviceSignature(
                device_type=DeviceType.IOT,
                ports=[80, 443, 8080, 1883, 8883, 5683, 1900],  # HTTP, MQTT, CoAP, UPnP
                services=["http", "https", "mqtt", "coap", "upnp"],
                keywords=["camera", "sensor", "iot", "smart", "esp", "arduino", "tasmota", "zigbee", "hue"],
                vendor_patterns=["Espressif", "Raspberry", "Arduino", "Tuya", "Philips"],
                priority=30
            ),
            DeviceType.VOIP: DeviceSignature(
                device_type=DeviceType.VOIP,
                ports=[5060, 5061, 5004, 5005, 2000, 4569],  # SIP, RTP, Asterisk
                services=["sip", "sips", "rtp", "asterisk", "iax"],
                keywords=["voip", "asterisk", "3cx", "phone", "pbx", "sip", "cisco phone"],
                vendor_patterns=["Cisco", "Polycom", "Yealink", "Grandstream"],
                priority=55
            ),
            DeviceType.MEDIA_SERVER: DeviceSignature(
                device_type=DeviceType.MEDIA_SERVER,
                ports=[8096, 32400, 8200, 554],  # Jellyfin, Plex, RTSP
                services=["http", "plex", "jellyfin", "rtsp", "dlna"],
                keywords=["plex", "jellyfin", "emby", "kodi", "media", "streaming"],
                priority=45
            ),
        }
    
    def _build_vendor_patterns(self) -> Dict[str, List[DeviceType]]:
        """Build vendor to device type mapping."""
        return {
            "Cisco": [DeviceType.ROUTER, DeviceType.SWITCH],
            "Juniper": [DeviceType.ROUTER, DeviceType.FIREWALL],
            "Fortinet|FortiGate": [DeviceType.FIREWALL],
            "Dell|PowerEdge": [DeviceType.WINDOWS_SERVER, DeviceType.LINUX_SERVER],
            "HP|Hewlett|ProCurve": [DeviceType.SWITCH, DeviceType.PRINTER],
            "Synology": [DeviceType.NAS],
            "QNAP": [DeviceType.NAS],
            "Apple": [DeviceType.WORKSTATION],
            "Intel Corporate": [DeviceType.WORKSTATION],
            "Raspberry": [DeviceType.IOT],
            "Ubiquiti": [DeviceType.ROUTER, DeviceType.SWITCH],
            "MikroTik": [DeviceType.ROUTER],
            "Netgear": [DeviceType.ROUTER, DeviceType.SWITCH],
            "TP-Link": [DeviceType.ROUTER, DeviceType.SWITCH, DeviceType.IOT],
            "VMware": [DeviceType.HYPERVISOR],
            "Microsoft": [DeviceType.WINDOWS_SERVER, DeviceType.WORKSTATION],
        }

    
    def _build_service_hints(self) -> Dict[str, DeviceType]:
        """Build service name to device type hints."""
        return {
            "mysql": DeviceType.DATABASE,
            "mariadb": DeviceType.DATABASE,
            "postgres": DeviceType.DATABASE,
            "postgresql": DeviceType.DATABASE,
            "mongodb": DeviceType.DATABASE,
            "redis": DeviceType.DATABASE,
            "memcached": DeviceType.DATABASE,
            "elasticsearch": DeviceType.DATABASE,
            "couchdb": DeviceType.DATABASE,
            "apache": DeviceType.WEB_SERVER,
            "nginx": DeviceType.WEB_SERVER,
            "httpd": DeviceType.WEB_SERVER,
            "iis": DeviceType.WEB_SERVER,
            "smtp": DeviceType.MAIL_SERVER,
            "postfix": DeviceType.MAIL_SERVER,
            "exchange": DeviceType.MAIL_SERVER,
            "dns": DeviceType.DNS_SERVER,
            "domain": DeviceType.DNS_SERVER,
            "named": DeviceType.DNS_SERVER,
            "ssh": DeviceType.LINUX_SERVER,
            "ms-wbt-server": DeviceType.WINDOWS_SERVER,
            "rdp": DeviceType.WINDOWS_SERVER,
            "vnc": DeviceType.WORKSTATION,
            "plex": DeviceType.MEDIA_SERVER,
            "jellyfin": DeviceType.MEDIA_SERVER,
        }

    def classify_devices(self, devices: List[Dict]) -> List[Dict]:
        """Classify a list of devices.
        
        Args:
            devices: List of device dictionaries
            
        Returns:
            Updated device list with type and confidence fields
        """
        classified = []
        for device in devices:
            classified_device = device.copy()
            device_type, confidence = self._classify_single_device(device)
            classified_device["type"] = device_type.value
            classified_device["confidence"] = confidence
            classified_device["classification_method"] = self._get_classification_method(device, device_type)
            classified.append(classified_device)
            
            logger.debug(
                f"Classified {device.get('ip', 'unknown')} as {device_type.value} "
                f"(confidence: {confidence:.2f})"
            )
            
        return classified

    def _classify_single_device(self, device: Dict) -> Tuple[DeviceType, float]:
        """Classify a single device and return type with confidence.
        
        Args:
            device: Device dictionary
            
        Returns:
            Tuple of (DeviceType, confidence_score)
        """
        # Extract device characteristics
        device_info = self._extract_device_info(device)
        
        # Calculate scores for each device type
        scores = {}
        for device_type, signature in self.signatures.items():
            score = self._calculate_signature_score(device_info, signature)
            if score > 0:
                scores[device_type] = score

        # Apply service hints for quick identification
        for service in device_info.services:
            for hint_service, hint_type in self.service_hints.items():
                if hint_service in service:
                    scores[hint_type] = scores.get(hint_type, 0) + 15

        # Check vendor patterns for additional hints
        if device_info.vendor:
            for pattern, device_types in self.vendor_patterns.items():
                if re.search(pattern, device_info.vendor, re.IGNORECASE):
                    for dtype in device_types:
                        scores[dtype] = scores.get(dtype, 0) + 10
        
        # Special handling for infrastructure devices
        if self._is_infrastructure_device(device_info):
            for infra_type in [DeviceType.ROUTER, DeviceType.SWITCH, DeviceType.FIREWALL]:
                if infra_type in scores:
                    scores[infra_type] += 5

        # Select best match
        if scores:
            best_type, best_score = max(scores.items(), key=lambda x: x[1])
            # Calculate confidence (0-1 scale)
            # Adjusted max score based on typical scoring patterns
            max_possible_score = 50  # More realistic maximum
            confidence = min(best_score / max_possible_score, 1.0)
            
            # Check minimum confidence threshold
            signature = self.signatures.get(best_type)
            if signature and confidence >= signature.min_confidence:
                return best_type, confidence
        
        return DeviceType.UNKNOWN, 0.0

    def _extract_device_info(self, device: Dict) -> 'DeviceInfo':
        """Extract and normalize device information."""
        # Handle None values gracefully
        open_ports = device.get("open_ports") or []
        services = device.get("services") or []
        
        return DeviceInfo(
            ports=set(open_ports) if open_ports else set(),
            services=[s.split(":")[0].lower() for s in services if s],
            os_info=(device.get("os") or "").lower(),
            hostname=(device.get("hostname") or "").lower(),
            vendor=(device.get("vendor") or "").lower(),
            mac=(device.get("mac") or "").upper(),
        )
    
    def _calculate_signature_score(self, device_info: 'DeviceInfo', signature: DeviceSignature) -> float:
        """Calculate how well a device matches a signature."""
        score = 0.0
        
        # Port matching (weighted by priority)
        if signature.ports and device_info.ports:
            matching_ports = device_info.ports.intersection(signature.ports)
            if matching_ports:
                port_weight = 3 * (signature.priority / 100)
                score += len(matching_ports) * port_weight
        
        # Service matching (most reliable indicator)
        if signature.services:
            for service in device_info.services:
                for sig_service in signature.services:
                    if sig_service in service:
                        service_weight = 5 * (signature.priority / 100)
                        score += service_weight
        
        # Keyword matching in OS/hostname/vendor
        if signature.keywords:
            text = f"{device_info.os_info} {device_info.hostname} {device_info.vendor}"
            for keyword in signature.keywords:
                if keyword in text:
                    score += 15  # Increased weight for keyword matches
        
        # Vendor pattern matching
        if signature.vendor_patterns and device_info.vendor:
            for pattern in signature.vendor_patterns:
                if re.search(pattern, device_info.vendor, re.IGNORECASE):
                    score += 10
        
        # Negative scoring for excluded ports
        if signature.exclude_ports:
            if device_info.ports.intersection(signature.exclude_ports):
                score -= 20
        
        # Check max ports constraint
        if signature.max_ports and len(device_info.ports) > signature.max_ports:
            score -= 10
            
        return max(0, score)
    
    def _get_classification_method(self, device: Dict, device_type: DeviceType) -> str:
        """Determine how the device was classified."""
        if device_type == DeviceType.UNKNOWN:
            return "unclassified"
            
        # Check if it was vendor-based
        vendor = device.get("vendor", "").lower()
        for pattern, types in self.vendor_patterns.items():
            if re.search(pattern, vendor, re.IGNORECASE) and device_type in types:
                return "vendor_match"
        
        # Check if it was service-based
        services = [s.split(":")[0].lower() for s in device.get("services", [])]
        for service in services:
            if service in self.service_hints and self.service_hints[service] == device_type:
                return "service_match"
        
        # Otherwise it was signature-based
        return "signature_match"
    
    def _is_infrastructure_device(self, device_info: 'DeviceInfo') -> bool:
        """Check if device appears to be network infrastructure."""
        infra_indicators = {
            "ports": {22, 23, 161, 443},  # SSH, Telnet, SNMP, HTTPS
            "services": ["ssh", "telnet", "snmp", "https"]
        }
        
        # Count infrastructure service indicators
        infra_port_count = len(device_info.ports.intersection(infra_indicators["ports"]))
        infra_service_count = sum(
            1 for s in device_info.services 
            if any(ind in s for ind in infra_indicators["services"])
        )
        
        # Infrastructure devices typically have management services and limited ports
        return (
            (infra_port_count >= 2 or infra_service_count >= 2) and 
            len(device_info.ports) < 20
        )



@dataclass
class DeviceInfo:
    """Normalized device information for classification."""
    ports: Set[int]
    services: List[str]
    os_info: str
    hostname: str
    vendor: str
    mac: str
