"""
Device Classification Module - AI-powered device type identification

This module implements a sophisticated pattern-matching engine that analyzes multiple
device characteristics to determine the most likely device type. The classification
process uses a weighted scoring system based on port signatures, running services,
vendor information, and OS fingerprints.

Key Design Principles:
- Signature-based matching with confidence scoring
- Priority-ordered evaluation (routers before switches, etc.)
- Fallback classification for unknown devices
- Extensible signature system for new device types

The classifier is designed to handle ambiguous cases where devices may match
multiple signatures, using priority and confidence scores to make the best decision.
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

# Configure logging
logger = logging.getLogger(__name__)


class DeviceType(Enum):
    """
    Enumeration of supported device types.

    Each type represents a distinct category of network device with unique
    characteristics and security implications. The order here doesn't affect
    classification priority - that's controlled by DeviceSignature.priority.
    """

    # Network Infrastructure (typically high-priority, critical devices)
    ROUTER = "router"  # Layer 3 routing devices, gateways
    SWITCH = "switch"  # Layer 2 switching devices
    FIREWALL = "firewall"  # Security appliances, UTM devices

    # Server Types (application and service hosts)
    DATABASE = "database"  # MySQL, PostgreSQL, Oracle, etc.
    WEB_SERVER = "web_server"  # Apache, nginx, IIS web servers
    MAIL_SERVER = "mail_server"  # SMTP, POP3, IMAP servers
    DNS_SERVER = "dns_server"  # Domain name resolution servers
    DOMAIN_CONTROLLER = "domain_controller"  # Active Directory, LDAP
    WINDOWS_SERVER = "windows_server"  # General Windows servers
    LINUX_SERVER = "linux_server"  # General Linux servers

    # Specialized Devices
    PRINTER = "printer"  # Network printers, MFPs
    NAS = "nas"  # Network Attached Storage
    HYPERVISOR = "hypervisor"  # VMware, Hyper-V, Proxmox hosts
    WORKSTATION = "workstation"  # End-user computers
    IOT = "iot"  # Internet of Things devices
    VOIP = "voip"  # VoIP phones, PBX systems
    MEDIA_SERVER = "media_server"  # Streaming, media services

    # Industrial/Utility Systems
    UPS = "ups"  # Uninterruptible Power Supplies
    PLC = "plc"  # Programmable Logic Controllers
    SCADA = "scada"  # Supervisory Control systems

    # Support Services
    NTP_SERVER = "ntp_server"  # Time synchronization servers
    MONITORING_SERVER = "monitoring_server"  # Nagios, Zabbix, etc.
    BACKUP_SERVER = "backup_server"  # Backup systems

    # Fallback category
    UNKNOWN = "unknown"  # Unclassified devices


@dataclass
class DeviceSignature:
    """
    Device type signature definition.

    A signature represents the characteristic pattern of a device type,
    used for matching against discovered devices. Higher priority signatures
    are evaluated first, and confidence scores determine match quality.

    Attributes:
        device_type: The DeviceType this signature identifies
        ports: List of characteristic open ports (any match counts)
        services: List of expected service names (any match counts)
        keywords: Keywords to search in hostname, OS, or vendor strings
        exclude_ports: Ports that should NOT be present (e.g., 3389 excludes servers from workstation classification)
        vendor_patterns: List of vendor names that strongly indicate this type
        priority: Higher priority signatures are checked first (0-100)
        max_ports: Maximum number of open ports expected (helps identify simple devices)
        min_confidence: Minimum confidence score required for classification
    """

    device_type: DeviceType
    ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    exclude_ports: List[int] = field(default_factory=list)
    vendor_patterns: List[str] = field(default_factory=list)
    priority: int = 50  # Default middle priority
    max_ports: Optional[int] = None  # No limit by default
    min_confidence: float = 0.3  # 30% minimum confidence required


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
                keywords=[
                    "router",
                    "gateway",
                    "cisco",
                    "juniper",
                    "mikrotik",
                    "fortinet",
                    "pfsense",
                    "edgerouter",
                ],
                vendor_patterns=["Cisco", "Juniper", "MikroTik", "Ubiquiti", "Netgear"],
                priority=90,
            ),
            DeviceType.SWITCH: DeviceSignature(
                device_type=DeviceType.SWITCH,
                ports=[22, 23, 161, 80, 443],
                services=["ssh", "telnet", "snmp", "http", "https"],
                keywords=["switch", "catalyst", "procurve", "powerconnect", "managed", "vlan"],
                vendor_patterns=["Cisco", "HP", "Dell", "Aruba"],
                priority=85,
            ),
            DeviceType.FIREWALL: DeviceSignature(
                device_type=DeviceType.FIREWALL,
                ports=[22, 443, 500, 4500, 1701],  # SSH, HTTPS, VPN ports
                services=["ssh", "https", "isakmp", "ipsec", "l2tp"],
                keywords=[
                    "firewall",
                    "fortigate",
                    "palo alto",
                    "checkpoint",
                    "sonicwall",
                    "asa",
                    "pfsense",
                ],
                vendor_patterns=["Fortinet", "Palo Alto", "Check Point", "SonicWall"],
                priority=88,
            ),
            DeviceType.DATABASE: DeviceSignature(
                device_type=DeviceType.DATABASE,
                ports=[3306, 5432, 1433, 1521, 27017, 6379, 5984, 9200],  # Added Elasticsearch
                services=[
                    "mysql",
                    "postgresql",
                    "ms-sql",
                    "oracle",
                    "mongodb",
                    "redis",
                    "couchdb",
                    "elasticsearch",
                ],
                keywords=[
                    "mysql",
                    "mariadb",
                    "postgres",
                    "oracle",
                    "mongodb",
                    "database",
                    "redis",
                    "nosql",
                ],
                priority=80,
            ),
            DeviceType.WEB_SERVER: DeviceSignature(
                device_type=DeviceType.WEB_SERVER,
                ports=[80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000],
                services=["http", "https", "http-proxy", "http-alt", "webmin", "nginx", "apache"],
                keywords=[
                    "apache",
                    "nginx",
                    "iis",
                    "tomcat",
                    "webserver",
                    "httpd",
                    "node",
                    "express",
                ],
                priority=75,
            ),
            DeviceType.MAIL_SERVER: DeviceSignature(
                device_type=DeviceType.MAIL_SERVER,
                ports=[25, 110, 143, 465, 587, 993, 995],
                services=["smtp", "pop3", "imap", "smtps", "submission", "imaps", "pop3s"],
                keywords=["mail", "exchange", "postfix", "sendmail", "zimbra", "dovecot", "exim"],
                priority=70,
            ),
            DeviceType.DNS_SERVER: DeviceSignature(
                device_type=DeviceType.DNS_SERVER,
                ports=[53],
                services=["dns", "domain"],
                keywords=["bind", "named", "dns", "resolver", "unbound", "powerdns"],
                priority=95,  # DNS is critical infrastructure
            ),
            DeviceType.DOMAIN_CONTROLLER: DeviceSignature(
                device_type=DeviceType.DOMAIN_CONTROLLER,
                ports=[88, 135, 139, 389, 445, 464, 636, 3268],  # Kerberos, LDAP, SMB
                services=["kerberos", "ldap", "ldaps", "msrpc", "netbios", "microsoft-ds"],
                keywords=[
                    "domain controller",
                    "active directory",
                    "ldap",
                    "kerberos",
                    "dc01",
                    "dc02",
                ],
                vendor_patterns=["Microsoft"],
                priority=95,  # Critical infrastructure
            ),
            DeviceType.NTP_SERVER: DeviceSignature(
                device_type=DeviceType.NTP_SERVER,
                ports=[123],
                services=["ntp"],
                keywords=["ntp", "time", "chrony", "ntpd"],
                priority=85,
            ),
            DeviceType.UPS: DeviceSignature(
                device_type=DeviceType.UPS,
                ports=[161, 3493, 80],  # SNMP, NUT, HTTP
                services=["snmp", "nut", "http"],
                keywords=["ups", "apc", "eaton", "power", "battery", "schneider"],
                vendor_patterns=["APC", "Eaton", "Schneider", "CyberPower"],
                priority=80,
            ),
            DeviceType.PLC: DeviceSignature(
                device_type=DeviceType.PLC,
                ports=[502, 2222, 44818, 47808],  # Modbus, EtherNet/IP, BACnet
                services=["modbus", "ethernet-ip", "bacnet"],
                keywords=["plc", "siemens", "allen bradley", "schneider", "omron", "rockwell"],
                vendor_patterns=["Siemens", "Rockwell", "Schneider", "Allen-Bradley"],
                priority=85,
            ),
            DeviceType.SCADA: DeviceSignature(
                device_type=DeviceType.SCADA,
                ports=[502, 20000, 2404, 4911],  # Modbus, DNP3, IEC-104, OPC
                services=["modbus", "dnp3", "iec104", "opc"],
                keywords=["scada", "hmi", "wonderware", "indusoft", "ignition", "wincc"],
                vendor_patterns=["Wonderware", "Indusoft", "Siemens", "GE"],
                priority=90,
            ),
            DeviceType.MONITORING_SERVER: DeviceSignature(
                device_type=DeviceType.MONITORING_SERVER,
                ports=[161, 162, 514, 5666, 9090, 3000],  # SNMP, syslog, NRPE, Prometheus, Grafana
                services=["snmp", "syslog", "nrpe", "prometheus", "grafana"],
                keywords=["nagios", "zabbix", "prometheus", "monitoring", "grafana", "prtg"],
                priority=75,
            ),
            DeviceType.BACKUP_SERVER: DeviceSignature(
                device_type=DeviceType.BACKUP_SERVER,
                ports=[9392, 10050, 3260, 11165],  # Veeam, Bacula, iSCSI, Acronis
                services=["veeam", "bacula", "iscsi", "acronis"],
                keywords=["backup", "veeam", "bacula", "commvault", "acronis", "veritas"],
                vendor_patterns=["Veeam", "Veritas", "Commvault"],
                priority=75,
            ),
            DeviceType.WINDOWS_SERVER: DeviceSignature(
                device_type=DeviceType.WINDOWS_SERVER,
                ports=[135, 139, 445, 3389, 88, 389, 636],  # RPC, SMB, RDP, Kerberos, LDAP
                services=[
                    "msrpc",
                    "netbios",
                    "microsoft-ds",
                    "ms-wbt-server",
                    "kerberos",
                    "ldap",
                    "ldaps",
                ],
                keywords=[
                    "windows",
                    "microsoft",
                    "active directory",
                    "domain controller",
                    "server",
                ],
                vendor_patterns=["Microsoft"],
                priority=65,
            ),
            DeviceType.LINUX_SERVER: DeviceSignature(
                device_type=DeviceType.LINUX_SERVER,
                ports=[22, 111, 2049],  # SSH, RPC, NFS
                services=["ssh", "rpcbind", "nfs"],
                keywords=["linux", "ubuntu", "centos", "debian", "redhat", "suse", "fedora"],
                exclude_ports=[139, 445, 3389],  # No Windows services
                priority=60,
            ),
            DeviceType.PRINTER: DeviceSignature(
                device_type=DeviceType.PRINTER,
                ports=[515, 631, 9100, 80, 443],
                services=["lpd", "ipp", "jetdirect", "http", "https"],
                keywords=[
                    "printer",
                    "print",
                    "cups",
                    "hp",
                    "canon",
                    "epson",
                    "brother",
                    "xerox",
                    "laserjet",
                ],
                vendor_patterns=["HP", "Canon", "Epson", "Brother", "Xerox"],
                priority=50,
            ),
            DeviceType.NAS: DeviceSignature(
                device_type=DeviceType.NAS,
                ports=[139, 445, 548, 2049, 873, 5000, 5001],  # SMB, AFP, NFS, rsync, Synology
                services=["netbios", "microsoft-ds", "afp", "nfs", "rsync", "http", "https"],
                keywords=[
                    "nas",
                    "synology",
                    "qnap",
                    "freenas",
                    "truenas",
                    "storage",
                    "openmediavault",
                ],
                vendor_patterns=["Synology", "QNAP", "Western Digital", "Netgear"],
                priority=70,
            ),
            DeviceType.HYPERVISOR: DeviceSignature(
                device_type=DeviceType.HYPERVISOR,
                ports=[443, 902, 5900, 8006],  # vSphere, Proxmox VNC
                services=["https", "vmware", "vnc", "proxmox"],
                keywords=[
                    "vmware",
                    "esxi",
                    "vsphere",
                    "proxmox",
                    "hyper-v",
                    "xenserver",
                    "kvm",
                    "virtualbox",
                ],
                vendor_patterns=["VMware", "Proxmox", "Citrix"],
                priority=85,
            ),
            DeviceType.WORKSTATION: DeviceSignature(
                device_type=DeviceType.WORKSTATION,
                ports=[135, 139, 445, 3389, 5900],  # Windows/VNC
                services=["netbios", "microsoft-ds", "ms-wbt-server", "vnc"],
                keywords=["workstation", "desktop", "windows 10", "windows 11", "macbook", "imac"],
                vendor_patterns=["Apple", "Dell", "HP", "Lenovo"],
                max_ports=15,
                priority=40,
            ),
            DeviceType.IOT: DeviceSignature(
                device_type=DeviceType.IOT,
                ports=[80, 443, 8080, 1883, 8883, 5683, 1900, 502, 554],  # Added Modbus, RTSP
                services=["http", "https", "mqtt", "coap", "upnp", "modbus", "rtsp"],
                keywords=[
                    "camera",
                    "sensor",
                    "iot",
                    "smart",
                    "esp",
                    "arduino",
                    "tasmota",
                    "zigbee",
                    "hue",
                    "hvac",
                    "thermostat",
                    "security",
                ],
                vendor_patterns=[
                    "Espressif",
                    "Raspberry",
                    "Arduino",
                    "Tuya",
                    "Philips",
                    "Honeywell",
                    "Hikvision",
                ],
                priority=30,
            ),
            DeviceType.VOIP: DeviceSignature(
                device_type=DeviceType.VOIP,
                ports=[5060, 5061, 5004, 5005, 2000, 4569],  # SIP, RTP, Asterisk
                services=["sip", "sips", "rtp", "asterisk", "iax"],
                keywords=["voip", "asterisk", "3cx", "phone", "pbx", "sip", "cisco phone"],
                vendor_patterns=["Cisco", "Polycom", "Yealink", "Grandstream"],
                priority=55,
            ),
            DeviceType.MEDIA_SERVER: DeviceSignature(
                device_type=DeviceType.MEDIA_SERVER,
                ports=[8096, 32400, 8200, 554],  # Jellyfin, Plex, RTSP
                services=["http", "plex", "jellyfin", "rtsp", "dlna"],
                keywords=["plex", "jellyfin", "emby", "kodi", "media", "streaming"],
                priority=45,
            ),
        }

    def _build_vendor_patterns(self) -> Dict[str, List[DeviceType]]:
        """Build vendor to device type mapping."""
        return {
            "Cisco": [DeviceType.ROUTER, DeviceType.SWITCH, DeviceType.VOIP],
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
            "Netgear": [DeviceType.ROUTER, DeviceType.SWITCH, DeviceType.NAS],
            "TP-Link": [DeviceType.ROUTER, DeviceType.SWITCH, DeviceType.IOT],
            "VMware": [DeviceType.HYPERVISOR],
            "Microsoft": [
                DeviceType.WINDOWS_SERVER,
                DeviceType.WORKSTATION,
                DeviceType.DOMAIN_CONTROLLER,
            ],
            "APC|Schneider": [DeviceType.UPS],
            "Eaton": [DeviceType.UPS],
            "Siemens": [DeviceType.PLC, DeviceType.SCADA],
            "Rockwell|Allen-Bradley": [DeviceType.PLC],
            "Wonderware": [DeviceType.SCADA],
            "Veeam": [DeviceType.BACKUP_SERVER],
            "Veritas": [DeviceType.BACKUP_SERVER],
            "Hikvision|Dahua": [DeviceType.IOT],
            "Polycom|Yealink": [DeviceType.VOIP],
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
        """
        Classify a list of devices based on their network characteristics.

        This is the main entry point for device classification. Each device is
        analyzed independently using signature matching, and the results include
        both the device type and a confidence score.

        The classification process:
        1. Extract device characteristics (ports, services, OS, vendor)
        2. Score against all signatures
        3. Apply service hints for quick wins
        4. Select highest scoring classification
        5. Add metadata about classification method

        Args:
            devices: List of device dictionaries from scanner containing:
                - ip: IP address
                - open_ports: List of open port numbers
                - services: List of service names
                - os: Operating system string (optional)
                - vendor: Vendor from MAC lookup (optional)
                - hostname: Device hostname (optional)

        Returns:
            Updated device list with additional fields:
                - type: Device type string (e.g., "router", "web_server")
                - confidence: Classification confidence (0.0-1.0)
                - classification_method: How the device was classified
        """
        classified = []
        for device in devices:
            # Create a copy to avoid modifying the original
            classified_device = device.copy()

            # Perform classification
            device_type, confidence = self._classify_single_device(device)

            # Add classification results
            classified_device["type"] = device_type.value
            classified_device["confidence"] = confidence
            classified_device["classification_method"] = self._get_classification_method(
                device, device_type
            )
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

    def _extract_device_info(self, device: Dict) -> "DeviceInfo":
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

    def _calculate_signature_score(
        self, device_info: "DeviceInfo", signature: DeviceSignature
    ) -> float:
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

    def _is_infrastructure_device(self, device_info: "DeviceInfo") -> bool:
        """Check if device appears to be network infrastructure."""
        infra_indicators = {
            "ports": {22, 23, 161, 443},  # SSH, Telnet, SNMP, HTTPS
            "services": ["ssh", "telnet", "snmp", "https"],
        }

        # Count infrastructure service indicators
        infra_port_count = len(device_info.ports.intersection(infra_indicators["ports"]))
        infra_service_count = sum(
            1 for s in device_info.services if any(ind in s for ind in infra_indicators["services"])
        )

        # Infrastructure devices typically have management services and limited ports
        return (infra_port_count >= 2 or infra_service_count >= 2) and len(device_info.ports) < 20


@dataclass
class DeviceInfo:
    """Normalized device information for classification."""

    ports: Set[int]
    services: List[str]
    os_info: str
    hostname: str
    vendor: str
    mac: str
