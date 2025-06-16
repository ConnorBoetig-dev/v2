"""
Device data model representing a discovered network device.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from datetime import datetime
from enum import Enum


class DeviceType(Enum):
    """Enumeration of device types."""
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    SERVER = "server"
    WORKSTATION = "workstation"
    PRINTER = "printer"
    STORAGE = "storage"
    WIRELESS_AP = "wireless_ap"
    VOIP_PHONE = "voip_phone"
    CAMERA = "camera"
    IOT_DEVICE = "iot_device"
    MOBILE = "mobile"
    VIRTUAL_MACHINE = "virtual_machine"
    LOAD_BALANCER = "load_balancer"
    DATABASE = "database"
    WEB_SERVER = "web_server"
    UNKNOWN = "unknown"


class DeviceStatus(Enum):
    """Device status enumeration."""
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"
    FILTERED = "filtered"


@dataclass
class Port:
    """Represents an open port on a device."""
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None
    extra_info: Optional[str] = None
    scripts: Dict[str, str] = field(default_factory=dict)


@dataclass
class NetworkInterface:
    """Represents a network interface."""
    name: str
    mac_address: Optional[str] = None
    ip_addresses: List[str] = field(default_factory=list)
    status: str = "up"
    speed: Optional[int] = None
    mtu: Optional[int] = None


@dataclass
class Vulnerability:
    """Represents a security vulnerability."""
    cve_id: str
    severity: str
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    affected_service: Optional[str] = None
    affected_version: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class Device:
    """
    Comprehensive device model with all discovered information.
    
    This model serves as the central data structure for representing
    network devices throughout the application.
    """
    # Core identification
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    
    # Device characteristics
    device_type: DeviceType = DeviceType.UNKNOWN
    os: Optional[str] = None
    os_accuracy: Optional[int] = None
    status: DeviceStatus = DeviceStatus.UNKNOWN
    
    # Network information
    open_ports: List[Port] = field(default_factory=list)
    interfaces: List[NetworkInterface] = field(default_factory=list)
    
    # Enrichment data
    snmp_info: Dict[str, Any] = field(default_factory=dict)
    dns_names: List[str] = field(default_factory=list)
    
    # Security information
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    risk_score: Optional[float] = None
    
    # Metadata
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    scan_id: Optional[str] = None
    
    # User annotations
    notes: Optional[str] = None
    tags: Set[str] = field(default_factory=set)
    is_critical: bool = False
    location: Optional[str] = None
    owner: Optional[str] = None
    
    def get_service_names(self) -> List[str]:
        """Get list of unique service names."""
        return list({p.service for p in self.open_ports if p.service})
    
    def get_open_port_numbers(self) -> List[int]:
        """Get list of open port numbers."""
        return sorted([p.number for p in self.open_ports])
    
    def has_vulnerability(self, severity: str = None) -> bool:
        """Check if device has vulnerabilities, optionally filtered by severity."""
        if severity:
            return any(v.severity.lower() == severity.lower() 
                      for v in self.vulnerabilities)
        return len(self.vulnerabilities) > 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert device to dictionary for serialization."""
        return {
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'mac_address': self.mac_address,
            'vendor': self.vendor,
            'device_type': self.device_type.value,
            'os': self.os,
            'os_accuracy': self.os_accuracy,
            'status': self.status.value,
            'open_ports': [
                {
                    'number': p.number,
                    'protocol': p.protocol,
                    'state': p.state,
                    'service': p.service,
                    'version': p.version,
                    'product': p.product
                } for p in self.open_ports
            ],
            'vulnerabilities': [
                {
                    'cve_id': v.cve_id,
                    'severity': v.severity,
                    'cvss_score': v.cvss_score,
                    'description': v.description
                } for v in self.vulnerabilities
            ],
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'last_updated': self.last_updated.isoformat(),
            'notes': self.notes,
            'tags': list(self.tags),
            'is_critical': self.is_critical,
            'risk_score': self.risk_score
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Device':
        """Create Device instance from dictionary."""
        device = cls(
            ip_address=data['ip_address'],
            hostname=data.get('hostname'),
            mac_address=data.get('mac_address'),
            vendor=data.get('vendor'),
            device_type=DeviceType(data.get('device_type', 'unknown')),
            os=data.get('os'),
            os_accuracy=data.get('os_accuracy'),
            status=DeviceStatus(data.get('status', 'unknown'))
        )
        
        # Restore ports
        for port_data in data.get('open_ports', []):
            device.open_ports.append(Port(
                number=port_data['number'],
                protocol=port_data.get('protocol', 'tcp'),
                state=port_data.get('state', 'open'),
                service=port_data.get('service'),
                version=port_data.get('version'),
                product=port_data.get('product')
            ))
        
        # Restore vulnerabilities
        for vuln_data in data.get('vulnerabilities', []):
            device.vulnerabilities.append(Vulnerability(
                cve_id=vuln_data['cve_id'],
                severity=vuln_data['severity'],
                cvss_score=vuln_data.get('cvss_score'),
                description=vuln_data.get('description')
            ))
        
        # Restore metadata
        if 'first_seen' in data:
            device.first_seen = datetime.fromisoformat(data['first_seen'])
        if 'last_seen' in data:
            device.last_seen = datetime.fromisoformat(data['last_seen'])
        if 'last_updated' in data:
            device.last_updated = datetime.fromisoformat(data['last_updated'])
        
        # Restore annotations
        device.notes = data.get('notes')
        device.tags = set(data.get('tags', []))
        device.is_critical = data.get('is_critical', False)
        device.risk_score = data.get('risk_score')
        
        return device