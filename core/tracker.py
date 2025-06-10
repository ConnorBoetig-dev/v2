"""Change tracking module for monitoring network modifications.

This module compares scan results over time to detect:
- New devices appearing on the network
- Devices that have gone offline
- Changes in device services, ports, or characteristics
"""

import hashlib
import json
from dataclasses import dataclass, field
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)


class ChangeType(Enum):
    """Types of changes that can be detected."""
    NEW_DEVICE = "new_device"
    MISSING_DEVICE = "missing_device"
    MODIFIED_DEVICE = "modified_device"
    NEW_SERVICE = "new_service"
    REMOVED_SERVICE = "removed_service"
    NEW_PORT = "new_port"
    CLOSED_PORT = "closed_port"
    OS_CHANGE = "os_change"
    TYPE_CHANGE = "type_change"
    HOSTNAME_CHANGE = "hostname_change"
    VENDOR_CHANGE = "vendor_change"


@dataclass
class DeviceChange:
    """Represents a change in a device."""
    ip: str
    change_type: ChangeType
    change_field: str = ""
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    severity: str = "info"  # info, warning, critical
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "ip": self.ip,
            "change_type": self.change_type.value,
            "change_field": self.change_field,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "timestamp": self.timestamp,
            "severity": self.severity,
        }


@dataclass
class ChangeReport:
    """Complete change report between two scans."""
    new_devices: List[Dict] = field(default_factory=list)
    missing_devices: List[Dict] = field(default_factory=list)
    changed_devices: List[Dict] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)
    scan_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    previous_scan_time: Optional[str] = None
    current_scan_time: Optional[str] = None
    
    def has_changes(self) -> bool:
        """Check if any changes were detected."""
        return bool(self.new_devices or self.missing_devices or self.changed_devices)
    
    def get_severity(self) -> str:
        """Determine overall severity of changes."""
        if self.missing_devices or any(
            change.get("critical") for change in self.new_devices + self.changed_devices
        ):
            return "critical"
        elif self.new_devices or self.changed_devices:
            return "warning"
        return "info"


class ChangeTracker:
    """Tracks changes between network scans."""
    
    def __init__(self, output_path: Path = Path("output")):
        """Initialize change tracker.
        
        Args:
            output_path: Base output directory path
        """
        self.output_path = output_path
        self.scans_path = output_path / "scans"
        self.changes_path = output_path / "changes"
        self.changes_path.mkdir(exist_ok=True)
        
        # Cache for performance
        self._fingerprint_cache = {}

    def detect_changes(self, current_devices: List[Dict]) -> Dict:
        """Compare current scan with previous scan.
        
        Args:
            current_devices: List of devices from current scan
            
        Returns:
            Dictionary containing detected changes
        """
        # Get most recent previous scan
        previous_scan_data = self._get_previous_scan()
        if not previous_scan_data:
            logger.info("No previous scan found for comparison")
            return {}
            
        previous_devices, previous_timestamp = previous_scan_data
        
        # Create lookup maps
        current_map = {d["ip"]: d for d in current_devices}
        previous_map = {d["ip"]: d for d in previous_devices}
        
        # Initialize change report
        report = ChangeReport(
            previous_scan_time=previous_timestamp,
            current_scan_time=datetime.now().isoformat(),
            summary={
                "total_current": len(current_devices),
                "total_previous": len(previous_devices),
                "timestamp": datetime.now().isoformat(),
            }
        )

        # Find new devices
        new_ips = set(current_map.keys()) - set(previous_map.keys())
        for ip in new_ips:
            device = current_map[ip].copy()
            device["change_type"] = "new"
            report.new_devices.append(device)
            logger.info(f"New device detected: {ip}")
            
        # Find missing devices
        missing_ips = set(previous_map.keys()) - set(current_map.keys())
        for ip in missing_ips:
            device = previous_map[ip].copy()
            device["change_type"] = "missing"
            report.missing_devices.append(device)
            logger.warning(f"Device went offline: {ip}")
            
        # Find changed devices
        common_ips = set(current_map.keys()) & set(previous_map.keys())
        for ip in common_ips:
            changes = self._compare_devices(current_map[ip], previous_map[ip])
            if changes:
                change_record = {
                    "ip": ip,
                    "hostname": current_map[ip].get("hostname", ""),
                    "type": current_map[ip].get("type", "unknown"),
                    "vendor": current_map[ip].get("vendor", ""),
                    "changes": changes,
                    "change_type": "modified",
                    "severity": self._calculate_change_severity(changes),
                }
                report.changed_devices.append(change_record)
                logger.info(f"Device changed: {ip} - {len(changes)} changes")
                
        # Update summary
        report.summary.update({
            "new_devices_count": len(report.new_devices),
            "missing_devices_count": len(report.missing_devices),
            "changed_devices_count": len(report.changed_devices),
            "total_changes": len(report.new_devices) + len(report.missing_devices) + len(report.changed_devices),
            "severity": report.get_severity(),
        })
        
        # Convert to dict for compatibility
        return {
            "new_devices": report.new_devices,
            "missing_devices": report.missing_devices,
            "changed_devices": report.changed_devices,
            "summary": report.summary,
        }

    def _get_previous_scan(self) -> Optional[Tuple[List[Dict], str]]:
        """Get the most recent previous scan.
        
        Returns:
            Tuple of (devices, timestamp) or None
        """
        scan_files = sorted(self.scans_path.glob("scan_*.json"))
        if len(scan_files) < 2:
            return None
            
        # Get second most recent (most recent is current)
        previous_file = scan_files[-2]
        
        try:
            with open(previous_file) as f:
                devices = json.load(f)
                
            # Extract timestamp from filename
            timestamp_str = previous_file.stem.replace("scan_", "")
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S").isoformat()
            except ValueError:
                timestamp = timestamp_str
                
            return devices, timestamp
            
        except Exception as e:
            logger.error(f"Failed to load previous scan: {e}")
            return None

    def _compare_devices(self, current: Dict, previous: Dict) -> List[Dict]:
        """Compare two device records for changes.
        
        Args:
            current: Current device state
            previous: Previous device state
            
        Returns:
            List of detected changes
        """
        changes = []
        
        # Check services
        curr_services = set(current.get("services", []))
        prev_services = set(previous.get("services", []))
        
        new_services = curr_services - prev_services
        if new_services:
            changes.append({
                "field": "services",
                "action": "added",
                "values": sorted(list(new_services)),
                "severity": "warning"
            })
            
        removed_services = prev_services - curr_services
        if removed_services:
            changes.append({
                "field": "services",
                "action": "removed",
                "values": sorted(list(removed_services)),
                "severity": "warning"
            })
            
        # Check ports
        curr_ports = set(current.get("open_ports", []))
        prev_ports = set(previous.get("open_ports", []))
        
        new_ports = curr_ports - prev_ports
        if new_ports:
            # Check for potentially dangerous ports
            dangerous_ports = self._check_dangerous_ports(new_ports)
            severity = "critical" if dangerous_ports else "warning"
            changes.append({
                "field": "ports",
                "action": "opened",
                "values": sorted(list(new_ports)),
                "severity": severity,
                "dangerous_ports": dangerous_ports
            })
            
        closed_ports = prev_ports - curr_ports
        if closed_ports:
            changes.append({
                "field": "ports",
                "action": "closed",
                "values": sorted(list(closed_ports)),
                "severity": "info"
            })
            
        # Check other fields with appropriate severity
        field_config = {
            "hostname": {"severity": "info"},
            "os": {"severity": "warning"},
            "type": {"severity": "warning"},
            "vendor": {"severity": "info"},
            "mac": {"severity": "critical"},  # MAC change could indicate spoofing
        }
        
        for field, config in field_config.items():
            curr_val = current.get(field, "")
            prev_val = previous.get(field, "")
            
            if curr_val != prev_val:
                changes.append({
                    "field": field,
                    "action": "changed",
                    "old_value": prev_val,
                    "new_value": curr_val,
                    "severity": config["severity"]
                })
                
        return changes

    def _generate_fingerprint(self, device: Dict) -> str:
        """Generate unique fingerprint for device state.
        
        Args:
            device: Device dictionary
            
        Returns:
            MD5 hash fingerprint
        """
        # Use cached fingerprint if available
        cache_key = device.get("ip", "")
        if cache_key in self._fingerprint_cache:
            cached_data = self._fingerprint_cache[cache_key]
            if cached_data["device"] == device:
                return cached_data["fingerprint"]
                
        # Create stable string representation
        data = {
            "mac": device.get("mac", ""),
            "ports": sorted(device.get("open_ports", [])),
            "services": sorted(device.get("services", [])),
            "os": device.get("os", ""),
            "type": device.get("type", ""),
            "vendor": device.get("vendor", ""),
        }
        
        json_str = json.dumps(data, sort_keys=True)
        fingerprint = hashlib.md5(json_str.encode()).hexdigest()
        
        # Cache the result
        if cache_key:
            self._fingerprint_cache[cache_key] = {
                "device": device.copy(),
                "fingerprint": fingerprint
            }
            
        return fingerprint
    
    def _check_dangerous_ports(self, ports: Set[int]) -> List[int]:
        """Check for potentially dangerous open ports.
        
        Args:
            ports: Set of port numbers
            
        Returns:
            List of dangerous ports found
        """
        # Common dangerous/sensitive ports
        dangerous_ports = {
            21: "FTP",
            23: "Telnet",
            135: "RPC",
            139: "NetBIOS",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            27017: "MongoDB",
        }
        
        found = []
        for port in ports:
            if port in dangerous_ports:
                found.append(port)
                logger.warning(f"Dangerous port opened: {port} ({dangerous_ports[port]})")
                
        return found
    
    def _calculate_change_severity(self, changes: List[Dict]) -> str:
        """Calculate overall severity of device changes.
        
        Args:
            changes: List of change records
            
        Returns:
            Severity level (info, warning, critical)
        """
        severities = [change.get("severity", "info") for change in changes]
        
        if "critical" in severities:
            return "critical"
        elif "warning" in severities:
            return "warning"
        return "info"
    
    def save_change_report(self, changes: Dict, timestamp: str) -> Optional[Path]:
        """Save change report to file.
        
        Args:
            changes: Change report dictionary
            timestamp: Timestamp for filename
            
        Returns:
            Path to saved file or None
        """
        if not changes:
            return None
            
        try:
            report_file = self.changes_path / f"changes_{timestamp}.json"
            with open(report_file, "w") as f:
                json.dump(changes, f, indent=2)
                
            logger.info(f"Saved change report to {report_file}")
            return report_file
            
        except Exception as e:
            logger.error(f"Failed to save change report: {e}")
            return None
