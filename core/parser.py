"""Scan result parser module for normalizing scanner outputs.

This module takes raw output from various scanners (nmap, masscan, arp-scan)
and converts them into a standardized device format.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict

from utils.mac_lookup import MACLookup

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class Device:
    """Standardized device representation."""
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    type: str = "unknown"
    os: str = ""
    os_accuracy: int = 0
    services: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    critical: bool = False
    confidence: float = 0.0
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    scan_time: str = field(default_factory=lambda: datetime.now().isoformat())
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    location: str = ""
    owner: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert device to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Device':
        """Create device from dictionary."""
        # Filter out unknown fields
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)


class ScanParser:
    """Parser for various network scanner outputs."""
    
    def __init__(self, mac_lookup: Optional[MACLookup] = None):
        """Initialize parser with optional MAC lookup.
        
        Args:
            mac_lookup: MACLookup instance for vendor resolution
        """
        self.mac_lookup = mac_lookup or MACLookup()
        
        # Parser registry
        self.parsers = {
            "nmap": self._parse_nmap_results,
            "masscan": self._parse_masscan_results,
            "arp-scan": self._parse_arp_results,
        }

    def parse_results(self, raw_results: Any, scanner_type: Optional[str] = None) -> List[Dict]:
        """Parse scan results into standardized format.
        
        Args:
            raw_results: Raw scanner output (format varies by scanner)
            scanner_type: Optional scanner type hint
            
        Returns:
            List of standardized device dictionaries
        """
        if not raw_results:
            logger.warning("Empty scan results provided")
            return []
            
        devices = []
        
        try:
            # Determine parser based on result format or hint
            if scanner_type and scanner_type in self.parsers:
                parser = self.parsers[scanner_type]
                devices = parser(raw_results)
            elif isinstance(raw_results, list):
                # Auto-detect format
                devices = self._auto_parse(raw_results)
            else:
                logger.error(f"Unknown result format: {type(raw_results)}")
                return []
                
            # Standardize and enrich all devices
            devices = self._standardize_devices(devices)
            devices = self.mac_lookup.enrich_with_arp_cache(devices)
            
            logger.info(f"Parsed {len(devices)} devices from scan results")
            return devices
            
        except Exception as e:
            logger.error(f"Failed to parse scan results: {e}")
            return []

    def _auto_parse(self, raw_results: List[Any]) -> List[Dict]:
        """Auto-detect scanner format and parse.
        
        Args:
            raw_results: List of scan results
            
        Returns:
            Parsed devices
        """
        if not raw_results:
            return []
            
        # Check first result to determine format
        first = raw_results[0]
        
        if isinstance(first, dict):
            if "ip" in first and "services" in first:
                # Likely nmap format
                logger.debug("Auto-detected nmap format")
                return self._parse_nmap_results(raw_results)
            elif "ip" in first or "ports" in first:
                # Likely masscan format
                logger.debug("Auto-detected masscan format")
                return self._parse_masscan_results(raw_results)
                
        logger.warning("Could not auto-detect scan format")
        return []

    def _standardize_devices(self, devices: List[Any]) -> List[Dict]:
        """Ensure all devices follow standard format.
        
        Args:
            devices: List of device data (dicts or Device objects)
            
        Returns:
            List of standardized device dictionaries
        """
        standardized = []
        
        for device_data in devices:
            try:
                # Convert to Device object if needed
                if isinstance(device_data, dict):
                    device = Device.from_dict(device_data)
                elif isinstance(device_data, Device):
                    device = device_data
                else:
                    logger.warning(f"Skipping invalid device data: {type(device_data)}")
                    continue
                    
                # Validate required fields
                if not device.ip:
                    logger.warning("Device missing IP address, skipping")
                    continue
                    
                # Normalize MAC address
                if device.mac:
                    device.mac = device.mac.upper()
                    
                # Ensure services are properly formatted
                normalized_services = []
                for service in device.services:
                    if isinstance(service, int):
                        # Convert port number to service string
                        normalized_services.append(f"unknown:{service}")
                    elif ":" not in str(service):
                        # Add port if missing
                        normalized_services.append(f"{service}:unknown")
                    else:
                        normalized_services.append(str(service))
                device.services = normalized_services
                
                # Enrich with vendor info if MAC exists but vendor missing
                if device.mac and not device.vendor:
                    vendor = self.mac_lookup.lookup(device.mac)
                    if vendor:
                        device.vendor = vendor
                        logger.debug(f"Enriched {device.ip} with vendor: {vendor}")
                        
                # Convert back to dict
                standardized.append(device.to_dict())
                
            except Exception as e:
                logger.error(f"Error standardizing device: {e}")
                continue
                
        return standardized

    def _parse_nmap_results(self, results: List[Dict]) -> List[Dict]:
        """Parse nmap-specific results.
        
        Args:
            results: Nmap scan results (already parsed from XML)
            
        Returns:
            List of device dictionaries
        """
        # Nmap results are already parsed by the scanner
        # Just ensure they're in the right format
        devices = []
        for result in results:
            if isinstance(result, dict) and result.get("ip"):
                devices.append(result)
            else:
                logger.warning(f"Invalid nmap result format: {result}")
                
        return devices

    def _parse_masscan_results(self, results: List[Dict]) -> List[Dict]:
        """Parse masscan JSON results.
        
        Args:
            results: Masscan results (JSON format)
            
        Returns:
            List of device dictionaries
        """
        devices = {}
        
        for entry in results:
            if not isinstance(entry, dict):
                continue
                
            ip = entry.get("ip")
            if not ip:
                continue
                
            # Create or update device entry
            if ip not in devices:
                devices[ip] = Device(ip=ip)
                
            # Add port information if available
            if "ports" in entry:
                for port_info in entry["ports"]:
                    port = port_info.get("port", 0)
                    proto = port_info.get("proto", "tcp")
                    state = port_info.get("state", "open")
                    
                    if port and state == "open":
                        if port not in devices[ip].open_ports:
                            devices[ip].open_ports.append(port)
                            
                        # Try to determine service name
                        service = port_info.get("service", {}).get("name", "unknown")
                        service_str = f"{service}:{port}/{proto}"
                        if service_str not in devices[ip].services:
                            devices[ip].services.append(service_str)
                            
            # Add timestamp if available
            if "timestamp" in entry:
                devices[ip].scan_time = entry["timestamp"]
                
        # Convert devices to list of dicts
        return [device.to_dict() for device in devices.values()]
    
    def _parse_arp_results(self, results: List[Dict]) -> List[Dict]:
        """Parse arp-scan results.
        
        Args:
            results: ARP scan results
            
        Returns:
            List of device dictionaries
        """
        devices = []
        
        for entry in results:
            if isinstance(entry, dict) and entry.get("ip"):
                # ARP results typically have IP, MAC, and vendor
                device = Device(
                    ip=entry["ip"],
                    mac=entry.get("mac", "").upper(),
                    vendor=entry.get("vendor", ""),
                    hostname=entry.get("hostname", ""),
                )
                devices.append(device.to_dict())
                
        return devices
