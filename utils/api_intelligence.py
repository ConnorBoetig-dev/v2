"""
API Intelligence Layer for NetworkMapper v2

This module provides intelligent device and service identification using
free APIs and databases with caching, rate limiting, and offline fallbacks.
"""

import json
import logging
import sqlite3
import time
import requests
import os
from pathlib import Path
from typing import Dict, Optional, List, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
import csv
import hashlib

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class DeviceIntelligence:
    """Device intelligence from API sources"""
    mac_vendor: str = ""
    device_type: str = ""
    os_guess: str = ""
    services: List[str] = None
    confidence: float = 0.0
    sources: List[str] = None
    last_updated: datetime = None
    data_sources: Dict[str, str] = None  # Track specific source of each data point

    def __post_init__(self):
        if self.services is None:
            self.services = []
        if self.sources is None:
            self.sources = []
        if self.last_updated is None:
            self.last_updated = datetime.now()
        if self.data_sources is None:
            self.data_sources = {}

    def to_dict(self) -> Dict:
        return {
            "mac_vendor": self.mac_vendor,
            "device_type": self.device_type,
            "os_guess": self.os_guess,
            "services": self.services,
            "confidence": self.confidence,
            "sources": self.sources,
            "last_updated": self.last_updated.isoformat(),
            "data_sources": self.data_sources
        }


class APIIntelligenceLayer:
    """Enhanced device identification using free APIs and databases"""

    def __init__(self, cache_dir: Path = Path("cache")):
        """Initialize API intelligence layer
        
        Args:
            cache_dir: Directory for caching databases and API responses
        """
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(exist_ok=True)
        
        # Database connections
        self.cache_db = cache_dir / "api_cache.db"
        self.conn = None
        
        # Rate limiting (requests per second)
        self.rate_limits = {
            "macvendorlookup": 2,  # macvendorlookup.com
            "maclookup": 5,        # maclookup.app
            "ipapi": 15,           # ip-api.com
        }
        
        # Last request timestamps
        self.last_requests = {api: 0 for api in self.rate_limits}
        
        # Initialize databases
        self._init_cache_db()
        self._download_vendor_db()
        self._download_iana_ports()
        
        # Load local databases
        self.iana_ports = self._load_iana_ports()
        self.device_signatures = self._load_device_signatures()

    def _init_cache_db(self):
        """Initialize SQLite cache database"""
        self.conn = sqlite3.connect(self.cache_db)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS mac_vendors (
                mac_prefix TEXT PRIMARY KEY,
                vendor TEXT,
                timestamp INTEGER
            )
        """)
        
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS device_intel (
                device_key TEXT PRIMARY KEY,
                intelligence TEXT,
                timestamp INTEGER
            )
        """)
        
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS api_responses (
                api_key TEXT PRIMARY KEY,
                response TEXT,
                timestamp INTEGER,
                expires INTEGER
            )
        """)
        
        self.conn.commit()

    def _download_vendor_db(self):
        """Download and cache MAC vendor database"""
        vendor_file = self.cache_dir / "mac_vendors.csv"
        
        # Check if we have a recent copy
        if vendor_file.exists():
            age = datetime.now() - datetime.fromtimestamp(vendor_file.stat().st_mtime)
            if age < timedelta(days=30):
                return
        
        logger.info("Downloading MAC vendor database...")
        try:
            # Download from Wireshark's repository
            url = "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # Parse and save as CSV
            with open(vendor_file, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['mac_prefix', 'vendor', 'description'])
                
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            mac_prefix = parts[0].replace(':', '').upper()
                            vendor = parts[1]
                            description = parts[2] if len(parts) > 2 else ""
                            writer.writerow([mac_prefix, vendor, description])
            
            logger.info(f"Downloaded MAC vendor database to {vendor_file}")
            
        except Exception as e:
            logger.warning(f"Failed to download MAC vendor database: {e}")

    def _download_iana_ports(self):
        """Download and cache IANA port assignments"""
        ports_file = self.cache_dir / "iana_ports.json"
        
        # Check if we have a recent copy
        if ports_file.exists():
            age = datetime.now() - datetime.fromtimestamp(ports_file.stat().st_mtime)
            if age < timedelta(days=90):
                return
        
        logger.info("Downloading IANA port assignments...")
        try:
            # Download from IANA
            url = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            # Parse CSV and create JSON
            ports_data = {}
            csv_reader = csv.DictReader(response.text.split('\n'))
            
            for row in csv_reader:
                port = row.get('Port Number', '').strip()
                service = row.get('Service Name', '').strip()
                description = row.get('Description', '').strip()
                protocol = row.get('Transport Protocol', '').strip()
                
                if port and service and protocol:
                    # Handle port ranges (e.g., "80-90")
                    if '-' in port:
                        try:
                            start, end = map(int, port.split('-'))
                            for p in range(start, end + 1):
                                ports_data[str(p)] = {
                                    'service': service,
                                    'description': description,
                                    'protocol': protocol.upper()
                                }
                        except ValueError:
                            continue
                    else:
                        try:
                            port_num = int(port)
                            ports_data[str(port_num)] = {
                                'service': service,
                                'description': description,
                                'protocol': protocol.upper()
                            }
                        except ValueError:
                            continue
            
            # Save as JSON
            with open(ports_file, 'w') as f:
                json.dump(ports_data, f, indent=2)
            
            logger.info(f"Downloaded IANA port database to {ports_file}")
            
        except Exception as e:
            logger.warning(f"Failed to download IANA port database: {e}")

    def _load_iana_ports(self) -> Dict:
        """Load IANA port assignments"""
        ports_file = self.cache_dir / "iana_ports.json"
        
        if ports_file.exists():
            try:
                with open(ports_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load IANA ports: {e}")
        
        # Fallback to basic port mapping
        return {
            "21": {"service": "ftp", "description": "File Transfer Protocol", "protocol": "TCP"},
            "22": {"service": "ssh", "description": "Secure Shell", "protocol": "TCP"},
            "23": {"service": "telnet", "description": "Telnet", "protocol": "TCP"},
            "25": {"service": "smtp", "description": "Simple Mail Transfer Protocol", "protocol": "TCP"},
            "53": {"service": "dns", "description": "Domain Name System", "protocol": "TCP/UDP"},
            "80": {"service": "http", "description": "Hypertext Transfer Protocol", "protocol": "TCP"},
            "110": {"service": "pop3", "description": "Post Office Protocol v3", "protocol": "TCP"},
            "143": {"service": "imap", "description": "Internet Message Access Protocol", "protocol": "TCP"},
            "443": {"service": "https", "description": "HTTP over TLS/SSL", "protocol": "TCP"},
            "993": {"service": "imaps", "description": "IMAP over TLS/SSL", "protocol": "TCP"},
            "995": {"service": "pop3s", "description": "POP3 over TLS/SSL", "protocol": "TCP"},
        }

    def _load_device_signatures(self) -> Dict:
        """Load device type signatures"""
        return {
            "printer": {
                "ports": [515, 631, 9100],
                "services": ["ipp", "lpd", "jetdirect"],
                "user_agents": ["CUPS", "HP", "Canon", "Epson"],
                "vendors": ["HP", "Canon", "Epson", "Brother", "Lexmark"]
            },
            "camera": {
                "ports": [554, 8080, 80],
                "services": ["rtsp", "http"],
                "user_agents": ["Axis", "Hikvision", "Dahua"],
                "vendors": ["Axis", "Hikvision", "Dahua"]
            },
            "router": {
                "ports": [22, 23, 80, 443, 161],
                "services": ["ssh", "telnet", "http", "https", "snmp"],
                "vendors": ["Cisco", "Netgear", "Linksys", "D-Link", "TP-Link"]
            },
            "switch": {
                "ports": [22, 23, 80, 443, 161],
                "services": ["ssh", "telnet", "http", "https", "snmp"],
                "vendors": ["Cisco", "HP", "Juniper", "Arista"]
            },
            "iot": {
                "ports": [80, 443, 1883, 8883],
                "services": ["http", "https", "mqtt"],
                "vendors": ["Raspberry Pi", "Arduino", "ESP"]
            }
        }

    def _rate_limit(self, api_name: str):
        """Apply rate limiting for API calls"""
        if api_name in self.rate_limits:
            min_interval = 1.0 / self.rate_limits[api_name]
            time_since_last = time.time() - self.last_requests[api_name]
            
            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                time.sleep(sleep_time)
            
            self.last_requests[api_name] = time.time()

    def get_mac_vendor(self, mac_address: str) -> tuple[str, str]:
        """Get MAC vendor with caching and API fallback
        
        Returns:
            tuple: (vendor_name, source) where source indicates data origin
        """
        if not mac_address:
            return "Unknown", "none"
        
        mac_prefix = mac_address.replace(':', '').replace('-', '').upper()[:6]
        
        # Check local cache
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT vendor FROM mac_vendors WHERE mac_prefix = ? AND timestamp > ?",
            (mac_prefix, int(time.time()) - 2592000)  # 30 days
        )
        result = cursor.fetchone()
        if result:
            return result[0], "cache"
        
        # Check local vendor database
        vendor_file = self.cache_dir / "mac_vendors.csv"
        if vendor_file.exists():
            try:
                with open(vendor_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row['mac_prefix'].startswith(mac_prefix):
                            vendor = row['vendor']
                            # Cache the result
                            cursor.execute(
                                "INSERT OR REPLACE INTO mac_vendors VALUES (?, ?, ?)",
                                (mac_prefix, vendor, int(time.time()))
                            )
                            self.conn.commit()
                            return vendor, "local_db"
            except Exception as e:
                logger.debug(f"Error reading local vendor database: {e}")
        
        # Try online APIs as fallback
        vendor, api_source = self._query_mac_vendor_api(mac_address)
        if vendor and vendor != "Unknown":
            cursor.execute(
                "INSERT OR REPLACE INTO mac_vendors VALUES (?, ?, ?)",
                (mac_prefix, vendor, int(time.time()))
            )
            self.conn.commit()
            return vendor, f"api_{api_source}"
        
        return "Unknown", "none"

    def _query_mac_vendor_api(self, mac_address: str) -> tuple[Optional[str], str]:
        """Query online MAC vendor APIs
        
        Returns:
            tuple: (vendor_name, api_source)
        """
        # Try api.macvendors.com (recommended by Gemini as more reliable)
        try:
            self._rate_limit("macvendorlookup")
            url = f"https://api.macvendors.com/{mac_address}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                vendor = response.text.strip()
                if vendor and "Not Found" not in vendor:
                    return vendor, "macvendors"
        except Exception as e:
            logger.debug(f"api.macvendors.com failed: {e}")
        
        # Try macvendorlookup.com as fallback
        try:
            self._rate_limit("macvendorlookup")
            url = f"https://api.macvendorlookup.com/{mac_address}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) > 0:
                    return data[0].get('company', 'Unknown'), "macvendorlookup"
                elif isinstance(data, dict):
                    return data.get('company', 'Unknown'), "macvendorlookup"
        except Exception as e:
            logger.debug(f"macvendorlookup.com failed: {e}")
        
        # Try maclookup.app as last resort
        try:
            self._rate_limit("maclookup")
            url = f"https://maclookup.app/api/v2/macs/{mac_address}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('found'):
                    return data.get('company', 'Unknown'), "maclookup"
        except Exception as e:
            logger.debug(f"maclookup.app failed: {e}")
        
        return None, "none"

    def get_port_info(self, port: int, protocol: str = "TCP") -> Dict:
        """Get port information from IANA database"""
        port_str = str(port)
        
        if port_str in self.iana_ports:
            info = self.iana_ports[port_str].copy()
            
            # Check if protocol matches
            if protocol.upper() in info.get('protocol', ''):
                return info
            elif info.get('protocol') == 'TCP/UDP':
                return info
        
        # Return unknown service
        return {
            "service": f"port-{port}",
            "description": f"Unknown service on port {port}",
            "protocol": protocol
        }

    def analyze_device(self, ip: str, mac: str = "", ports: List[int] = None, 
                      user_agent: str = "", hostname: str = "") -> DeviceIntelligence:
        """Comprehensive device analysis using all available intelligence"""
        
        if ports is None:
            ports = []
        
        intel = DeviceIntelligence()
        intel.sources = []
        intel.data_sources = {}
        
        # MAC vendor lookup
        if mac:
            vendor, source = self.get_mac_vendor(mac)
            intel.mac_vendor = vendor
            intel.data_sources["mac_vendor"] = source
            if intel.mac_vendor != "Unknown":
                intel.sources.append("mac_vendor")
        
        # Device type classification based on ports and signatures
        device_scores = {}
        
        for device_type, signature in self.device_signatures.items():
            score = 0
            
            # Check ports
            if ports:
                matching_ports = set(ports) & set(signature.get("ports", []))
                if matching_ports:
                    score += len(matching_ports) * 2
            
            # Check vendor
            if intel.mac_vendor:
                for vendor in signature.get("vendors", []):
                    if vendor.lower() in intel.mac_vendor.lower():
                        score += 3
                        break
            
            # Check user agent
            if user_agent:
                for ua in signature.get("user_agents", []):
                    if ua.lower() in user_agent.lower():
                        score += 2
                        break
            
            # Check hostname
            if hostname:
                if device_type in hostname.lower():
                    score += 1
            
            device_scores[device_type] = score
        
        # Determine most likely device type
        if device_scores:
            best_type = max(device_scores, key=device_scores.get)
            if device_scores[best_type] > 0:
                intel.device_type = best_type
                intel.confidence = min(device_scores[best_type] / 10.0, 1.0)
                intel.sources.append("signature_analysis")
        
        # Analyze services from ports
        for port in ports:
            port_info = self.get_port_info(port)
            service = port_info.get("service", f"port-{port}")
            if service not in intel.services:
                intel.services.append(service)
        
        if intel.services:
            intel.sources.append("port_analysis")
        
        # OS guessing based on vendor and device type
        if intel.mac_vendor:
            vendor_lower = intel.mac_vendor.lower()
            if "apple" in vendor_lower:
                intel.os_guess = "macOS/iOS"
            elif "microsoft" in vendor_lower:
                intel.os_guess = "Windows"
            elif "raspberry" in vendor_lower:
                intel.os_guess = "Linux (Raspberry Pi)"
            elif intel.device_type == "router":
                intel.os_guess = "Embedded/Router OS"
            elif intel.device_type == "printer":
                intel.os_guess = "Printer Firmware"
        
        return intel


    def close(self):
        """Close database connections"""
        if self.conn:
            self.conn.close()

    def __del__(self):
        """Cleanup on destruction"""
        self.close()


# Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Initialize API intelligence
    api_intel = APIIntelligenceLayer()
    
    # Test MAC vendor lookup
    test_mac = "00:1A:2B:3C:4D:5E"
    vendor = api_intel.get_mac_vendor(test_mac)
    print(f"MAC {test_mac} -> Vendor: {vendor}")
    
    # Test port analysis
    port_info = api_intel.get_port_info(80)
    print(f"Port 80 -> {port_info}")
    
    # Test device analysis
    device_intel = api_intel.analyze_device(
        ip="192.168.1.100",
        mac="00:1A:2B:3C:4D:5E",
        ports=[80, 443, 22],
        hostname="webserver01"
    )
    print(f"Device analysis: {device_intel.to_dict()}")
    
    # Test geolocation
    geo = api_intel.get_geolocation("8.8.8.8")
    print(f"Geolocation: {geo}")
    
    api_intel.close()