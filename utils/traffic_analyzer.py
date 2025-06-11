"""
Passive Traffic Analysis Module for NetworkMapper v2

This module provides passive network monitoring capabilities to:
- Discover stealth/hidden devices
- Map real-time traffic flows
- Correlate services with actual usage
- Build communication patterns
"""

import ipaddress
import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from queue import Queue
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, sniff
    from scapy.layers.http import HTTPRequest, HTTPResponse

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available - passive traffic analysis will be limited")

# Import API intelligence layer
try:
    from .api_intelligence import APIIntelligenceLayer, DeviceIntelligence
    API_INTELLIGENCE_AVAILABLE = True
except ImportError:
    logger.warning("API Intelligence layer not available")
    API_INTELLIGENCE_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class TrafficFlow:
    """Represents a traffic flow between two endpoints"""

    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    service: str = ""
    packets: int = 0
    bytes: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    dns_names: Set[str] = field(default_factory=set)

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "service": self.service,
            "packets": self.packets,
            "bytes": self.bytes,
            "start_time": self.start_time.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "dns_names": list(self.dns_names),
        }


@dataclass
class StealthDevice:
    """Represents a device discovered through passive monitoring"""

    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    services_used: Set[str] = field(default_factory=set)
    communication_peers: Set[str] = field(default_factory=set)
    total_flows: int = 0
    inbound_flows: int = 0
    outbound_flows: int = 0
    ports_used: Set[int] = field(default_factory=set)
    user_agent: str = ""
    api_intelligence: Optional[Dict] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        device_dict = {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "services_used": list(self.services_used),
            "communication_peers": list(self.communication_peers),
            "total_flows": self.total_flows,
            "inbound_flows": self.inbound_flows,
            "outbound_flows": self.outbound_flows,
            "ports_used": list(self.ports_used),
            "user_agent": self.user_agent,
            "likely_type": self.guess_device_type(),
        }
        
        # Add API intelligence if available
        if self.api_intelligence:
            device_dict["api_intelligence"] = self.api_intelligence
            
        return device_dict

    def guess_device_type(self) -> str:
        """Guess device type based on traffic patterns"""
        # High outbound flows suggest client/workstation
        if self.outbound_flows > self.inbound_flows * 2:
            return "workstation"

        # High inbound flows suggest server
        if self.inbound_flows > self.outbound_flows * 2:
            if "http" in self.services_used or "https" in self.services_used:
                return "web_server"
            elif "ssh" in self.services_used:
                return "linux_server"
            elif "rdp" in self.services_used:
                return "windows_server"
            return "server"

        # Many peers suggest router/firewall
        if len(self.communication_peers) > 20:
            return "router_or_firewall"

        # DNS activity suggests DNS server
        if "dns" in self.services_used and self.inbound_flows > 100:
            return "dns_server"

        return "unknown"


class PassiveTrafficAnalyzer:
    """Passive traffic analysis for device discovery and flow mapping"""

    def __init__(self, interface: str = None, output_path: Path = Path("output")):
        """Initialize the traffic analyzer

        Args:
            interface: Network interface to monitor (None for auto-detect)
            output_path: Base output directory
        """
        self.interface = interface or self._detect_interface()
        self.output_path = output_path
        self.output_path.mkdir(exist_ok=True)

        # Data structures
        self.devices: Dict[str, StealthDevice] = {}
        self.flows: Dict[Tuple, TrafficFlow] = {}
        self.arp_cache: Dict[str, str] = {}  # IP -> MAC mapping
        self.dns_cache: Dict[str, Set[str]] = defaultdict(set)  # IP -> hostnames
        self.service_patterns: Dict[int, str] = self._init_service_patterns()
        self.discovered_devices: Set[str] = set()  # All discovered device IPs

        # Processing queue
        self.packet_queue = Queue(maxsize=10000)
        self.running = False
        self.capture_thread = None
        self.process_thread = None

        # Initialize API intelligence layer
        self.api_intelligence = None
        if API_INTELLIGENCE_AVAILABLE:
            try:
                self.api_intelligence = APIIntelligenceLayer(cache_dir=self.output_path / "cache")
                logger.info("API Intelligence layer initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize API Intelligence: {e}")

        # Statistics
        self.stats = {
            "packets_captured": 0,
            "packets_processed": 0,
            "flows_tracked": 0,
            "devices_discovered": 0,
            "start_time": datetime.now().isoformat(),
            "api_intelligence_enabled": self.api_intelligence is not None,
        }

    def _detect_interface(self) -> str:
        """Auto-detect suitable network interface"""
        try:
            # Try to find default interface
            result = subprocess.run(
                ["ip", "route", "show", "default"], capture_output=True, text=True
            )
            if result.returncode == 0:
                # Extract interface from "default via x.x.x.x dev eth0"
                parts = result.stdout.split()
                if "dev" in parts:
                    idx = parts.index("dev")
                    if idx + 1 < len(parts):
                        interface = parts[idx + 1]
                        logger.info(f"Auto-detected interface: {interface}")
                        return interface
        except Exception as e:
            logger.warning(f"Failed to auto-detect interface: {e}")

        # Fallback to first non-loopback interface
        try:
            # Get all interfaces
            result = subprocess.run(
                ["ip", "link", "show"], capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ':' in line and 'lo:' not in line:
                        # Extract interface name (e.g., "2: enp0s1:" -> "enp0s1")
                        parts = line.split(':')
                        if len(parts) >= 2:
                            interface = parts[1].strip()
                            if interface and interface != 'lo':
                                logger.info(f"Using first non-loopback interface: {interface}")
                                return interface
        except Exception as e:
            logger.warning(f"Failed to list interfaces: {e}")

        # Try netifaces if available
        try:
            import netifaces
            for iface in netifaces.interfaces():
                if iface != "lo" and netifaces.AF_INET in netifaces.ifaddresses(iface):
                    logger.info(f"Using interface from netifaces: {iface}")
                    return iface
        except ImportError:
            pass

        # Last resort - try common interface names
        common_names = ["enp0s1", "eth0", "ens33", "enp0s3"]
        for name in common_names:
            try:
                result = subprocess.run(
                    ["ip", "link", "show", name], capture_output=True, text=True
                )
                if result.returncode == 0:
                    logger.info(f"Using common interface name: {name}")
                    return name
            except:
                pass

        logger.warning("Could not detect interface, defaulting to eth0")
        return "eth0"

    def _init_service_patterns(self) -> Dict[int, str]:
        """Initialize port to service mapping"""
        return {
            20: "ftp-data",
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            67: "dhcp",
            68: "dhcp",
            80: "http",
            110: "pop3",
            123: "ntp",
            135: "rpc",
            139: "netbios",
            143: "imap",
            161: "snmp",
            162: "snmp-trap",
            389: "ldap",
            443: "https",
            445: "smb",
            465: "smtps",
            514: "syslog",
            515: "printer",
            587: "smtp",
            636: "ldaps",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            1521: "oracle",
            1723: "pptp",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            5985: "winrm",
            6379: "redis",
            8080: "http-alt",
            8443: "https-alt",
            9200: "elasticsearch",
            11211: "memcached",
            27017: "mongodb",
        }

    def start_capture(self, duration: int = 0, packet_count: int = 0) -> None:
        """Start passive traffic capture

        Args:
            duration: Capture duration in seconds (0 for continuous)
            packet_count: Max packets to capture (0 for unlimited)
        """
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is required for passive traffic analysis")
            logger.error("Install with: pip install scapy OR run ./install_scapy.sh")
            # Set some minimal stats so reports don't break
            self.stats["packets_captured"] = 0
            self.stats["flows_tracked"] = 0
            self.stats["devices_discovered"] = 0
            return

        if self.running:
            logger.warning("Capture already running")
            return

        self.running = True
        self.stats["start_time"] = datetime.now().isoformat()

        # Start packet processor thread
        self.process_thread = threading.Thread(target=self._process_packets)
        self.process_thread.daemon = True
        self.process_thread.start()

        # Start capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_packets, args=(duration, packet_count)
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()

        logger.info(f"Started passive traffic capture on {self.interface}")

    def stop_capture(self) -> None:
        """Stop passive traffic capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        if self.process_thread:
            self.process_thread.join(timeout=5)

        # Enrich devices with API intelligence after capture
        if self.devices:
            logger.info("Enriching devices with API intelligence...")
            self.enrich_devices_with_api_intelligence()

        logger.info(f"Stopped passive traffic capture. Stats: {self.stats}")

    def _capture_packets(self, duration: int, packet_count: int) -> None:
        """Capture packets using scapy with sudo wrapper"""
        import tempfile
        import subprocess
        import os
        
        temp_file = None
        try:
            # Create temporary file for capture results
            temp_fd, temp_file = tempfile.mkstemp(suffix='.json', prefix='traffic_capture_')
            os.close(temp_fd)
            
            # Make the temp file writable by the sudo process
            os.chmod(temp_file, 0o666)
            
            # Path to sudo wrapper script
            script_path = Path(__file__).parent / "traffic_capture_sudo.py"
            
            # Run capture with sudo
            cmd = [
                "sudo", "-n",
                sys.executable,
                str(script_path),
                self.interface,
                str(duration if duration > 0 else 60),  # Default 60s if not specified
                temp_file
            ]
            
            logger.info(f"Starting packet capture with sudo on {self.interface}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                error_msg = result.stderr or result.stdout
                if "password" in error_msg.lower():
                    logger.error("Sudo authentication required for packet capture")
                    logger.error("Please run with: sudo python3 mapper.py")
                else:
                    # Log the full error including any warnings
                    logger.error(f"Capture failed with return code {result.returncode}")
                    if result.stderr:
                        # Check if it's just warnings (which shouldn't fail the capture)
                        if "CryptographyDeprecationWarning" in result.stderr:
                            logger.warning("Ignoring cryptography deprecation warning")
                            # Don't return, continue processing
                        else:
                            logger.error(f"Stderr: {result.stderr}")
                            return
                    if result.stdout:
                        logger.error(f"Stdout: {result.stdout}")
                
                # Only return if it's a real error, not just warnings
                if result.returncode != 0 and "warning" not in error_msg.lower():
                    return
            
            # Check if there's any stdout output
            if result.stdout and result.stdout.strip():
                # Log the full output for debugging
                logger.info(f"Capture script output: {result.stdout}")
                
                # Try to parse as JSON (expected format)
                try:
                    output_data = json.loads(result.stdout.strip())
                    if "error" in output_data:
                        logger.error(f"Capture error: {output_data['error']}")
                        return
                    elif "debug" in output_data:
                        logger.info(f"Capture debug info: {output_data['debug']}")
                except json.JSONDecodeError:
                    # If it's not JSON, log it but continue
                    logger.warning(f"Non-JSON output from capture: {result.stdout}")
                
            # Parse capture results
            if os.path.exists(temp_file):
                with open(temp_file, 'r') as f:
                    capture_data = json.load(f)
                    
                packets = capture_data.get("packets", [])
                self.stats["packets_captured"] = len(packets)
                
                # Process packets
                for pkt_data in packets:
                    if not self.running:
                        break
                    self._process_packet_data(pkt_data)
                    
                logger.info(f"Processed {len(packets)} packets from capture")
                    
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self.running = False
            # Clean up temp file
            if temp_file and os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except:
                    pass

    def _process_packet_data(self, pkt_data: Dict) -> None:
        """Process a single packet data dictionary"""
        try:
            # Extract flow key
            src_ip = pkt_data.get("src_ip", "")
            dst_ip = pkt_data.get("dst_ip", "")
            src_port = pkt_data.get("src_port", 0)
            dst_port = pkt_data.get("dst_port", 0)
            protocol = pkt_data.get("proto_name", "")
            
            if not src_ip or not dst_ip:
                # Handle ARP packets
                if pkt_data.get("arp_src_ip"):
                    src_ip = pkt_data["arp_src_ip"]
                    src_mac = pkt_data.get("arp_src_mac", "")
                    if src_ip and src_mac:
                        self.arp_cache[src_ip] = src_mac
                        self.discovered_devices.add(src_ip)
                return
                
            # Create flow key
            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            
            # Update or create flow
            if flow_key in self.flows:
                flow = self.flows[flow_key]
                flow.packets += 1
                flow.bytes += pkt_data.get("size", 0)
                flow.last_seen = datetime.now()
            else:
                flow = TrafficFlow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    packets=1,
                    bytes=pkt_data.get("size", 0)
                )
                
                # Detect service
                if dst_port in self.service_patterns:
                    flow.service = self.service_patterns[dst_port]
                elif src_port in self.service_patterns:
                    flow.service = self.service_patterns[src_port]
                    
                self.flows[flow_key] = flow
                self.stats["flows_tracked"] = len(self.flows)
                
            # Track devices
            self.discovered_devices.add(src_ip)
            self.discovered_devices.add(dst_ip)
            
            # Update stats
            self.stats["packets_processed"] += 1
            self.stats["flows_tracked"] = len(self.flows)
            self.stats["devices_discovered"] = len(self.discovered_devices)
            
        except Exception as e:
            logger.debug(f"Error processing packet: {e}")
    
    def _process_packets(self) -> None:
        """Process captured packets"""
        while self.running or not self.packet_queue.empty():
            try:
                # Get packet with timeout
                pkt = self.packet_queue.get(timeout=1)
                self._analyze_packet(pkt)
                self.stats["packets_processed"] += 1

            except:
                continue

    def _analyze_packet(self, pkt) -> None:
        """Analyze a single packet"""
        try:
            # Process ARP packets
            if pkt.haslayer(ARP):
                self._process_arp(pkt)

            # Process IP packets
            if pkt.haslayer(IP):
                self._process_ip(pkt)

                # Process DNS
                if pkt.haslayer(DNS):
                    self._process_dns(pkt)

                # Process TCP/UDP flows
                if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                    self._process_flow(pkt)

        except Exception as e:
            logger.debug(f"Packet analysis error: {e}")

    def _process_arp(self, pkt) -> None:
        """Process ARP packets for device discovery"""
        arp = pkt[ARP]

        # Update ARP cache
        if arp.psrc and arp.hwsrc:
            self.arp_cache[arp.psrc] = arp.hwsrc
            self._update_device(arp.psrc, mac=arp.hwsrc)

    def _process_dns(self, pkt) -> None:
        """Process DNS packets for hostname resolution"""
        dns = pkt[DNS]

        # Process DNS responses
        if dns.qr == 1:  # DNS response
            for i in range(dns.ancount):
                try:
                    answer = dns.an[i]
                    if hasattr(answer, "rdata") and hasattr(answer, "rrname"):
                        hostname = (
                            answer.rrname.decode()
                            if isinstance(answer.rrname, bytes)
                            else str(answer.rrname)
                        )
                        ip = answer.rdata

                        # Update DNS cache
                        if isinstance(ip, str) and self._is_valid_ip(ip):
                            self.dns_cache[ip].add(hostname.rstrip("."))
                            self._update_device(ip, hostname=hostname.rstrip("."))

                except Exception as e:
                    logger.debug(f"DNS parsing error: {e}")

    def _process_ip(self, pkt) -> None:
        """Process IP packets for device discovery"""
        ip = pkt[IP]

        # Skip multicast and broadcast
        if ip.dst.startswith("224.") or ip.dst.startswith("255."):
            return

        # Update devices
        self._update_device(ip.src)
        self._update_device(ip.dst)

    def _process_flow(self, pkt) -> None:
        """Process TCP/UDP flows"""
        ip = pkt[IP]

        # Determine protocol and ports
        if pkt.haslayer(TCP):
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        else:
            return

        # Create flow key (smaller IP first for bidirectional flows)
        if ip.src < ip.dst:
            flow_key = (ip.src, ip.dst, sport, dport, proto)
            direction = "forward"
        else:
            flow_key = (ip.dst, ip.src, dport, sport, proto)
            direction = "reverse"

        # Update or create flow
        if flow_key not in self.flows:
            self.flows[flow_key] = TrafficFlow(
                src_ip=flow_key[0],
                dst_ip=flow_key[1],
                src_port=flow_key[2],
                dst_port=flow_key[3],
                protocol=flow_key[4],
                service=self._identify_service(flow_key[3]),  # Use destination port
            )
            self.stats["flows_tracked"] += 1

        flow = self.flows[flow_key]
        flow.packets += 1
        flow.bytes += len(pkt)
        flow.last_seen = datetime.now()

        # Update device flow statistics and port tracking
        if direction == "forward":
            self._update_device_flows(ip.src, outbound=True, service=flow.service, peer=ip.dst, port=dport)
            self._update_device_flows(ip.dst, outbound=False, service=flow.service, peer=ip.src, port=sport)
        else:
            self._update_device_flows(ip.dst, outbound=True, service=flow.service, peer=ip.src, port=sport)
            self._update_device_flows(ip.src, outbound=False, service=flow.service, peer=ip.dst, port=dport)
            
        # Extract HTTP User-Agent if available
        if pkt.haslayer(HTTPRequest):
            try:
                headers = pkt[HTTPRequest].fields
                if b'User-Agent' in headers:
                    user_agent = headers[b'User-Agent'].decode('utf-8', errors='ignore')
                    if ip.src in self.devices and not self.devices[ip.src].user_agent:
                        self.devices[ip.src].user_agent = user_agent
            except Exception as e:
                logger.debug(f"Error extracting User-Agent: {e}")

    def _identify_service(self, port: int) -> str:
        """Identify service from port number"""
        return self.service_patterns.get(port, f"port-{port}")

    def _update_device(self, ip: str, mac: str = "", hostname: str = "") -> None:
        """Update device information"""
        if not self._is_valid_ip(ip):
            return

        # Skip local/private addresses optionally
        # if ipaddress.ip_address(ip).is_private:
        #     return

        if ip not in self.devices:
            self.devices[ip] = StealthDevice(ip=ip)
            self.stats["devices_discovered"] += 1
            logger.info(f"Discovered new device: {ip}")

        device = self.devices[ip]
        device.last_seen = datetime.now()

        if mac and not device.mac:
            device.mac = mac

        if hostname and not device.hostname:
            device.hostname = hostname

    def _update_device_flows(self, ip: str, outbound: bool, service: str, peer: str, port: int = 0) -> None:
        """Update device flow statistics"""
        if ip not in self.devices:
            return

        device = self.devices[ip]
        device.total_flows += 1

        if outbound:
            device.outbound_flows += 1
        else:
            device.inbound_flows += 1

        if service:
            device.services_used.add(service)

        if peer:
            device.communication_peers.add(peer)
            
        if port > 0:
            device.ports_used.add(port)

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if IP address is valid"""
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False

    def enrich_devices_with_api_intelligence(self):
        """Enrich discovered devices using API intelligence"""
        if not self.api_intelligence:
            logger.debug("API intelligence not available for device enrichment")
            return
        
        logger.info(f"Enriching {len(self.devices)} devices with API intelligence...")
        
        for ip, device in self.devices.items():
            try:
                # Gather device intelligence from APIs
                device_intel = self.api_intelligence.analyze_device(
                    ip=ip,
                    mac=device.mac,
                    ports=list(device.ports_used),
                    user_agent=device.user_agent,
                    hostname=device.hostname
                )
                
                # Update device with API intelligence
                device.api_intelligence = device_intel.to_dict()
                
                # Update vendor from API if not already set
                if device_intel.mac_vendor and device_intel.mac_vendor != "Unknown":
                    if not device.vendor or device.vendor == "Unknown":
                        device.vendor = device_intel.mac_vendor
                
                # Log enrichment
                if device_intel.sources:
                    logger.debug(f"Enriched {ip} with sources: {device_intel.sources}")
                
            except Exception as e:
                logger.warning(f"Failed to enrich device {ip}: {e}")
        
        logger.info("Device enrichment completed")

    def get_discovered_devices(self) -> List[Dict]:
        """Get all discovered devices"""
        return [device.to_dict() for device in self.devices.values()]

    def get_traffic_flows(self) -> List[Dict]:
        """Get all traffic flows"""
        return [flow.to_dict() for flow in self.flows.values()]

    def get_flow_matrix(self) -> Dict[str, Dict[str, int]]:
        """Get communication matrix between devices"""
        matrix = defaultdict(lambda: defaultdict(int))

        for flow in self.flows.values():
            matrix[flow.src_ip][flow.dst_ip] += flow.packets

        return dict(matrix)

    def get_top_talkers(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top talking devices by traffic volume"""
        talkers = Counter()

        for flow in self.flows.values():
            talkers[flow.src_ip] += flow.bytes
            talkers[flow.dst_ip] += flow.bytes

        return talkers.most_common(limit)

    def get_service_usage(self) -> Dict[str, List[str]]:
        """Get service usage by device"""
        usage = defaultdict(list)

        for device in self.devices.values():
            for service in device.services_used:
                usage[service].append(device.ip)

        return dict(usage)

    def export_results(self, timestamp: str = None) -> Tuple[Path, Path]:
        """Export analysis results to JSON files

        Returns:
            Tuple of (devices_file, flows_file) paths
        """
        if not timestamp:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create empty results if scapy wasn't available
        if not SCAPY_AVAILABLE:
            devices_file = self.output_path / f"passive_devices_{timestamp}.json"
            flows_file = self.output_path / f"traffic_flows_{timestamp}.json"

            empty_data = {
                "timestamp": datetime.now().isoformat(),
                "interface": self.interface,
                "error": "Scapy not available - passive analysis skipped",
                "devices": [],
                "flows": [],
                "flow_matrix": {},
                "top_talkers": [],
                "service_usage": {},
            }

            with open(devices_file, "w") as f:
                json.dump(empty_data, f, indent=2)
            with open(flows_file, "w") as f:
                json.dump(empty_data, f, indent=2)

            return devices_file, flows_file

        # Export devices
        devices_file = self.output_path / f"passive_devices_{timestamp}.json"
        devices_data = {
            "timestamp": datetime.now().isoformat(),
            "interface": self.interface,
            "stats": self.stats,
            "devices": self.get_discovered_devices(),
        }

        with open(devices_file, "w") as f:
            json.dump(devices_data, f, indent=2)

        # Export flows
        flows_file = self.output_path / f"traffic_flows_{timestamp}.json"
        flows_data = {
            "timestamp": datetime.now().isoformat(),
            "interface": self.interface,
            "flows": self.get_traffic_flows(),
            "flow_matrix": self.get_flow_matrix(),
            "top_talkers": self.get_top_talkers(),
            "service_usage": self.get_service_usage(),
        }

        with open(flows_file, "w") as f:
            json.dump(flows_data, f, indent=2)

        logger.info(f"Exported results: {devices_file}, {flows_file}")
        return devices_file, flows_file

    def merge_with_active_scan(self, active_devices: List[Dict]) -> List[Dict]:
        """Merge passive discoveries with active scan results

        Args:
            active_devices: List of devices from active scanning

        Returns:
            Merged device list with passive enrichment
        """
        # Create lookup for active devices
        active_map = {d["ip"]: d for d in active_devices}

        # Merge passive discoveries
        for ip, passive_device in self.devices.items():
            if ip in active_map:
                # Enrich existing device
                device = active_map[ip]
                device["passive_analysis"] = {
                    "last_seen": passive_device.last_seen.isoformat(),
                    "traffic_flows": passive_device.total_flows,
                    "services_observed": list(passive_device.services_used),
                    "communication_peers": len(passive_device.communication_peers),
                    "inbound_flows": passive_device.inbound_flows,
                    "outbound_flows": passive_device.outbound_flows,
                }

                # Update hostname if discovered
                if passive_device.hostname and not device.get("hostname"):
                    device["hostname"] = passive_device.hostname
                    
                # Merge API intelligence if available
                if passive_device.api_intelligence:
                    device["api_intelligence"] = passive_device.api_intelligence

            else:
                # Add stealth device not found in active scan
                device_data = {
                    "ip": ip,
                    "mac": passive_device.mac,
                    "hostname": passive_device.hostname,
                    "type": passive_device.guess_device_type(),
                    "vendor": passive_device.vendor,
                    "stealth_device": True,
                    "discovery_method": "passive",
                    "first_seen": passive_device.first_seen.isoformat(),
                    "last_seen": passive_device.last_seen.isoformat(),
                    "services": list(passive_device.services_used),
                    "passive_analysis": {
                        "traffic_flows": passive_device.total_flows,
                        "communication_peers": len(passive_device.communication_peers),
                        "inbound_flows": passive_device.inbound_flows,
                        "outbound_flows": passive_device.outbound_flows,
                    },
                }
                
                # Add API intelligence if available
                if passive_device.api_intelligence:
                    device_data["api_intelligence"] = passive_device.api_intelligence
                    
                active_map[ip] = device_data
                logger.info(f"Added stealth device from passive analysis: {ip}")

        return list(active_map.values())

    def cleanup(self):
        """Cleanup resources"""
        if self.api_intelligence:
            self.api_intelligence.close()

    def __del__(self):
        """Cleanup on destruction"""
        self.cleanup()


# Example usage and testing
if __name__ == "__main__":
    # Test passive analyzer
    analyzer = PassiveTrafficAnalyzer()

    print(f"Starting passive traffic analysis on interface: {analyzer.interface}")
    print("This requires root/sudo privileges!")
    print("Press Ctrl+C to stop...\n")

    try:
        # Start capture for 60 seconds
        analyzer.start_capture(duration=60)

        # Wait for capture to complete
        while analyzer.running:
            time.sleep(5)
            print(
                f"Captured: {analyzer.stats['packets_captured']} packets, "
                f"Discovered: {analyzer.stats['devices_discovered']} devices"
            )

        # Export results
        devices_file, flows_file = analyzer.export_results()

        # Print summary
        print("\n=== Passive Analysis Summary ===")
        print(f"Total packets: {analyzer.stats['packets_processed']}")
        print(f"Devices discovered: {len(analyzer.devices)}")
        print(f"Traffic flows: {len(analyzer.flows)}")

        # Top talkers
        print("\nTop Talkers:")
        for ip, bytes_count in analyzer.get_top_talkers(5):
            print(f"  {ip}: {bytes_count:,} bytes")

        # Service usage
        print("\nService Usage:")
        for service, ips in analyzer.get_service_usage().items():
            print(f"  {service}: {len(ips)} devices")

    except KeyboardInterrupt:
        print("\nStopping capture...")
        analyzer.stop_capture()
    except Exception as e:
        print(f"Error: {e}")
        analyzer.stop_capture()
