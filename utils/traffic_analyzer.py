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
import subprocess
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

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
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
            "likely_type": self.guess_device_type(),
        }

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

        # Processing queue
        self.packet_queue = Queue(maxsize=10000)
        self.running = False
        self.capture_thread = None
        self.process_thread = None

        # Statistics
        self.stats = {
            "packets_captured": 0,
            "packets_processed": 0,
            "flows_tracked": 0,
            "devices_discovered": 0,
            "start_time": datetime.now().isoformat(),
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
                        return parts[idx + 1]
        except Exception as e:
            logger.warning(f"Failed to auto-detect interface: {e}")

        # Fallback to first non-loopback interface
        try:
            import netifaces

            for iface in netifaces.interfaces():
                if iface != "lo" and netifaces.AF_INET in netifaces.ifaddresses(iface):
                    return iface
        except ImportError:
            pass

        # Last resort
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

        logger.info(f"Stopped passive traffic capture. Stats: {self.stats}")

    def _capture_packets(self, duration: int, packet_count: int) -> None:
        """Capture packets using scapy"""
        try:

            def packet_handler(pkt):
                if not self.running:
                    return

                self.stats["packets_captured"] += 1

                # Add to queue if not full
                if not self.packet_queue.full():
                    self.packet_queue.put(pkt)
                else:
                    logger.debug("Packet queue full, dropping packet")

            # Build filter to reduce noise
            bpf_filter = "not port 22"  # Exclude SSH to avoid capturing our own session

            # Start sniffing
            sniff(
                iface=self.interface,
                prn=packet_handler,
                filter=bpf_filter,
                count=packet_count if packet_count > 0 else 0,
                timeout=duration if duration > 0 else None,
                store=False,
            )

        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self.running = False

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

        # Update device flow statistics
        if direction == "forward":
            self._update_device_flows(ip.src, outbound=True, service=flow.service, peer=ip.dst)
            self._update_device_flows(ip.dst, outbound=False, service=flow.service, peer=ip.src)
        else:
            self._update_device_flows(ip.dst, outbound=True, service=flow.service, peer=ip.src)
            self._update_device_flows(ip.src, outbound=False, service=flow.service, peer=ip.dst)

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

    def _update_device_flows(self, ip: str, outbound: bool, service: str, peer: str) -> None:
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

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if IP address is valid"""
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False

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

            else:
                # Add stealth device not found in active scan
                active_map[ip] = {
                    "ip": ip,
                    "mac": passive_device.mac,
                    "hostname": passive_device.hostname,
                    "type": passive_device.guess_device_type(),
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
                logger.info(f"Added stealth device from passive analysis: {ip}")

        return list(active_map.values())


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
