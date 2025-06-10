#!/usr/bin/env python3
"""
Sudo wrapper for packet capture
This script is called with sudo to perform the actual packet capture
"""

import json
import sys
import time
from pathlib import Path
import logging

# Suppress scapy warnings and output
logging.getLogger("scapy").setLevel(logging.ERROR)

try:
    from scapy.all import sniff, IP, TCP, UDP, ARP, DNS, Ether, conf
    # Disable scapy verbosity
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    print(json.dumps({"error": "Scapy not installed"}))
    sys.exit(1)


def capture_packets(interface, duration, output_file):
    """Capture packets and save to file"""
    # Suppress all output during capture
    import os
    import contextlib
    
    packets_data = []
    start_time = time.time()
    
    def packet_handler(pkt):
        # Don't check duration here - let stop_filter handle it
        packet_info = {
            "timestamp": time.time(),
            "size": len(pkt)
        }
        
        # Extract Ethernet info
        if Ether in pkt:
            packet_info["src_mac"] = pkt[Ether].src
            packet_info["dst_mac"] = pkt[Ether].dst
        
        # Extract IP info
        if IP in pkt:
            packet_info["src_ip"] = pkt[IP].src
            packet_info["dst_ip"] = pkt[IP].dst
            packet_info["protocol"] = pkt[IP].proto
            
            # Extract TCP/UDP ports
            if TCP in pkt:
                packet_info["src_port"] = pkt[TCP].sport
                packet_info["dst_port"] = pkt[TCP].dport
                packet_info["proto_name"] = "TCP"
            elif UDP in pkt:
                packet_info["src_port"] = pkt[UDP].sport
                packet_info["dst_port"] = pkt[UDP].dport
                packet_info["proto_name"] = "UDP"
                
        # Handle ARP
        elif ARP in pkt:
            packet_info["arp_src_ip"] = pkt[ARP].psrc
            packet_info["arp_dst_ip"] = pkt[ARP].pdst
            packet_info["arp_src_mac"] = pkt[ARP].hwsrc
            packet_info["proto_name"] = "ARP"
            
        packets_data.append(packet_info)
        # The prn callback should not return any value
    
    try:
        # Suppress output during sniffing
        with open(os.devnull, 'w') as devnull:
            old_stdout = sys.stdout
            sys.stdout = devnull
            
            # Start sniffing
            sniff(
                iface=interface,
                prn=packet_handler,
                filter="not port 22",  # Exclude SSH
                timeout=duration,
                store=False,
                stop_filter=lambda x: time.time() - start_time > duration
            )
            
            # Restore stdout
            sys.stdout = old_stdout
        
        # Save results
        with open(output_file, 'w') as f:
            json.dump({
                "packets": packets_data,
                "stats": {
                    "total_packets": len(packets_data),
                    "duration": duration,
                    "interface": interface
                }
            }, f)
            
        print(json.dumps({"success": True, "packets": len(packets_data)}))
        
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(json.dumps({"error": "Usage: traffic_capture_sudo.py <interface> <duration> <output_file>"}))
        sys.exit(1)
        
    interface = sys.argv[1]
    duration = int(sys.argv[2])
    output_file = sys.argv[3]
    
    capture_packets(interface, duration, output_file)