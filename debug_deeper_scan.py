#!/usr/bin/env python3
"""Debug why deeper scan isn't getting vendor/OS/services"""

import subprocess
import tempfile
import xml.etree.ElementTree as ET

# Test with a real host that should have services
test_ip = "scanme.nmap.org"  # Public test server

print("=== Testing Nmap Enrichment ===\n")

# Create temp file for output
with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as f:
    temp_file = f.name

# Run the exact nmap command used in deeper scan enrichment
cmd = [
    "sudo", "-n", "nmap",
    "-sS",
    "-sV", 
    "-O",
    "--osscan-guess",
    "--version-intensity", "5",
    "--top-ports", "500",
    "-T4",
    "--script-timeout", "10s",
    "-oX", temp_file,
    test_ip
]

print(f"Running: {' '.join(cmd)}\n")

try:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    
    if result.returncode != 0:
        print(f"ERROR: {result.stderr}")
    else:
        # Parse XML to see what we got
        tree = ET.parse(temp_file)
        root = tree.getroot()
        
        for host in root.findall('.//host'):
            # Check status
            status = host.find('.//status')
            if status is not None and status.get('state') == 'up':
                print(f"Host is UP")
                
                # IP
                ip_elem = host.find('.//address[@addrtype="ipv4"]')
                if ip_elem is not None:
                    print(f"IP: {ip_elem.get('addr')}")
                
                # MAC and vendor
                mac_elem = host.find('.//address[@addrtype="mac"]')
                if mac_elem is not None:
                    print(f"MAC: {mac_elem.get('addr')}")
                    print(f"Vendor from nmap: {mac_elem.get('vendor', 'None')}")
                else:
                    print("MAC: Not found (remote host?)")
                
                # OS detection
                os_matches = host.findall('.//osmatch')
                if os_matches:
                    best = max(os_matches, key=lambda x: int(x.get('accuracy', 0)))
                    print(f"OS: {best.get('name')} ({best.get('accuracy')}% accuracy)")
                else:
                    print("OS: Not detected")
                
                # Services
                print("\nServices:")
                ports = host.findall('.//port')
                for port in ports:
                    if port.find('.//state[@state="open"]') is not None:
                        port_id = port.get('portid')
                        service = port.find('.//service')
                        if service is not None:
                            name = service.get('name', 'unknown')
                            product = service.get('product', '')
                            version = service.get('version', '')
                            
                            service_str = f"{name}:{port_id}"
                            if product:
                                service_str += f" ({product}"
                                if version:
                                    service_str += f" {version}"
                                service_str += ")"
                            
                            print(f"  - {service_str}")
                        else:
                            print(f"  - tcp:{port_id} (no service info)")
                            
except Exception as e:
    print(f"Error: {e}")

import os
if os.path.exists(temp_file):
    os.unlink(temp_file)

print("\n=== Testing Local Network ===")
print("For local network scans, MAC addresses should be available.")
print("For remote hosts, MAC won't be available (different network segment).")
print("\nIn your case (10.1.100.x), these are local hosts so:")
print("- MAC addresses SHOULD be detected")
print("- Vendor SHOULD come from MAC")
print("- OS detection needs root access and proper timing")
print("- Services need version detection (-sV)")