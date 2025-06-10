#!/usr/bin/env python3
"""
Test masscan functionality and diagnose scanning issues
"""

import subprocess
import sys
import time
from pathlib import Path

def check_masscan_installation():
    """Check if masscan is installed and accessible"""
    try:
        result = subprocess.run(["which", "masscan"], capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ Masscan found at:", result.stdout.strip())
            
            # Get version
            version_result = subprocess.run(["masscan", "--version"], capture_output=True, text=True)
            print("  Version:", version_result.stdout.strip() if version_result.stdout else "Unknown")
            return True
        else:
            print("✗ Masscan not found")
            print("  Install with: sudo apt install masscan")
            return False
    except Exception as e:
        print(f"✗ Error checking masscan: {e}")
        return False

def test_simple_scan(target="8.8.8.8"):
    """Test a simple masscan scan against a known host"""
    print(f"\nTesting masscan with known host ({target})...")
    
    try:
        # Test with a single port on a known responsive host
        cmd = [
            "sudo", "masscan",
            "-p80,443",
            target,
            "--rate=1000",
            "--wait=3"
        ]
        
        print(f"Command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("✓ Masscan executed successfully")
            if result.stdout:
                print("Output:", result.stdout.strip())
            else:
                print("  (No output - host may not have these ports open)")
            return True
        else:
            print("✗ Masscan failed")
            if result.stderr:
                print("Error:", result.stderr.strip())
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ Masscan timed out")
        return False
    except Exception as e:
        print(f"✗ Error running masscan: {e}")
        return False

def test_local_network_discovery():
    """Test discovering local network devices"""
    print("\nTesting local network discovery...")
    
    # Get local subnet
    try:
        # Get default route to determine local network
        route_result = subprocess.run(["ip", "route", "show", "default"], 
                                    capture_output=True, text=True)
        if route_result.returncode == 0 and route_result.stdout:
            # Extract gateway IP
            parts = route_result.stdout.split()
            if "via" in parts:
                gateway_ip = parts[parts.index("via") + 1]
                # Convert to /24 subnet
                octets = gateway_ip.split(".")
                subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
                print(f"Detected local subnet: {subnet}")
                
                # Test with common ports
                cmd = [
                    "sudo", "masscan",
                    "-p80,443,22,445,8080,3389",
                    subnet,
                    "--rate=10000",
                    "--wait=3",
                    "-oJ", "-"  # Output to stdout
                ]
                
                print(f"Scanning with: masscan -p80,443,22,445,8080,3389 {subnet}")
                print("This may take 30-60 seconds...")
                
                start_time = time.time()
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                elapsed = time.time() - start_time
                
                if result.returncode == 0:
                    print(f"✓ Scan completed in {elapsed:.1f} seconds")
                    
                    # Count discovered hosts
                    lines = result.stdout.strip().split("\n")
                    hosts = set()
                    for line in lines:
                        if line.strip() and "ip" in line:
                            try:
                                import json
                                data = json.loads(line.strip().rstrip(","))
                                if "ip" in data:
                                    hosts.add(data["ip"])
                            except:
                                pass
                    
                    print(f"Found {len(hosts)} hosts with open ports")
                    if hosts:
                        print("Sample hosts:", list(hosts)[:5])
                    
                    return len(hosts) > 0
                else:
                    print("✗ Scan failed")
                    if result.stderr:
                        print("Error:", result.stderr.strip())
                    return False
                    
    except Exception as e:
        print(f"✗ Error detecting local network: {e}")
        return False

def suggest_alternatives():
    """Suggest alternative scanning approaches"""
    print("\n" + "="*60)
    print("SUGGESTIONS FOR BETTER RESULTS:")
    print("="*60)
    
    print("\n1. Use nmap for discovery (more reliable but slower):")
    print("   - In NetworkMapper, choose 'Discovery Scan' without masscan")
    print("   - Nmap uses multiple discovery techniques (ICMP, TCP, UDP)")
    
    print("\n2. Try ARP scanning for local networks:")
    print("   - Select 'ARP Scan' option in NetworkMapper")
    print("   - Works well for local subnets")
    
    print("\n3. Expand port list for masscan:")
    print("   - Your network might use non-standard ports")
    print("   - Try: masscan -p1-1000 <target> (first 1000 ports)")
    
    print("\n4. Check firewall settings:")
    print("   - Ensure your firewall allows outbound SYN packets")
    print("   - Some networks block port scanning")
    
    print("\n5. Verify network connectivity:")
    print("   - Can you ping devices on the network?")
    print("   - Try: ping -c 1 <target_ip>")

def main():
    """Run masscan diagnostics"""
    print("NetworkMapper v2 - Masscan Diagnostics")
    print("=" * 40)
    
    # Check installation
    if not check_masscan_installation():
        sys.exit(1)
    
    # Check sudo access
    print("\nChecking sudo access...")
    sudo_check = subprocess.run(["sudo", "-n", "true"], capture_output=True)
    if sudo_check.returncode != 0:
        print("⚠ Need sudo access for masscan")
        subprocess.run(["sudo", "-v"])
    
    # Test basic functionality
    if len(sys.argv) > 1:
        # Test specific target
        target = sys.argv[1]
        print(f"\nTesting against specified target: {target}")
        test_simple_scan(target)
    else:
        # Test against known host
        test_simple_scan()
        
        # Test local network
        if input("\nTest local network discovery? (y/n): ").lower() == 'y':
            test_local_network_discovery()
    
    # Show suggestions
    suggest_alternatives()

if __name__ == "__main__":
    main()