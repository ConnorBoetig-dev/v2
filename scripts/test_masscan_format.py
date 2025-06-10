#!/usr/bin/env python3
"""
Test masscan output format to debug parsing issues
"""

import json
import subprocess
import tempfile
from pathlib import Path

# Sample masscan outputs in different possible formats
sample_outputs = [
    # Format 1: Line-by-line JSON objects
    '''{"ip": "10.1.0.252", "timestamp": "1736518432", "ports": [{"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]}
{"ip": "10.1.0.248", "timestamp": "1736518433", "ports": [{"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]}
{"ip": "10.1.0.251", "timestamp": "1736518434", "ports": [{"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]}''',
    
    # Format 2: JSON array
    '''[
{"ip": "10.1.0.252", "timestamp": "1736518432", "ports": [{"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
{"ip": "10.1.0.248", "timestamp": "1736518433", "ports": [{"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]},
{"ip": "10.1.0.251", "timestamp": "1736518434", "ports": [{"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}]}
]''',
    
    # Format 3: Masscan banner format
    '''{   "ip": "10.1.0.252",   "timestamp": "1736518432", "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] }
{   "ip": "10.1.0.248",   "timestamp": "1736518433", "ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] }
{   "ip": "10.1.0.251",   "timestamp": "1736518434", "ports": [ {"port": 22, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] }''',
]

def test_parser_with_format(format_name, sample_data):
    """Test the parser with a specific format"""
    print(f"\nTesting format: {format_name}")
    print("="*50)
    
    # Import the scanner
    import sys
    sys.path.append(str(Path(__file__).parent.parent))
    from core.scanner import NetworkScanner
    
    scanner = NetworkScanner()
    
    # Write sample data to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write(sample_data)
        temp_file = f.name
    
    try:
        # Test parsing
        devices = scanner._parse_masscan_output(temp_file)
        print(f"✓ Parsed {len(devices)} devices")
        
        for device in devices:
            print(f"  - {device['ip']}: ports {device.get('open_ports', [])} services {device.get('services', [])}")
        
        return len(devices) > 0
        
    except Exception as e:
        print(f"✗ Parsing failed: {e}")
        return False
        
    finally:
        # Clean up
        import os
        os.unlink(temp_file)

def get_real_masscan_output():
    """Try to get real masscan output format"""
    print("\nChecking real masscan output format...")
    print("="*50)
    
    try:
        # Run a simple masscan command that doesn't need sudo (help output)
        result = subprocess.run(["masscan", "--echo"], capture_output=True, text=True)
        if result.returncode == 0:
            print("Masscan is accessible")
        
        # Check if we can find any existing masscan output files
        output_files = list(Path("output").rglob("*masscan*.json"))
        if output_files:
            print(f"\nFound {len(output_files)} existing masscan output files")
            # Read the first few lines of the most recent one
            latest = max(output_files, key=lambda p: p.stat().st_mtime)
            print(f"Examining: {latest}")
            with open(latest) as f:
                lines = f.readlines()[:5]
                print("First few lines:")
                for line in lines:
                    print(f"  {line.strip()}")
        
    except Exception as e:
        print(f"Error: {e}")

def main():
    """Test different masscan output formats"""
    print("NetworkMapper v2 - Masscan Format Testing")
    print("="*50)
    
    # Test each format
    format_names = [
        "Line-by-line JSON",
        "JSON Array", 
        "Masscan Banner Format"
    ]
    
    results = []
    for i, (name, sample) in enumerate(zip(format_names, sample_outputs)):
        success = test_parser_with_format(name, sample)
        results.append((name, success))
    
    # Get real output
    get_real_masscan_output()
    
    # Summary
    print("\n" + "="*50)
    print("SUMMARY")
    print("="*50)
    
    for name, success in results:
        status = "✓ SUCCESS" if success else "✗ FAILED"
        print(f"{name}: {status}")
    
    print("\nThe parser should handle all these formats correctly.")
    print("If masscan is finding hosts but the parser shows 0 devices,")
    print("the issue might be with the JSON structure or port status filtering.")

if __name__ == "__main__":
    main()