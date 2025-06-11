#!/usr/bin/env python3
"""
Test script to verify visualization fixes
"""

import json
import subprocess
import time
import webbrowser
from pathlib import Path
from datetime import datetime

def test_3d_visualization():
    """Test that 3D visualization loads properly"""
    print("Testing 3D visualization fix...")
    
    # Find most recent network map
    reports_dir = Path("output/reports")
    if not reports_dir.exists():
        print("No reports directory found. Run a scan first.")
        return False
        
    network_maps = sorted(reports_dir.glob("network_map_*.html"), reverse=True)
    if not network_maps:
        print("No network maps found. Run a scan first.")
        return False
    
    latest_map = network_maps[0]
    print(f"Testing with: {latest_map}")
    
    # Open in browser
    file_url = f"file://{latest_map.absolute()}"
    print(f"Opening: {file_url}")
    webbrowser.open(file_url)
    
    print("\nPlease check in the browser:")
    print("1. Click the '3D View' button")
    print("2. Verify that the 3D visualization appears")
    print("3. Try rotating/zooming with mouse")
    print("\nDoes the 3D view work? (y/n): ", end="")
    
    return input().lower() == 'y'

def test_traffic_flow():
    """Test that traffic flow report is generated"""
    print("\nTesting traffic flow visualization...")
    
    # Check if traffic flow reports exist
    reports_dir = Path("output/reports")
    traffic_reports = sorted(reports_dir.glob("traffic_flow_*.html"), reverse=True)
    
    if not traffic_reports:
        print("No traffic flow reports found.")
        print("\nTo generate a traffic flow report:")
        print("1. Run a scan with passive traffic analysis enabled")
        print("2. When prompted 'Enable passive traffic analysis?', answer 'y'")
        print("3. The scan will capture network traffic for analysis")
        return False
    
    latest_traffic = traffic_reports[0]
    print(f"Found traffic report: {latest_traffic}")
    
    # Open in browser
    file_url = f"file://{latest_traffic.absolute()}"
    print(f"Opening: {file_url}")
    webbrowser.open(file_url)
    
    print("\nThe traffic flow report should show:")
    print("- Network devices as nodes")
    print("- Traffic flows as connections")
    print("- Top traffic generators")
    print("- Service distribution")
    
    return True

def check_passive_analysis_option():
    """Check if passive analysis is properly presented during scan"""
    print("\n" + "="*50)
    print("SCAN OPTIONS CHECK")
    print("="*50)
    
    print("\nDuring a network scan, you should see these options:")
    print("1. Target network selection")
    print("2. Scan type selection")
    print("3. SNMP enrichment option")
    print("4. Passive traffic analysis option <- THIS GENERATES TRAFFIC FLOW")
    print("5. Vulnerability scanning option")
    
    print("\nTo enable traffic flow visualization:")
    print("- Answer 'y' when asked 'Enable passive traffic analysis?'")
    print("- This requires sudo/root privileges")
    print("- It will capture network traffic for 30 seconds")
    
    return True

def main():
    """Run all visualization tests"""
    print("NetworkMapper v2 Visualization Test Suite")
    print("========================================\n")
    
    # Test 1: 3D Visualization
    three_d_works = test_3d_visualization()
    
    # Test 2: Traffic Flow
    traffic_flow_exists = test_traffic_flow()
    
    # Test 3: Check options
    check_passive_analysis_option()
    
    # Summary
    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    print(f"3D Visualization: {'PASS' if three_d_works else 'CHECK MANUALLY'}")
    print(f"Traffic Flow Report: {'EXISTS' if traffic_flow_exists else 'NOT FOUND - Run scan with passive analysis'}")
    
    if not traffic_flow_exists:
        print("\nTo generate traffic flow report:")
        print("1. Run: python3 mapper.py")
        print("2. Choose option 1 (Scan Network)")
        print("3. When asked 'Enable passive traffic analysis?', answer 'y'")
        print("4. Complete the scan")
        print("5. The traffic flow report will be generated automatically")

if __name__ == "__main__":
    main()