#!/usr/bin/env python3
"""Test script to verify visualization fixes"""

import json
from pathlib import Path
from utils.visualization import MapGenerator

def test_visualization_fix():
    """Test that the visualization generates proper link data"""
    
    # Load test data from our demo
    demo_file = Path("output/scans/scan_20250610_034734.json")
    if not demo_file.exists():
        print("Demo scan file not found. Please run demo_large_network.py first.")
        return
    
    with open(demo_file) as f:
        devices = json.load(f)
    
    # Load flow matrix
    flow_file = Path("output/scans/demo_flow_matrix_20250610_034734.json")
    if not flow_file.exists():
        print("Flow matrix file not found.")
        return
        
    with open(flow_file) as f:
        flow_matrix = json.load(f)
    
    # Generate visualization data
    map_gen = MapGenerator()
    
    # Test traffic flow data generation
    traffic_data = map_gen.generate_traffic_flow_data(devices, flow_matrix)
    
    print(f"Total nodes: {len(traffic_data['nodes'])}")
    print(f"Total links: {len(traffic_data['links'])}")
    
    # Check link format
    if traffic_data['links']:
        sample_link = traffic_data['links'][0]
        print(f"\nSample link structure:")
        print(f"  Source: {sample_link['source']} (type: {type(sample_link['source']).__name__})")
        print(f"  Target: {sample_link['target']} (type: {type(sample_link['target']).__name__})")
        print(f"  Value: {sample_link['value']}")
        print(f"  Packets: {sample_link.get('packets', 'N/A')}")
        
        # Verify source and target are IP strings
        if isinstance(sample_link['source'], str) and '.' in sample_link['source']:
            print("\n✅ Links correctly use IP address strings")
        else:
            print("\n❌ Links are using numeric indices instead of IPs")
    
    # Test regular D3 data generation (without flow matrix)
    d3_data = map_gen.generate_d3_data(devices)
    
    print(f"\n\nRegular D3 data:")
    print(f"Total nodes: {len(d3_data['nodes'])}")
    print(f"Total links: {len(d3_data['links'])}")
    
    if d3_data['links']:
        sample_link = d3_data['links'][0]
        print(f"\nSample link structure:")
        print(f"  Source: {sample_link['source']} (type: {type(sample_link['source']).__name__})")
        print(f"  Target: {sample_link['target']} (type: {type(sample_link['target']).__name__})")
    
    # Check node structure
    if traffic_data['nodes']:
        sample_node = traffic_data['nodes'][0]
        print(f"\n\nSample node structure:")
        print(f"  ID: {sample_node['id']}")
        print(f"  Name: {sample_node['name']}")
        print(f"  Type: {sample_node['type']}")
        if 'traffic' in sample_node:
            print(f"  Traffic: {sample_node['traffic']}")

if __name__ == "__main__":
    test_visualization_fix()