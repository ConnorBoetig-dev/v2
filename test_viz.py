#!/usr/bin/env python3
"""Test visualization data generation"""

import json
from pathlib import Path
from utils.visualization import MapGenerator

# Load demo data
demo_dir = Path("output/demo")
scan_file = sorted(demo_dir.glob("scan_*.json"))[-1]
flow_file = sorted(demo_dir.glob("flows_*.json"))[-1]

print(f"Loading data from {scan_file}")

with open(scan_file) as f:
    devices = json.load(f)

with open(flow_file) as f:
    flow_matrix = json.load(f)

print(f"Loaded {len(devices)} devices")
print(f"Flow matrix has {len(flow_matrix)} source IPs")

# Test visualization generation
map_gen = MapGenerator()

# Test 1: Generate normal D3 data (without flow matrix)
print("\nTest 1: Normal D3 data generation")
d3_data = map_gen.generate_d3_data(devices)
print(f"- Nodes: {len(d3_data['nodes'])}")
print(f"- Links: {len(d3_data['links'])}")

# Test 2: Generate traffic flow data (with flow matrix)
print("\nTest 2: Traffic flow data generation")
traffic_data = map_gen.generate_traffic_flow_data(devices, flow_matrix)
print(f"- Nodes: {len(traffic_data['nodes'])}")
print(f"- Links: {len(traffic_data['links'])}")

# Check some links
if traffic_data['links']:
    print("\nSample links:")
    for i, link in enumerate(traffic_data['links'][:5]):
        src_idx = link.get('source')
        tgt_idx = link.get('target')
        if isinstance(src_idx, int) and isinstance(tgt_idx, int):
            src_node = traffic_data['nodes'][src_idx]
            tgt_node = traffic_data['nodes'][tgt_idx]
            print(f"  {src_node['id']} -> {tgt_node['id']}: {link.get('packets', 0)} packets")
        else:
            print(f"  Link {i}: {link}")

# Save test output
test_output = Path("output/test_viz_data.json")
with open(test_output, 'w') as f:
    json.dump({
        "d3_data": d3_data,
        "traffic_data": traffic_data,
        "flow_matrix_sample": {k: v for k, v in list(flow_matrix.items())[:5]}
    }, f, indent=2)

print(f"\nTest data saved to {test_output}")