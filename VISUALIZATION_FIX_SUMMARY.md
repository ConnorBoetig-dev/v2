# NetworkMapper v2 - Visualization Connection Fix Summary

## Issue
The 2D network map wasn't showing connection lines when passive traffic analysis was performed, despite having traffic flow data (e.g., 1462 links). The traffic flow visualization also wasn't appearing correctly.

## Root Cause
When passive analysis results existed, `mapper.py` was calling `generate_traffic_flow_data()` instead of `generate_d3_data()`. The traffic flow function was returning links with numeric indices (e.g., `source: 0, target: 1`) instead of IP address strings (e.g., `source: "192.168.1.1", target: "192.168.1.10"`).

## Fix Applied
Modified `utils/visualization.py` in the `generate_traffic_flow_data()` function:

```python
# Before (line 134-137):
"source": node_index[src_ip],  # Numeric index
"target": node_index[dst_ip],  # Numeric index

# After:
"source": src_ip,  # IP address string
"target": dst_ip,  # IP address string
```

## Why This Works
The D3.js visualization code in `report.html` expects links to reference nodes by their ID:
```javascript
.force("link", d3.forceLink(links).id(d => d.id).distance(100))
```

Since nodes have `id: device["ip"]` (IP address strings), the links must use IP addresses as source/target values, not numeric indices.

## Additional Improvements
1. Added debug logging to track IPs in flow matrix that aren't in the device list
2. Both `generate_d3_data()` and `generate_traffic_flow_data()` now return consistent link formats
3. The visualization correctly shows actual traffic flows when passive analysis is performed

## Testing
Created and ran a test script that verified:
- Regular D3 data generates inferred topology links with IP addresses
- Traffic flow data generates actual traffic links with IP addresses
- Both formats are compatible with the D3.js visualization code

## Result
The 2D network map now properly displays connection lines when traffic flow data is available from passive analysis.