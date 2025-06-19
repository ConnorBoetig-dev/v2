#!/usr/bin/env python3
"""Debug MAC lookup issues"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent))

from utils.mac_lookup import MACLookup

# Test specific lookup
mac_lookup = MACLookup()

# Check what's in the cache for these prefixes
test_prefixes = ["84:a9:38", "84-A9-38", "e8:40:f2", "E8-40-F2", "a0:ce:c8", "A0-CE-C8"]

print("Checking vendor cache for prefixes:")
for prefix in test_prefixes:
    prefix_lower = prefix.lower()
    if prefix_lower in mac_lookup.vendor_cache:
        print(f"  {prefix} -> {mac_lookup.vendor_cache[prefix_lower]}")

# Check a few entries from the cache
print("\nFirst 10 entries in vendor cache:")
for i, (k, v) in enumerate(mac_lookup.vendor_cache.items()):
    if i >= 10:
        break
    print(f"  '{k}' -> '{v}'")

# Now grep the actual file for our MACs
print("\nSearching OUI file directly:")
import subprocess

result = subprocess.run(["grep", "-i", "84-A9-38", "cache/oui.txt"], capture_output=True, text=True)
if result.stdout:
    print(f"Found 84-A9-38: {result.stdout.strip()}")

result = subprocess.run(
    ["grep", "-i", "^E8-40-F2", "cache/oui.txt"], capture_output=True, text=True
)
if result.stdout:
    print(f"Found E8-40-F2: {result.stdout.strip()}")

result = subprocess.run(
    ["grep", "-i", "^A0-CE-C8", "cache/oui.txt"], capture_output=True, text=True
)
if result.stdout:
    print(f"Found A0-CE-C8: {result.stdout.strip()}")
